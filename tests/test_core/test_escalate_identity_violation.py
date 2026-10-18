from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.helpers import escalate_identity_violation
from guard_core.detection_result import DetectionResult
from guard_core.models import SecurityConfig, ThreatBanConfig


def _make_middleware(
    counts: dict[str, dict[str, int]] | None = None,
    cap: int = 10_000,
) -> Any:
    mw = MagicMock()
    mw.config = SecurityConfig(enable_redis=False, ban_counters_max_tracked_ips=cap)
    mw.suspicious_request_counts = counts if counts is not None else {}
    mw.route_resolver = MagicMock()
    mw.route_resolver.should_bypass_check = lambda *_: False
    mw.event_bus = MagicMock()
    mw.event_bus.send_middleware_event = AsyncMock()
    return mw


def _make_request(is_whitelisted: bool = False) -> Any:
    request = MagicMock()
    request.state = MagicMock()
    request.state.is_whitelisted = is_whitelisted
    request.state.route_config = None
    request.url_full = "https://test/x"
    return request


def _patch_detect(
    monkeypatch: pytest.MonkeyPatch,
    is_threat: bool = True,
    trigger_info: str = "xss hit",
    threat_categories: list[str] | None = None,
) -> None:
    async def fake_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        return DetectionResult(
            is_threat=is_threat,
            trigger_info=trigger_info,
            threat_categories=threat_categories
            if threat_categories is not None
            else ["xss"],
        )

    monkeypatch.setattr(
        "guard_core.core.checks.helpers.detect_penetration_patterns", fake_detect
    )


async def test_whitelisted_ip_is_never_escalated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_ip_banning=True, auto_ban_threshold=1)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch)

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(is_whitelisted=True),
        "1.1.1.1",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_restriction",
        "trigger",
    )

    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()
    mw.event_bus.send_middleware_event.assert_not_called()


async def test_falsy_client_ip_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    config = SecurityConfig(enable_ip_banning=True, auto_ban_threshold=1)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch)

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_restriction",
        "trigger",
    )

    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()


async def test_no_threat_no_counter_change_no_ban(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_ip_banning=True, auto_ban_threshold=1)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch, is_threat=False, trigger_info="not_enabled")

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "1.1.1.1",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_restriction",
        "trigger",
    )

    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()
    mw.event_bus.send_middleware_event.assert_not_called()


async def test_disabled_by_decorator_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    config = SecurityConfig(enable_ip_banning=True, auto_ban_threshold=1)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch, is_threat=False, trigger_info="disabled_by_decorator")

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "1.1.1.1",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_restriction",
        "trigger",
    )

    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()


async def test_never_reads_the_detection_pipeline_when_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detect_mock = AsyncMock(side_effect=AssertionError("must not scan the payload"))
    monkeypatch.setattr(
        "guard_core.core.checks.helpers.detect_penetration_attempt", detect_mock
    )
    config = SecurityConfig(
        enable_ip_banning=True, auto_ban_threshold=1, enable_penetration_detection=False
    )
    mw = _make_middleware()
    ban = AsyncMock()

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "3.3.3.3",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_restriction",
        "trigger",
    )

    detect_mock.assert_not_called()
    ban.ban_ip.assert_not_called()
    assert mw.suspicious_request_counts == {}


async def test_increments_the_real_detected_threat_category_not_the_synthetic_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_ip_banning=False)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch, threat_categories=["xss"])

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "2.2.2.2",
        MagicMock(),
        "ip_security",
        frozenset(),
        "user_agent",
        "Blocked user agent: curl",
    )

    assert mw.suspicious_request_counts["2.2.2.2"] == {"xss": 1}
    ban.ban_ip.assert_not_called()


async def test_increments_every_real_detected_category_in_one_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_ip_banning=False)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch, threat_categories=["xss", "sqli"])

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "2.2.2.3",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_blocked",
        "t",
    )

    assert mw.suspicious_request_counts["2.2.2.3"] == {"xss": 1, "sqli": 1}


async def test_no_detected_category_falls_back_to_uncategorized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_ip_banning=False)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch, threat_categories=[])

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "2.2.2.4",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_blocked",
        "t",
    )

    assert mw.suspicious_request_counts["2.2.2.4"] == {"uncategorized": 1}


async def test_ip_banning_disabled_no_ban(monkeypatch: pytest.MonkeyPatch) -> None:
    config = SecurityConfig(enable_ip_banning=False, auto_ban_threshold=1)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch)

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "3.3.3.3",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_restriction",
        "t",
    )

    assert mw.suspicious_request_counts["3.3.3.3"] == {"xss": 1}
    ban.ban_ip.assert_not_called()


async def test_below_flat_threshold_no_ban(monkeypatch: pytest.MonkeyPatch) -> None:
    config = SecurityConfig(enable_ip_banning=True, auto_ban_threshold=5)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch)

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "4.4.4.4",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_restriction",
        "t",
    )

    assert mw.suspicious_request_counts["4.4.4.4"] == {"xss": 1}
    ban.ban_ip.assert_not_called()


async def test_flat_threshold_met_after_repeated_violations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True, auto_ban_threshold=2, auto_ban_duration=300
    )
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch)

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "7.7.7.7",
        MagicMock(),
        "ip_security",
        frozenset(),
        "user_agent",
        "t",
    )
    assert ban.ban_ip.call_count == 0

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "7.7.7.7",
        MagicMock(),
        "ip_security",
        frozenset(),
        "user_agent",
        "t",
    )
    ban.ban_ip.assert_called_once_with("7.7.7.7", 300, "penetration_attempt")


async def test_first_violation_bans_immediately_when_threshold_is_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True, auto_ban_threshold=1, auto_ban_duration=60
    )
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch)

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "11.0.0.1",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_blocked",
        "t",
    )

    ban.ban_ip.assert_called_once_with("11.0.0.1", 60, "penetration_attempt")


async def test_per_category_ban_config_overrides_a_high_flat_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True,
        auto_ban_threshold=1000,
        threat_ban_config={"xss": ThreatBanConfig(threshold=1, duration=99999)},
    )
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch, threat_categories=["xss"])

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "9.9.9.9",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_blocked",
        "IP blocked by blocked_countries",
    )

    ban.ban_ip.assert_called_once_with("9.9.9.9", 99999, "penetration_attempt:xss")
    assert "9.9.9.9" not in mw.suspicious_request_counts


async def test_per_category_ban_takes_priority_over_flat_ban(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=60,
        threat_ban_config={"xss": ThreatBanConfig(threshold=1, duration=99999)},
    )
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch, threat_categories=["xss"])

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "9.9.9.10",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_blocked",
        "t",
    )

    ban.ban_ip.assert_called_once_with("9.9.9.10", 99999, "penetration_attempt:xss")


async def test_muted_check_logs_suppresses_log(monkeypatch: pytest.MonkeyPatch) -> None:
    config = SecurityConfig(
        enable_ip_banning=True, auto_ban_threshold=1, auto_ban_duration=60
    )
    mw = _make_middleware()
    ban = AsyncMock()
    log_mock = AsyncMock()
    monkeypatch.setattr("guard_core.core.checks.helpers.log_activity", log_mock)
    _patch_detect(monkeypatch)

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "12.0.0.1",
        MagicMock(),
        "ip_security",
        frozenset({"ip_security"}),
        "user_agent",
        "t",
    )

    ban.ban_ip.assert_called_once()
    log_mock.assert_called_once()
    assert log_mock.call_args.kwargs["muted_check_logs"] == {"ip_security"}


async def test_penetration_attempt_event_emitted_when_banned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True, auto_ban_threshold=1, auto_ban_duration=60
    )
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch)

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "13.0.0.1",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_restriction",
        "hit",
    )

    event_call = mw.event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "penetration_attempt"
    assert event_call.kwargs["action_taken"] == "banned"
    assert event_call.kwargs["trigger_info"] == "hit"


async def test_penetration_attempt_event_emitted_when_not_banned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_ip_banning=False)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch)

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "14.0.0.1",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_restriction",
        "hit",
    )

    event_call = mw.event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "penetration_attempt"
    assert event_call.kwargs["action_taken"] == "tracked"


async def test_penetration_attempt_event_still_carries_the_synthetic_identity_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_ip_banning=False)
    mw = _make_middleware()
    ban = AsyncMock()
    _patch_detect(monkeypatch, threat_categories=["xss"])

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "14.0.0.2",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_restriction",
        "hit",
    )

    event_call = mw.event_bus.send_middleware_event.await_args
    assert event_call.kwargs["violation_category"] == "ip_restriction"
    assert mw.suspicious_request_counts["14.0.0.2"] == {"xss": 1}


async def test_ban_failure_is_swallowed_logged_and_made_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True, auto_ban_threshold=1, auto_ban_duration=300
    )
    mw = _make_middleware()
    ban = AsyncMock()
    ban.ban_ip = AsyncMock(side_effect=ValueError("duration exceeds local cap"))
    logger = MagicMock()
    _patch_detect(monkeypatch)

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "40.0.0.1",
        logger,
        "ip_security",
        frozenset(),
        "ip_restriction",
        "t",
    )

    assert mw.suspicious_request_counts["40.0.0.1"] == {"xss": 1}
    ban.ban_ip.assert_called_once_with("40.0.0.1", 300, "penetration_attempt")
    logger.exception.assert_called_once()
    assert logger.exception.call_args.args[1] == "40.0.0.1"

    event_call = mw.event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "ip_ban_failed"
    assert event_call.kwargs["ip_address"] == "40.0.0.1"
    assert "duration exceeds local cap" in event_call.kwargs["reason"]


async def test_redis_error_during_ban_is_swallowed_logged_and_made_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True, auto_ban_threshold=1, auto_ban_duration=300
    )
    mw = _make_middleware()
    ban = AsyncMock()
    ban.ban_ip = AsyncMock(side_effect=ConnectionError("redis unavailable"))
    logger = MagicMock()
    _patch_detect(monkeypatch)

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "42.0.0.1",
        logger,
        "ip_security",
        frozenset(),
        "ip_restriction",
        "t",
    )

    logger.exception.assert_called_once()
    event_call = mw.event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "ip_ban_failed"
    assert "redis unavailable" in event_call.kwargs["reason"]


async def test_ban_and_event_bus_both_failing_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True, auto_ban_threshold=1, auto_ban_duration=300
    )
    mw = _make_middleware()
    ban = AsyncMock()
    ban.ban_ip = AsyncMock(side_effect=RuntimeError("redis down, ban not applied"))
    logger = MagicMock()
    _patch_detect(monkeypatch)

    async def selective_failure(*_a: Any, **kwargs: Any) -> None:
        if kwargs.get("event_type") == "ip_ban_failed":
            raise ConnectionError("event bus down too")

    mw.event_bus.send_middleware_event = AsyncMock(side_effect=selective_failure)

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "43.0.0.1",
        logger,
        "ip_security",
        frozenset(),
        "ip_restriction",
        "t",
    )

    assert mw.suspicious_request_counts["43.0.0.1"] == {"xss": 1}
    ban.ban_ip.assert_called_once()
    assert logger.exception.call_count == 2


async def test_a_broken_log_sink_never_escapes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_ip_banning=True, auto_ban_threshold=1, auto_ban_duration=300
    )
    mw = MagicMock()
    mw.suspicious_request_counts = {}
    mw.route_resolver = MagicMock()
    mw.route_resolver.should_bypass_check = lambda *_: False
    mw.event_bus = MagicMock()
    mw.event_bus.send_middleware_event = AsyncMock(
        side_effect=ConnectionError("event bus down too")
    )
    ban = AsyncMock()
    ban.ban_ip = AsyncMock(side_effect=RuntimeError("redis down"))
    logger = MagicMock()
    logger.exception = MagicMock(side_effect=OSError("log sink unavailable"))
    _patch_detect(monkeypatch)

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "44.0.0.1",
        logger,
        "ip_security",
        frozenset(),
        "ip_restriction",
        "t",
    )

    assert logger.exception.call_count == 2


async def test_bounds_suspicious_request_counts_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_ip_banning=False)
    mw = _make_middleware(
        {"1.1.1.1": {"ip_restriction": 1}, "2.2.2.2": {"x": 1}}, cap=2
    )
    ban = AsyncMock()
    _patch_detect(monkeypatch)

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "3.3.3.3",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_restriction",
        "t",
    )

    assert "1.1.1.1" not in mw.suspicious_request_counts
    assert "2.2.2.2" in mw.suspicious_request_counts
    assert mw.suspicious_request_counts["3.3.3.3"] == {"xss": 1}
    assert len(mw.suspicious_request_counts) == 2


async def test_touching_an_entry_protects_it_from_a_fresh_ip_flood(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cap = 20
    config = SecurityConfig(enable_ip_banning=False)
    mw = _make_middleware(cap=cap)
    ban = AsyncMock()
    _patch_detect(monkeypatch)

    async def touch(client_ip: str) -> None:
        await escalate_identity_violation(
            mw,
            config,
            ban,
            _make_request(),
            client_ip,
            MagicMock(),
            "ip_security",
            frozenset(),
            "ip_blocked",
            "t",
        )

    for _ in range(9):
        await touch("9.9.9.9")
    assert mw.suspicious_request_counts["9.9.9.9"] == {"xss": 9}

    flood_size = cap * 10
    for i in range(flood_size):
        await touch(f"203.0.{i // 256}.{i % 256}")
        if i % 5 == 0:
            await touch("9.9.9.9")

    assert "9.9.9.9" in mw.suspicious_request_counts
    assert mw.suspicious_request_counts["9.9.9.9"]["xss"] == 9 + flood_size // 5
    assert "203.0.0.0" not in mw.suspicious_request_counts
    assert len(mw.suspicious_request_counts) == cap


async def test_untouched_entry_is_the_first_evicted_when_over_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_ip_banning=False)
    mw = _make_middleware(cap=3)
    ban = AsyncMock()
    _patch_detect(monkeypatch)

    for ip in ("a", "b", "c"):
        await escalate_identity_violation(
            mw,
            config,
            ban,
            _make_request(),
            ip,
            MagicMock(),
            "ip_security",
            frozenset(),
            "ip_blocked",
            "t",
        )

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "b",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_blocked",
        "t",
    )

    await escalate_identity_violation(
        mw,
        config,
        ban,
        _make_request(),
        "d",
        MagicMock(),
        "ip_security",
        frozenset(),
        "ip_blocked",
        "t",
    )

    assert "a" not in mw.suspicious_request_counts
    assert set(mw.suspicious_request_counts) == {"b", "c", "d"}
