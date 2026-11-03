import logging
from typing import cast
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig, ThreatBanConfig
from guard_core.sync.core.checks.helpers import _resolve_and_apply_threshold_ban
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.suspatterns_handler import ALL_DETECTION_CATEGORIES


def test_threat_ban_config_accepts_positive_values() -> None:
    cfg = ThreatBanConfig(threshold=3, duration=86400)
    assert cfg.threshold == 3
    assert cfg.duration == 86400


def test_threat_ban_config_rejects_non_positive_threshold() -> None:
    with pytest.raises(ValueError):
        ThreatBanConfig(threshold=0, duration=60)


def test_threat_ban_config_rejects_non_positive_duration() -> None:
    with pytest.raises(ValueError):
        ThreatBanConfig(threshold=1, duration=0)


def test_security_config_threat_ban_config_default_empty() -> None:
    assert SyncSecurityConfig().threat_ban_config == {}


def test_security_config_threat_ban_config_accepts_valid_categories() -> None:
    config = SyncSecurityConfig(
        threat_ban_config={
            "xss": ThreatBanConfig(threshold=3, duration=86400),
            "sqli": ThreatBanConfig(threshold=1, duration=604800),
        }
    )
    assert config.threat_ban_config["xss"].threshold == 3
    assert config.threat_ban_config["sqli"].duration == 604800


def test_security_config_threat_ban_config_rejects_unknown_category() -> None:
    with pytest.raises(ValueError, match="Unknown threat categor"):
        SyncSecurityConfig(
            threat_ban_config={"nonsense": ThreatBanConfig(threshold=1, duration=60)}
        )


def test_security_config_threat_ban_config_accepts_all_known_categories() -> None:
    config = SyncSecurityConfig(
        threat_ban_config={
            cat: ThreatBanConfig(threshold=1, duration=60)
            for cat in ALL_DETECTION_CATEGORIES
        }
    )
    assert set(config.threat_ban_config.keys()) == set(ALL_DETECTION_CATEGORIES)


def _build_check(config: SyncSecurityConfig) -> SuspiciousActivityCheck:
    middleware = MagicMock()
    middleware.config = config
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        return_value=MagicMock(status_code=403)
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False

    return SuspiciousActivityCheck(middleware)


def _make_detect_fn(result: DetectionResult) -> object:
    def fake_detect(*_args: object, **_kwargs: object) -> DetectionResult:
        return result

    return fake_detect


def _patch_detect_and_ban(
    monkeypatch: pytest.MonkeyPatch,
    check: SuspiciousActivityCheck,
    result: DetectionResult,
    ban_calls: list[tuple[str, int, str]],
) -> None:
    monkeypatch.setattr(
        "guard_core.sync.core.checks.implementations.suspicious_activity"
        ".get_cached_detection_result",
        _make_detect_fn(result),
    )

    def fake_ban(ip: str, duration: int, reason: str, *, grouped: bool = False) -> None:
        ban_calls.append((ip, duration, reason))

    monkeypatch.setattr(check.ip_ban_manager, "_ban_ip_escalating", fake_ban)


def _make_request(client_ip: str) -> MagicMock:
    request = MagicMock()
    request.state.is_whitelisted = False
    request.state.client_ip = client_ip
    request.state.route_config = None
    request.url_full = "https://test/x"
    return request


def test_per_category_ban_fires_at_category_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(
        enable_ip_banning=True,
        auto_ban_threshold=1000,
        auto_ban_duration=60,
        threat_ban_config={"xss": ThreatBanConfig(threshold=2, duration=86400)},
    )
    check = _build_check(config)

    ban_calls: list[tuple[str, int, str]] = []
    _patch_detect_and_ban(
        monkeypatch,
        check,
        DetectionResult(
            is_threat=True,
            trigger_info="Query param 'q': XSS pattern",
            threat_categories=["xss"],
            threat_scores={"xss": 1.0},
        ),
        ban_calls,
    )

    request = _make_request("1.2.3.4")

    check.check(request)
    assert ban_calls == []

    check.check(request)
    assert len(ban_calls) == 1
    ip, duration, reason = ban_calls[0]
    assert ip == "1.2.3.4"
    assert duration == 86400
    assert reason == "penetration_attempt:xss"


def test_flat_ban_fires_when_no_per_category_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(
        enable_ip_banning=True,
        auto_ban_threshold=2,
        auto_ban_duration=60,
        threat_ban_config={},
    )
    check = _build_check(config)

    ban_calls: list[tuple[str, int, str]] = []
    _patch_detect_and_ban(
        monkeypatch,
        check,
        DetectionResult(
            is_threat=True,
            trigger_info="trigger",
            threat_categories=["xss"],
            threat_scores={"xss": 1.0},
        ),
        ban_calls,
    )

    request = _make_request("5.6.7.8")

    check.check(request)
    assert ban_calls == []
    check.check(request)
    assert len(ban_calls) == 1
    _, duration, reason = ban_calls[0]
    assert duration == 60
    assert reason == "penetration_attempt"


def test_per_category_ban_short_circuits_flat_ban(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=60,
        threat_ban_config={"xss": ThreatBanConfig(threshold=1, duration=9999)},
    )
    check = _build_check(config)

    ban_calls: list[tuple[str, int, str]] = []
    _patch_detect_and_ban(
        monkeypatch,
        check,
        DetectionResult(
            is_threat=True,
            trigger_info="trigger",
            threat_categories=["xss"],
            threat_scores={"xss": 1.0},
        ),
        ban_calls,
    )

    request = _make_request("9.9.9.9")

    check.check(request)
    assert len(ban_calls) == 1
    assert ban_calls[0][1] == 9999
    assert ban_calls[0][2] == "penetration_attempt:xss"


def test_per_category_skip_when_entry_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=60,
        threat_ban_config={"xss": ThreatBanConfig(threshold=10, duration=99)},
    )
    check = _build_check(config)

    ban_calls: list[tuple[str, int, str]] = []
    _patch_detect_and_ban(
        monkeypatch,
        check,
        DetectionResult(
            is_threat=True,
            trigger_info="trigger",
            threat_categories=["sqli", "xss"],
            threat_scores={"sqli": 1.0, "xss": 1.0},
        ),
        ban_calls,
    )

    request = _make_request("10.0.0.1")

    check.check(request)
    assert len(ban_calls) == 1
    assert ban_calls[0][1] == 60
    assert ban_calls[0][2] == "penetration_attempt"


def test_no_ban_when_ip_banning_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(
        enable_ip_banning=False,
        auto_ban_threshold=1,
        auto_ban_duration=60,
        threat_ban_config={"xss": ThreatBanConfig(threshold=1, duration=86400)},
    )
    check = _build_check(config)

    ban_calls: list[tuple[str, int, str]] = []
    _patch_detect_and_ban(
        monkeypatch,
        check,
        DetectionResult(
            is_threat=True,
            trigger_info="trigger",
            threat_categories=["xss"],
            threat_scores={"xss": 1.0},
        ),
        ban_calls,
    )

    request = _make_request("11.0.0.1")

    check.check(request)
    assert ban_calls == []


def test_uncategorized_threat_increments_uncategorized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=60,
        threat_ban_config={},
    )
    check = _build_check(config)

    ban_calls: list[tuple[str, int, str]] = []
    _patch_detect_and_ban(
        monkeypatch,
        check,
        DetectionResult(
            is_threat=True,
            trigger_info="trigger",
            threat_categories=[],
            threat_scores={},
        ),
        ban_calls,
    )

    request = _make_request("12.0.0.1")

    check.check(request)
    assert check.middleware.suspicious_request_counts["12.0.0.1"]["uncategorized"] == 1


def test_passive_mode_with_threat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(
        passive_mode=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=60,
    )
    check = _build_check(config)

    ban_calls: list[tuple[str, int, str]] = []
    _patch_detect_and_ban(
        monkeypatch,
        check,
        DetectionResult(
            is_threat=True,
            trigger_info="trigger",
            threat_categories=["xss"],
            threat_scores={"xss": 1.0},
        ),
        ban_calls,
    )

    request = _make_request("13.0.0.1")

    result = check.check(request)
    assert result is None
    assert ban_calls == []
    assert check.middleware.suspicious_request_counts == {}


def test_no_threat_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    config = SyncSecurityConfig()
    check = _build_check(config)

    ban_calls: list[tuple[str, int, str]] = []
    _patch_detect_and_ban(
        monkeypatch,
        check,
        DetectionResult(is_threat=False, trigger_info=""),
        ban_calls,
    )

    request = _make_request("14.0.0.1")

    result = check.check(request)
    assert result is None
    assert ban_calls == []


def test_disabled_by_decorator_emits_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig()
    check = _build_check(config)

    ban_calls: list[tuple[str, int, str]] = []
    _patch_detect_and_ban(
        monkeypatch,
        check,
        DetectionResult(is_threat=False, trigger_info="disabled_by_decorator"),
        ban_calls,
    )

    request = _make_request("15.0.0.1")

    result = check.check(request)
    assert result is None
    send_event = check.middleware.event_bus.send_middleware_event
    assert isinstance(send_event, MagicMock)
    send_event.assert_called_once()


def test_check_skips_when_whitelisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig()
    check = _build_check(config)

    request = MagicMock()
    request.state.is_whitelisted = True
    request.state.client_ip = "16.0.0.1"

    result = check.check(request)
    assert result is None


def test_check_skips_when_no_client_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig()
    check = _build_check(config)

    request = MagicMock()
    request.state.is_whitelisted = False
    request.state.client_ip = None
    request.state.route_config = None

    result = check.check(request)
    assert result is None


def _build_check_with_fresh_ip_ban_manager(
    config: SyncSecurityConfig,
) -> tuple[SuspiciousActivityCheck, IPBanManager]:
    IPBanManager._instance = None
    fresh_manager = IPBanManager()
    fresh_manager.redis_handler = None

    check = _build_check(config)
    check.ip_ban_manager = fresh_manager
    return check, fresh_manager


def test_refused_ban_falls_through_to_400_not_403(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=60,
    )
    check, fresh_manager = _build_check_with_fresh_ip_ban_manager(config)

    monkeypatch.setattr(
        "guard_core.sync.core.checks.implementations.suspicious_activity"
        ".get_cached_detection_result",
        _make_detect_fn(
            DetectionResult(
                is_threat=True,
                trigger_info="trigger",
                threat_categories=["xss"],
                threat_scores={"xss": 1.0},
            )
        ),
    )

    request = _make_request("127.0.0.1")

    caplog.set_level(logging.WARNING)
    check.check(request)

    cast(MagicMock, check.middleware.create_error_response).assert_called_once_with(
        status_code=400,
        default_message="Suspicious activity detected",
    )
    assert not any("IP banned" in r.getMessage() for r in caplog.records)
    assert fresh_manager.is_ip_banned("127.0.0.1") is False


def test_applied_ban_still_gives_403(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=60,
    )
    check, fresh_manager = _build_check_with_fresh_ip_ban_manager(config)

    monkeypatch.setattr(
        "guard_core.sync.core.checks.implementations.suspicious_activity"
        ".get_cached_detection_result",
        _make_detect_fn(
            DetectionResult(
                is_threat=True,
                trigger_info="trigger",
                threat_categories=["xss"],
                threat_scores={"xss": 1.0},
            )
        ),
    )

    request = _make_request("203.0.113.50")

    check.check(request)

    cast(MagicMock, check.middleware.create_error_response).assert_called_once_with(
        status_code=403,
        default_message="IP has been banned",
    )
    assert fresh_manager.is_ip_banned("203.0.113.50") is True


def test_per_category_ban_refused_returns_none() -> None:
    config = SyncSecurityConfig(
        enable_ip_banning=True,
        auto_ban_threshold=1000,
        auto_ban_duration=60,
        threat_ban_config={"xss": ThreatBanConfig(threshold=1, duration=86400)},
    )
    ip_ban_manager = MagicMock()
    ip_ban_manager._ban_ip_escalating = MagicMock(return_value=None)

    result = _resolve_and_apply_threshold_ban(
        {"xss": 1},
        config,
        ip_ban_manager,
        "127.0.0.1",
        ["xss"],
        "penetration_attempt",
    )

    assert result is None
    ip_ban_manager._ban_ip_escalating.assert_called_once_with(
        "127.0.0.1", 86400, "penetration_attempt:xss", grouped=False
    )
