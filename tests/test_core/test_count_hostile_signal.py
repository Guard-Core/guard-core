from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from guard_core.core.checks.helpers import count_hostile_signal_and_maybe_ban
from guard_core.models import SecurityConfig, ThreatBanConfig

BOT_IP = "40.0.0.1"


def _check(config: SecurityConfig, ban: Any = None, counts: Any = None) -> Any:
    middleware = MagicMock()
    middleware.config = config
    middleware.suspicious_request_counts = counts if counts is not None else {}
    middleware.event_bus.send_middleware_event = AsyncMock()
    return SimpleNamespace(
        config=config,
        middleware=middleware,
        logger=MagicMock(),
        check_name="authentication",
        ip_ban_manager=ban if ban is not None else AsyncMock(),
    )


def _request(client_ip: str | None = BOT_IP, whitelisted: bool = False) -> Any:
    request = MagicMock()
    request.state.client_ip = client_ip
    request.state.is_whitelisted = whitelisted
    request.url_full = "https://test/x"
    return request


async def test_unknown_client_is_not_counted() -> None:
    check = _check(SecurityConfig(auto_ban_threshold=1))

    assert not await count_hostile_signal_and_maybe_ban(
        check, _request(client_ip=None), "referrer", "t"
    )
    assert check.middleware.suspicious_request_counts == {}


async def test_whitelisted_client_is_not_counted() -> None:
    check = _check(SecurityConfig(auto_ban_threshold=1))

    assert not await count_hostile_signal_and_maybe_ban(
        check, _request(whitelisted=True), "referrer", "t"
    )
    assert check.middleware.suspicious_request_counts == {}


async def test_banning_disabled_neither_counts_nor_bans() -> None:
    check = _check(SecurityConfig(enable_ip_banning=False, auto_ban_threshold=1))

    assert not await count_hostile_signal_and_maybe_ban(
        check, _request(), "referrer", "t"
    )
    assert check.middleware.suspicious_request_counts == {}
    check.ip_ban_manager.ban_ip.assert_not_called()


async def test_default_threshold_argument_applies_when_no_override() -> None:
    check = _check(SecurityConfig(auto_ban_threshold=50, auto_ban_duration=90))

    banned = await count_hostile_signal_and_maybe_ban(
        check, _request(), "honeypot", "t", 1
    )

    assert banned is True
    check.ip_ban_manager.ban_ip.assert_awaited_once_with(
        BOT_IP, 90, "honeypot_triggered:honeypot", grouped=False
    )


async def test_threat_ban_config_entry_beats_default_threshold() -> None:
    config = SecurityConfig(
        auto_ban_threshold=50,
        threat_ban_config={"honeypot": ThreatBanConfig(threshold=2, duration=5)},
    )
    check = _check(config)

    assert not await count_hostile_signal_and_maybe_ban(
        check, _request(), "honeypot", "t", 1
    )
    assert await count_hostile_signal_and_maybe_ban(
        check, _request(), "honeypot", "t", 1
    )
    check.ip_ban_manager.ban_ip.assert_awaited_once_with(
        BOT_IP, 5, "honeypot_triggered:honeypot", grouped=False
    )


async def test_ban_failure_is_swallowed_logged_and_made_visible() -> None:
    ban = AsyncMock()
    ban.ban_ip = AsyncMock(side_effect=ConnectionError("redis unavailable"))
    check = _check(SecurityConfig(auto_ban_threshold=1), ban)

    banned = await count_hostile_signal_and_maybe_ban(
        check, _request(), "referrer", "t"
    )

    assert banned is False
    check.logger.exception.assert_called_once()
    event_call = check.middleware.event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "ip_ban_failed"
    assert event_call.kwargs["ip_address"] == BOT_IP
    assert "redis unavailable" in event_call.kwargs["reason"]


async def test_ban_and_event_bus_both_failing_does_not_raise() -> None:
    ban = AsyncMock()
    ban.ban_ip = AsyncMock(side_effect=RuntimeError("redis down"))
    check = _check(SecurityConfig(auto_ban_threshold=1), ban)
    check.middleware.event_bus.send_middleware_event = AsyncMock(
        side_effect=ConnectionError("event bus down too")
    )

    assert not await count_hostile_signal_and_maybe_ban(
        check, _request(), "referrer", "t"
    )
    assert check.logger.exception.call_count == 2


async def test_a_broken_log_sink_never_escapes() -> None:
    ban = AsyncMock()
    ban.ban_ip = AsyncMock(side_effect=RuntimeError("redis down"))
    check = _check(SecurityConfig(auto_ban_threshold=1), ban)
    check.middleware.event_bus.send_middleware_event = AsyncMock(
        side_effect=ConnectionError("event bus down too")
    )
    check.logger.exception = MagicMock(side_effect=OSError("log sink unavailable"))

    assert not await count_hostile_signal_and_maybe_ban(
        check, _request(), "referrer", "t"
    )
    assert check.logger.exception.call_count == 2


async def test_tracked_ips_stay_bounded() -> None:
    counts = {"1.1.1.1": {"referrer": 1}, "2.2.2.2": {"referrer": 1}}
    check = _check(
        SecurityConfig(auto_ban_threshold=9, ban_counters_max_tracked_ips=2),
        counts=counts,
    )

    await count_hostile_signal_and_maybe_ban(
        check, _request("3.3.3.3"), "referrer", "t"
    )

    assert "1.1.1.1" not in counts
    assert "2.2.2.2" in counts
    assert counts["3.3.3.3"] == {"referrer": 1}


async def test_touching_an_entry_protects_it_from_a_fresh_ip_flood() -> None:
    cap = 20
    check = _check(
        SecurityConfig(auto_ban_threshold=1000, ban_counters_max_tracked_ips=cap)
    )

    async def touch(client_ip: str) -> None:
        await count_hostile_signal_and_maybe_ban(
            check, _request(client_ip), "referrer", "t"
        )

    for _ in range(9):
        await touch("9.9.9.9")
    for i in range(cap * 10):
        await touch(f"203.0.{i // 256}.{i % 256}")
        if i % 5 == 0:
            await touch("9.9.9.9")

    counts = check.middleware.suspicious_request_counts
    assert counts["9.9.9.9"]["referrer"] == 9 + (cap * 10) // 5
    assert "203.0.0.0" not in counts
    assert len(counts) == cap
