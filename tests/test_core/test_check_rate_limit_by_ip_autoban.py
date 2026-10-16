import time
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

import guard_core.handlers.ratelimit_handler as ratelimit_handler
from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.ratelimit_handler import (
    _by_ip_autoban_counts,
    check_rate_limit_by_ip,
)
from guard_core.models import SecurityConfig, ThreatBanConfig

BanCalls = list[tuple[str, int, str]]


def _install_recording_ban_manager(
    config: SecurityConfig,
) -> tuple[IPBanManager, BanCalls]:
    IPBanManager._instance = None
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = config
    ban_calls: BanCalls = []

    async def fake_ban(
        ip: str, duration: int, reason: str = "threshold_exceeded"
    ) -> bool:
        ban_calls.append((ip, duration, reason))
        return True

    manager.ban_ip = fake_ban  # type: ignore[method-assign]
    return manager, ban_calls


async def test_knob_off_default_never_bans_on_repeated_violations() -> None:
    config = SecurityConfig(
        enable_redis=False,
        rate_limit=1,
        rate_limit_window=60,
        enable_ip_banning=True,
        auto_ban_threshold=1,
    )
    assert config.enable_rate_limit_auto_ban is False
    _, ban_calls = _install_recording_ban_manager(config)
    try:
        ip = "192.0.2.101"
        await check_rate_limit_by_ip(ip, config)
        await check_rate_limit_by_ip(ip, config)
        await check_rate_limit_by_ip(ip, config)

        assert ban_calls == []
    finally:
        IPBanManager._instance = None


async def test_threshold_crossing_bans_with_configured_duration_and_reason() -> None:
    config = SecurityConfig(
        enable_redis=False,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=2,
        auto_ban_duration=1234,
    )
    _, ban_calls = _install_recording_ban_manager(config)
    try:
        ip = "192.0.2.102"

        assert await check_rate_limit_by_ip(ip, config) is True
        assert await check_rate_limit_by_ip(ip, config) is False
        assert ban_calls == []

        assert await check_rate_limit_by_ip(ip, config) is False
        assert ban_calls == [(ip, 1234, "rate_limit_exceeded")]
    finally:
        IPBanManager._instance = None


async def test_per_category_threat_ban_config_override_honored() -> None:
    config = SecurityConfig(
        enable_redis=False,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=1000,
        auto_ban_duration=60,
        threat_ban_config={"rate_limit": ThreatBanConfig(threshold=1, duration=999)},
    )
    _, ban_calls = _install_recording_ban_manager(config)
    try:
        ip = "192.0.2.103"

        assert await check_rate_limit_by_ip(ip, config) is True
        assert await check_rate_limit_by_ip(ip, config) is False

        assert ban_calls == [(ip, 999, "rate_limit_exceeded:rate_limit")]
    finally:
        IPBanManager._instance = None


async def test_passive_mode_suppresses_counting_and_ban() -> None:
    config = SecurityConfig(
        passive_mode=True,
        enable_redis=False,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
    )
    _, ban_calls = _install_recording_ban_manager(config)
    try:
        ip = "192.0.2.104"

        assert await check_rate_limit_by_ip(ip, config) is True
        assert await check_rate_limit_by_ip(ip, config) is False

        assert ban_calls == []
        assert ip not in _by_ip_autoban_counts
    finally:
        IPBanManager._instance = None


async def test_enable_ip_banning_false_suppresses_ban() -> None:
    config = SecurityConfig(
        enable_redis=False,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=False,
        auto_ban_threshold=1,
    )
    _, ban_calls = _install_recording_ban_manager(config)
    try:
        ip = "192.0.2.105"
        await check_rate_limit_by_ip(ip, config)
        await check_rate_limit_by_ip(ip, config)

        assert ban_calls == []
    finally:
        IPBanManager._instance = None


async def test_loopback_ip_not_banned_despite_threshold_crossing() -> None:
    config = SecurityConfig(
        enable_redis=False,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
    )
    IPBanManager._instance = None
    try:
        real_manager = IPBanManager()
        real_manager.redis_handler = None
        real_manager.config = config

        assert await check_rate_limit_by_ip("127.0.0.1", config) is True
        assert await check_rate_limit_by_ip("127.0.0.1", config) is False

        assert "127.0.0.1" not in real_manager.banned_ips
    finally:
        IPBanManager._instance = None


async def test_rejected_ip_input_records_no_autoban_count() -> None:
    config = SecurityConfig(
        enable_redis=False,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
    )
    bad_ip = "not-an-ip-192.0.2.106"

    try:
        await check_rate_limit_by_ip(bad_ip, config)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass

    assert bad_ip not in _by_ip_autoban_counts


async def test_redis_backed_over_limit_feeds_autoban_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_redis=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=111,
    )
    _, ban_calls = _install_recording_ban_manager(config)
    try:

        async def fake_redis_count(
            *_args: object, **_kwargs: object
        ) -> tuple[int, None]:
            return 5, None

        monkeypatch.setattr(
            "guard_core.handlers.ratelimit_handler._redis_request_count",
            fake_redis_count,
        )

        ip = "192.0.2.107"
        result = await check_rate_limit_by_ip(ip, config, redis_handler=Mock())

        assert result is False
        assert ban_calls == [(ip, 111, "rate_limit_exceeded")]
    finally:
        IPBanManager._instance = None


async def test_already_banned_ip_makes_zero_additional_ban_calls() -> None:
    config = SecurityConfig(
        enable_redis=False,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=2,
        auto_ban_duration=1234,
    )
    IPBanManager._instance = None
    try:
        manager = IPBanManager()
        manager.redis_handler = None
        manager.config = config
        ban_calls: BanCalls = []

        async def fake_ban(
            ip: str, duration: int, reason: str = "threshold_exceeded"
        ) -> bool:
            ban_calls.append((ip, duration, reason))
            manager.banned_ips[ip] = time.time() + duration
            return True

        manager.ban_ip = fake_ban  # type: ignore[method-assign]

        ip = "192.0.2.110"

        assert await check_rate_limit_by_ip(ip, config) is True
        assert await check_rate_limit_by_ip(ip, config) is False
        assert ban_calls == []

        assert await check_rate_limit_by_ip(ip, config) is False
        assert ban_calls == [(ip, 1234, "rate_limit_exceeded")]
        assert ip not in _by_ip_autoban_counts

        for _ in range(3):
            assert await check_rate_limit_by_ip(ip, config) is False

        assert ban_calls == [(ip, 1234, "rate_limit_exceeded")]
        assert ip not in _by_ip_autoban_counts
    finally:
        IPBanManager._instance = None


def _make_middleware(config: SecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=429))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.geo_ip_handler = None
    middleware.suspicious_request_counts = {}
    middleware.rate_limit_handler = Mock()
    middleware.rate_limit_handler.check_rate_limit = AsyncMock(
        return_value=Mock(status_code=429)
    )
    return middleware


def _make_request(client_ip: str) -> MagicMock:
    request = MagicMock()
    request.state.client_ip = client_ip
    request.state.route_config = None
    request.state.is_whitelisted = False
    request.url_path = "/api/test"
    return request


async def test_dedicated_counter_isolated_from_middleware_suspicious_counts() -> None:
    config = SecurityConfig(
        enable_redis=False,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=1000,
    )
    IPBanManager._instance = None
    try:
        real_manager = IPBanManager()
        real_manager.redis_handler = None
        real_manager.config = config

        middleware = _make_middleware(config)
        check = RateLimitCheck(middleware)
        check.ip_ban_manager = Mock()
        check.ip_ban_manager.ban_ip = AsyncMock()

        await check.check(_make_request("192.0.2.108"))

        primitive_ip = "192.0.2.109"
        await check_rate_limit_by_ip(primitive_ip, config)
        await check_rate_limit_by_ip(primitive_ip, config)

        assert middleware.suspicious_request_counts == {
            "192.0.2.108": {"rate_limit": 1}
        }
        assert primitive_ip not in middleware.suspicious_request_counts
        assert _by_ip_autoban_counts[primitive_ip] == 1
        assert "192.0.2.108" not in _by_ip_autoban_counts
    finally:
        IPBanManager._instance = None


async def test_autoban_counter_evicts_the_oldest_ip_a_touched_ip_survives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _by_ip_autoban_counts.clear()
    monkeypatch.setattr(ratelimit_handler, "_MAX_TRACKED_RATE_LIMIT_KEYS", 3)
    config = SecurityConfig(
        enable_redis=False,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=1_000_000,
    )
    _install_recording_ban_manager(config)
    try:
        for ip in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
            await check_rate_limit_by_ip(ip, config)
            await check_rate_limit_by_ip(ip, config)

        assert set(_by_ip_autoban_counts) == {
            "198.51.100.1",
            "198.51.100.2",
            "198.51.100.3",
        }

        await check_rate_limit_by_ip("198.51.100.1", config)
        await check_rate_limit_by_ip("198.51.100.1", config)
        await check_rate_limit_by_ip("198.51.100.4", config)
        await check_rate_limit_by_ip("198.51.100.4", config)

        assert len(_by_ip_autoban_counts) == 3
        assert "198.51.100.2" not in _by_ip_autoban_counts
        assert "198.51.100.1" in _by_ip_autoban_counts
        assert "198.51.100.4" in _by_ip_autoban_counts
    finally:
        IPBanManager._instance = None
