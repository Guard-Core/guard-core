import time
from collections.abc import Iterator
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.models import SyncSecurityConfig, ThreatBanConfig
from guard_core.sync.core.checks.helpers import SUSPICIOUS_COUNT_WINDOW_SECONDS
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.ratelimit_handler import (
    RateLimitBlock,
    RateLimitVerdict,
    _by_ip_autoban_counts,
    check_rate_limit_by_ip,
)

BanCalls = list[tuple[str, int, str]]


@pytest.fixture(autouse=True)
def _undo_started_patches() -> Iterator[None]:
    yield
    patch.stopall()


def _install_recording_ban_manager(
    config: SyncSecurityConfig,
) -> tuple[IPBanManager, BanCalls]:
    IPBanManager._instance = None
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = config
    ban_calls: BanCalls = []

    def fake_ban(
        _self: IPBanManager,
        ip: str,
        duration: int,
        reason: str = "threshold_exceeded",
        *,
        grouped: bool = False,
    ) -> int | None:
        ban_calls.append((ip, duration, reason))
        return duration

    patch.object(IPBanManager, "_ban_ip_escalating", fake_ban).start()
    return manager, ban_calls


def test_knob_off_default_never_bans_on_repeated_violations() -> None:
    config = SyncSecurityConfig(
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
        check_rate_limit_by_ip(ip, config)
        check_rate_limit_by_ip(ip, config)
        check_rate_limit_by_ip(ip, config)

        assert ban_calls == []
    finally:
        IPBanManager._instance = None


def test_threshold_crossing_bans_with_configured_duration_and_reason() -> None:
    config = SyncSecurityConfig(
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

        assert check_rate_limit_by_ip(ip, config) is True
        assert check_rate_limit_by_ip(ip, config) is False
        assert ban_calls == []

        assert check_rate_limit_by_ip(ip, config) is False
        assert ban_calls == [(ip, 1234, "rate_limit_exceeded")]
    finally:
        IPBanManager._instance = None


def test_per_category_threat_ban_config_override_honored() -> None:
    config = SyncSecurityConfig(
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

        assert check_rate_limit_by_ip(ip, config) is True
        assert check_rate_limit_by_ip(ip, config) is False

        assert ban_calls == [(ip, 999, "rate_limit_exceeded:rate_limit")]
    finally:
        IPBanManager._instance = None


def test_passive_mode_suppresses_counting_and_ban() -> None:
    config = SyncSecurityConfig(
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

        assert check_rate_limit_by_ip(ip, config) is True
        assert check_rate_limit_by_ip(ip, config) is False

        assert ban_calls == []
        assert ip not in _by_ip_autoban_counts.for_app(config)
    finally:
        IPBanManager._instance = None


def test_enable_ip_banning_false_suppresses_ban() -> None:
    config = SyncSecurityConfig(
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
        check_rate_limit_by_ip(ip, config)
        check_rate_limit_by_ip(ip, config)

        assert ban_calls == []
    finally:
        IPBanManager._instance = None


def test_loopback_ip_not_banned_despite_threshold_crossing() -> None:
    config = SyncSecurityConfig(
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

        assert check_rate_limit_by_ip("127.0.0.1", config) is True
        assert check_rate_limit_by_ip("127.0.0.1", config) is False

        assert "127.0.0.1" not in real_manager.banned_ips
    finally:
        IPBanManager._instance = None


def test_rejected_ip_input_records_no_autoban_count() -> None:
    config = SyncSecurityConfig(
        enable_redis=False,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
    )
    bad_ip = "not-an-ip-192.0.2.106"

    try:
        check_rate_limit_by_ip(bad_ip, config)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass

    assert bad_ip not in _by_ip_autoban_counts.for_app(config)


def test_redis_backed_over_limit_feeds_autoban_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(
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

        def fake_redis_verdict(
            *_args: object, **_kwargs: object
        ) -> tuple[RateLimitVerdict, None]:
            return RateLimitVerdict(0, 6, 30), None

        monkeypatch.setattr(
            "guard_core.sync.handlers.ratelimit_handler._redis_tier_verdict",
            fake_redis_verdict,
        )

        ip = "192.0.2.107"
        redis = Mock(
            record_sliding_window_hit=MagicMock(return_value=1), delete=MagicMock()
        )
        result = check_rate_limit_by_ip(ip, config, redis_handler=redis)

        assert result is False
        assert ban_calls == [(ip, 111, "rate_limit_exceeded")]
    finally:
        IPBanManager._instance = None


def test_already_banned_ip_makes_zero_additional_ban_calls() -> None:
    config = SyncSecurityConfig(
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

        def fake_ban(
            ip: str,
            duration: int,
            reason: str = "threshold_exceeded",
            *,
            grouped: bool = False,
        ) -> int | None:
            ban_calls.append((ip, duration, reason))
            manager.banned_ips[ip] = time.time() + duration
            return duration

        patch.object(manager, "_ban_ip_escalating", fake_ban).start()

        ip = "192.0.2.110"

        assert check_rate_limit_by_ip(ip, config) is True
        assert check_rate_limit_by_ip(ip, config) is False
        assert ban_calls == []

        assert check_rate_limit_by_ip(ip, config) is False
        assert ban_calls == [(ip, 1234, "rate_limit_exceeded")]
        assert ip not in _by_ip_autoban_counts.for_app(config)

        for _ in range(3):
            assert check_rate_limit_by_ip(ip, config) is False

        assert ban_calls == [(ip, 1234, "rate_limit_exceeded")]
        assert ip not in _by_ip_autoban_counts.for_app(config)
    finally:
        IPBanManager._instance = None


def _make_middleware(config: SyncSecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=429))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.geo_ip_handler = None
    middleware.suspicious_request_counts = {}
    middleware.rate_limit_handler = Mock(redis_handler=None)
    middleware.rate_limit_handler.report_rate_limit_block = MagicMock()
    middleware.rate_limit_handler.check_rate_limit_tiers = MagicMock(
        return_value=RateLimitBlock(0, 2, Mock(status_code=429))
    )
    return middleware


def _make_request(client_ip: str) -> MagicMock:
    request = MagicMock()
    request.state.client_ip = client_ip
    request.state.route_config = None
    request.state.is_whitelisted = False
    request.url_path = "/api/test"
    return request


def test_dedicated_counter_isolated_from_middleware_suspicious_counts() -> None:
    config = SyncSecurityConfig(
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
        check.ip_ban_manager._ban_ip_escalating = MagicMock()

        check.check(_make_request("192.0.2.108"))

        primitive_ip = "192.0.2.109"
        check_rate_limit_by_ip(primitive_ip, config)
        check_rate_limit_by_ip(primitive_ip, config)

        assert middleware.suspicious_request_counts == {
            "192.0.2.108": {"rate_limit": 1}
        }
        assert primitive_ip not in middleware.suspicious_request_counts
        assert _by_ip_autoban_counts.for_app(config)[primitive_ip] == {"rate_limit": 1}
        assert "192.0.2.108" not in _by_ip_autoban_counts.for_app(config)
    finally:
        IPBanManager._instance = None


def test_autoban_counter_evicts_the_oldest_ip_a_touched_ip_survives() -> None:
    _by_ip_autoban_counts.clear()
    config = SyncSecurityConfig(
        ban_counters_max_tracked_ips=3,
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
            check_rate_limit_by_ip(ip, config)
            check_rate_limit_by_ip(ip, config)

        assert set(_by_ip_autoban_counts.for_app(config)) == {
            "198.51.100.1",
            "198.51.100.2",
            "198.51.100.3",
        }

        check_rate_limit_by_ip("198.51.100.1", config)
        check_rate_limit_by_ip("198.51.100.1", config)
        check_rate_limit_by_ip("198.51.100.4", config)
        check_rate_limit_by_ip("198.51.100.4", config)

        assert len(_by_ip_autoban_counts.for_app(config)) == 3
        assert "198.51.100.2" not in _by_ip_autoban_counts.for_app(config)
        assert "198.51.100.1" in _by_ip_autoban_counts.for_app(config)
        assert "198.51.100.4" in _by_ip_autoban_counts.for_app(config)
    finally:
        IPBanManager._instance = None


def _autoban_config() -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=2,
        auto_ban_duration=600,
    )


def test_violations_older_than_the_window_do_not_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 10_000.0}
    monkeypatch.setattr(time, "monotonic", lambda: clock["now"])
    config = _autoban_config()
    _, ban_calls = _install_recording_ban_manager(config)
    ip = "192.0.2.150"
    try:
        check_rate_limit_by_ip(ip, config)
        assert check_rate_limit_by_ip(ip, config) is False
        clock["now"] += SUSPICIOUS_COUNT_WINDOW_SECONDS + 1
        assert check_rate_limit_by_ip(ip, config) is False

        assert ban_calls == []
    finally:
        IPBanManager._instance = None
        _by_ip_autoban_counts.for_app(config).pop(ip, None)


def test_violations_inside_the_window_still_ban_and_clear_the_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 20_000.0}
    monkeypatch.setattr(time, "monotonic", lambda: clock["now"])
    config = _autoban_config()
    _, ban_calls = _install_recording_ban_manager(config)
    ip = "192.0.2.151"
    try:
        check_rate_limit_by_ip(ip, config)
        assert check_rate_limit_by_ip(ip, config) is False
        clock["now"] += SUSPICIOUS_COUNT_WINDOW_SECONDS - 1
        assert check_rate_limit_by_ip(ip, config) is False

        assert ban_calls == [(ip, 600, "rate_limit_exceeded")]
        assert ip not in _by_ip_autoban_counts.for_app(config)
    finally:
        IPBanManager._instance = None
        _by_ip_autoban_counts.for_app(config).pop(ip, None)


def test_a_failing_shared_violation_counter_falls_back_to_the_process_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(
        enable_redis=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=222,
    )
    _, ban_calls = _install_recording_ban_manager(config)
    try:
        redis = Mock(
            record_sliding_window_hit=MagicMock(side_effect=ConnectionError("down")),
            delete=MagicMock(),
        )
        ip = "192.0.2.111"

        def no_redis_verdict(*_args: object, **_kwargs: object) -> tuple[None, None]:
            return None, None

        monkeypatch.setattr(
            "guard_core.sync.handlers.ratelimit_handler._redis_tier_verdict",
            no_redis_verdict,
        )

        assert check_rate_limit_by_ip(ip, config, redis_handler=redis) is True
        assert check_rate_limit_by_ip(ip, config, redis_handler=redis) is False
        assert ban_calls == [(ip, 222, "rate_limit_exceeded")]
    finally:
        IPBanManager._instance = None
