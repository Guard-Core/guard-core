from typing import cast
from unittest.mock import MagicMock, Mock

import pytest
from pydantic import ValidationError

from guard_core.models import SyncSecurityConfig, ThreatBanConfig
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.ratelimit_handler import RateLimitBlock

BanCalls = list[tuple[str, int, str]]


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
    request.url_full = "https://test/api/test"
    return request


def _make_check_with_recording_ban(
    config: SyncSecurityConfig,
) -> tuple[RateLimitCheck, BanCalls]:
    middleware = _make_middleware(config)
    check = RateLimitCheck(middleware)
    ban_calls: BanCalls = []

    def fake_ban(ip: str, duration: int, reason: str, *, grouped: bool = False) -> None:
        ban_calls.append((ip, duration, reason))

    check.ip_ban_manager = Mock()
    check.ip_ban_manager._ban_ip_escalating = fake_ban
    return check, ban_calls


def test_knob_off_default_never_bans_on_violation() -> None:
    config = SyncSecurityConfig(
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_ip_banning=True,
        auto_ban_threshold=1,
    )
    assert config.enable_rate_limit_auto_ban is False
    check, ban_calls = _make_check_with_recording_ban(config)

    check.check(_make_request("1.1.1.1"))
    check.check(_make_request("1.1.1.1"))

    assert ban_calls == []


def test_threshold_crossing_bans_with_configured_duration_and_reason() -> None:
    config = SyncSecurityConfig(
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=2,
        auto_ban_duration=1234,
    )
    check, ban_calls = _make_check_with_recording_ban(config)
    request = _make_request("2.2.2.2")

    check.check(request)
    assert ban_calls == []

    check.check(request)
    assert len(ban_calls) == 1
    ip, duration, reason = ban_calls[0]
    assert ip == "2.2.2.2"
    assert duration == 1234
    assert reason == "rate_limit_exceeded"


def test_per_category_threat_ban_config_override_honored() -> None:
    config = SyncSecurityConfig(
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=1000,
        auto_ban_duration=60,
        threat_ban_config={"rate_limit": ThreatBanConfig(threshold=1, duration=999)},
    )
    check, ban_calls = _make_check_with_recording_ban(config)

    check.check(_make_request("3.3.3.3"))

    assert len(ban_calls) == 1
    ip, duration, reason = ban_calls[0]
    assert ip == "3.3.3.3"
    assert duration == 999
    assert reason == "rate_limit_exceeded:rate_limit"


def test_threat_ban_config_accepts_rate_limit_pseudo_category() -> None:
    config = SyncSecurityConfig(
        threat_ban_config={"rate_limit": ThreatBanConfig(threshold=1, duration=60)}
    )

    assert config.threat_ban_config["rate_limit"].threshold == 1


def test_enabled_detection_categories_rejects_rate_limit_pseudo_category() -> None:
    with pytest.raises(ValidationError, match="Unknown detection categor"):
        SyncSecurityConfig(enabled_detection_categories=["rate_limit"])


def test_passive_mode_does_not_feed_counter_or_ban() -> None:
    config = SyncSecurityConfig(
        passive_mode=True,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
    )
    check, ban_calls = _make_check_with_recording_ban(config)

    result = check.check(_make_request("4.4.4.4"))

    assert result is None
    assert ban_calls == []
    assert check.middleware.suspicious_request_counts == {}


def test_loopback_ip_not_banned_despite_threshold_crossing() -> None:
    IPBanManager._instance = None
    try:
        config = SyncSecurityConfig(
            enable_rate_limiting=True,
            rate_limit=1,
            rate_limit_window=60,
            enable_rate_limit_auto_ban=True,
            enable_ip_banning=True,
            auto_ban_threshold=1,
        )
        middleware = _make_middleware(config)
        check = RateLimitCheck(middleware)
        real_manager = IPBanManager()
        real_manager.redis_handler = None
        real_manager.config = config
        check.ip_ban_manager = real_manager

        check.check(_make_request("127.0.0.1"))

        assert "127.0.0.1" not in real_manager.banned_ips
    finally:
        IPBanManager._instance = None


def test_enable_ip_banning_false_suppresses_ban() -> None:
    config = SyncSecurityConfig(
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=False,
        auto_ban_threshold=1,
    )
    check, ban_calls = _make_check_with_recording_ban(config)

    check.check(_make_request("5.5.5.5"))

    assert ban_calls == []


def test_a_failing_shared_violation_counter_falls_back_to_the_process_count() -> None:
    config = SyncSecurityConfig(
        enable_redis=True,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=2,
        auto_ban_duration=300,
    )
    check, ban_calls = _make_check_with_recording_ban(config)
    assert isinstance(check.middleware.rate_limit_handler, Mock)
    check.middleware.rate_limit_handler.redis_handler = Mock(
        record_sliding_window_hit=MagicMock(side_effect=ConnectionError("redis down"))
    )
    request = _make_request("4.4.4.4")

    check.check(request)
    check.check(request)

    assert ban_calls == [("4.4.4.4", 300, "rate_limit_exceeded")]
    logger = cast(Mock, check.middleware.logger)
    assert logger.warning.call_count == 2
    assert "redis down" in str(logger.warning.call_args)
