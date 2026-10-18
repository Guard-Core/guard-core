from typing import Any
from unittest.mock import MagicMock, Mock, patch

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.handlers.ratelimit_handler import RateLimitBlock


def _mw(cfg: SecurityConfig) -> Mock:
    mw = Mock()
    mw.config = cfg
    mw.logger = Mock()
    mw.event_bus = Mock()
    mw.event_bus.send_middleware_event = MagicMock()
    mw.create_error_response = MagicMock(return_value=Mock(status_code=403))
    mw.route_resolver = Mock()
    mw.route_resolver.should_bypass_check = Mock(return_value=False)
    mw.geo_ip_handler = None
    mw.suspicious_request_counts = {}
    return mw


def _req(rc: RouteConfig, ip: str = "1.2.3.4") -> Mock:
    r = Mock()
    r.state = Mock()
    r.state.client_ip = ip
    r.state.route_config = rc
    del r.state.is_whitelisted
    return r


@patch("guard_core.sync.core.checks.implementations.ip_security.log_activity")
def test_route_whitelist_is_not_global_trust(_mock_log: Any) -> None:
    cfg = SecurityConfig()
    cfg.passive_mode = False
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    rc.rate_limit = 1
    req = _req(rc)

    check = IpSecurityCheck(_mw(cfg))
    with patch.object(check, "ip_ban_manager") as mock_ban_manager:
        mock_ban_manager.is_ip_banned = MagicMock(return_value=False)
        result = check.check(req)

    assert result is None
    assert req.state.is_whitelisted is False


@patch("guard_core.sync.core.checks.implementations.ip_security.log_activity")
def test_route_whitelist_does_not_lift_the_global_blacklist(
    _mock_log: Any,
) -> None:
    cfg = SecurityConfig()
    cfg.passive_mode = False
    cfg.blacklist = ("1.2.3.4",)
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]

    check = IpSecurityCheck(_mw(cfg))
    with patch.object(check, "ip_ban_manager") as mock_ban_manager:
        mock_ban_manager.is_ip_banned = MagicMock(return_value=False)
        result = check.check(_req(rc))

    assert result is not None


def test_route_whitelisted_ip_still_rate_limited() -> None:
    cfg = SecurityConfig()
    cfg.passive_mode = False
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    rc.rate_limit = 1
    req = _req(rc)
    req.state.is_whitelisted = False

    mw = _mw(cfg)
    mw.rate_limit_handler = Mock()
    mw.rate_limit_handler.report_rate_limit_block = MagicMock()
    mw.rate_limit_handler.check_rate_limit_tiers = MagicMock(
        return_value=RateLimitBlock(0, 2, Mock(status_code=429))
    )

    result = RateLimitCheck(mw).check(req)

    assert result is not None
    mw.rate_limit_handler.check_rate_limit_tiers.assert_called_once()


@patch("guard_core.sync.core.checks.implementations.suspicious_activity.log_activity")
def test_route_whitelisted_ip_still_scanned_for_attacks(_mock_log: Any) -> None:
    cfg = SecurityConfig()
    cfg.passive_mode = False
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    req = _req(rc)
    req.state.is_whitelisted = False

    threat = DetectionResult(
        is_threat=True, trigger_info="xss", threat_categories=["xss"]
    )
    with patch(
        "guard_core.sync.core.checks.implementations.suspicious_activity."
        "get_cached_detection_result",
        new=MagicMock(return_value=threat),
    ) as mock_detect:
        result = SuspiciousActivityCheck(_mw(cfg)).check(req)

    assert result is not None
    mock_detect.assert_called_once()


@patch("guard_core.sync.core.checks.implementations.ip_security.log_activity")
def test_global_cloud_block_is_left_to_the_cloud_provider_check(
    _mock_log: Any,
) -> None:
    cfg = SecurityConfig()
    cfg.passive_mode = False
    cfg.block_cloud_providers = frozenset({"AWS"})
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    req = _req(rc)

    check = IpSecurityCheck(_mw(cfg))
    with (
        patch.object(check, "ip_ban_manager") as mock_ban_manager,
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as cloud,
    ):
        mock_ban_manager.is_ip_banned = MagicMock(return_value=False)
        cloud.is_cloud_ip = Mock(return_value=True)
        result = check.check(req)

    assert result is None
    cloud.is_cloud_ip.assert_not_called()
    assert req.state.is_whitelisted is False
