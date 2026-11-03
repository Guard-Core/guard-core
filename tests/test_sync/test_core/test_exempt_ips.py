import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.implementations.cloud_provider import (
    CloudProviderCheck,
)
from guard_core.sync.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.core.checks.implementations.user_agent import UserAgentCheck
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.handlers.ratelimit_handler import RateLimitBlock

EXEMPT_IP = "198.51.100.7"
OTHER_IP = "203.0.113.9"
_IMPL = "guard_core.sync.core.checks.implementations"


def _config(**fields: object) -> SyncSecurityConfig:
    config = SyncSecurityConfig(**fields)
    config.passive_mode = False
    return config


def _middleware(config: SyncSecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.event_bus.send_cloud_detection_events = MagicMock()
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=403))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.route_resolver.get_cloud_providers_to_check = Mock(return_value=["AWS"])
    middleware.geo_ip_handler = None
    middleware.suspicious_request_counts = {}
    return middleware


def _request(
    ip: str,
    route_config: RouteConfig | None = None,
    user_agent: str = "curl/8.0",
    **state: object,
) -> Mock:
    request = Mock()
    request.state = SimpleNamespace(client_ip=ip, route_config=route_config, **state)
    request.headers = {"User-Agent": user_agent}
    return request


def _ip_check(
    config: SyncSecurityConfig, request: Mock, banned: bool = False
) -> object:
    check = IpSecurityCheck(_middleware(config))
    with (
        patch.object(check, "ip_ban_manager") as ban_manager,
        patch(f"{_IMPL}.ip_security.log_activity", new=MagicMock()),
        patch(
            "guard_core.sync.core.checks.helpers.escalate_identity_violation",
            new=MagicMock(),
        ),
    ):
        ban_manager.is_ip_banned = MagicMock(return_value=banned)
        return check.check(request)


@pytest.mark.parametrize(
    ("ip", "expected"),
    [(EXEMPT_IP, True), ("198.51.100.20", True), (OTHER_IP, False), ("unknown", False)],
)
def test_exempt_match_sets_the_flag_without_blocking_anyone(
    ip: str, expected: bool
) -> None:
    request = _request(ip)

    result = _ip_check(_config(exempt_ips=[EXEMPT_IP, "198.51.100.16/28"]), request)

    assert result is None
    assert request.state.is_exempt is expected
    assert request.state.is_whitelisted is False


def test_blacklisted_exempt_ip_is_still_blocked() -> None:
    request = _request(EXEMPT_IP)

    result = _ip_check(_config(exempt_ips=[EXEMPT_IP], blacklist=[EXEMPT_IP]), request)

    assert result is not None
    assert request.state.is_exempt is False


def test_banned_exempt_ip_is_still_blocked() -> None:
    result = _ip_check(
        _config(exempt_ips=[EXEMPT_IP]), _request(EXEMPT_IP), banned=True
    )

    assert result is not None


def test_exempt_ip_does_not_pass_a_restrictive_whitelist() -> None:
    request = _request(EXEMPT_IP)

    result = _ip_check(_config(exempt_ips=[EXEMPT_IP], whitelist=[OTHER_IP]), request)

    assert result is not None
    assert request.state.is_exempt is False


def test_route_block_ip_still_blocks_an_exempt_ip() -> None:
    route_config = RouteConfig()
    route_config.ip_blacklist = [EXEMPT_IP]

    result = _ip_check(
        _config(exempt_ips=[EXEMPT_IP]), _request(EXEMPT_IP, route_config)
    )

    assert result is not None


def test_route_require_ip_takes_over_as_it_does_for_the_whitelist() -> None:
    route_config = RouteConfig()
    route_config.ip_whitelist = [EXEMPT_IP]
    request = _request(EXEMPT_IP, route_config)

    result = _ip_check(_config(exempt_ips=[EXEMPT_IP], whitelist=[EXEMPT_IP]), request)

    assert result is None
    assert (request.state.is_whitelisted, request.state.is_exempt) == (False, False)


@pytest.mark.parametrize("ip_list", ["whitelist", "exempt_ips"])
def test_global_cloud_block_is_left_to_the_cloud_provider_check(
    ip_list: str,
) -> None:
    with patch.object(cloud_handler, "is_cloud_ip", return_value=True) as is_cloud:
        result = _ip_check(
            _config(block_cloud_providers={"AWS"}, **{ip_list: [EXEMPT_IP]}),
            _request(EXEMPT_IP),
        )

    assert result is None
    is_cloud.assert_not_called()


def _run_twice(
    check: SecurityCheck,
    route_config: RouteConfig | None = None,
    user_agent: str = "curl/8.0",
) -> tuple[Any, Any]:
    exempt = check.check(
        _request(
            EXEMPT_IP,
            route_config,
            user_agent,
            is_whitelisted=False,
            is_exempt=True,
        )
    )
    not_exempt = check.check(
        _request(
            EXEMPT_IP,
            route_config,
            user_agent,
            is_whitelisted=False,
            is_exempt=False,
        )
    )
    return exempt, not_exempt


def test_rate_limit_is_skipped_for_an_exempt_request() -> None:
    middleware = _middleware(_config(exempt_ips=[EXEMPT_IP], rate_limit=1))
    middleware.rate_limit_handler = Mock()
    middleware.rate_limit_handler.report_rate_limit_block = MagicMock()
    middleware.rate_limit_handler.check_rate_limit_tiers = MagicMock(
        return_value=RateLimitBlock(0, 2, Mock(status_code=429))
    )
    route_config = RouteConfig()
    route_config.rate_limit = 1

    exempt, not_exempt = _run_twice(
        RateLimitCheck(middleware), route_config=route_config
    )

    assert exempt is None
    assert not_exempt is not None


def test_user_agent_check_is_skipped_for_an_exempt_request() -> None:
    config = _config(exempt_ips=[EXEMPT_IP], blocked_user_agents=["badbot"])

    with patch(f"{_IMPL}.user_agent.log_activity", new=MagicMock()):
        exempt, not_exempt = _run_twice(
            UserAgentCheck(_middleware(config)), user_agent="badbot/1.0"
        )

    assert exempt is None
    assert not_exempt is not None


def test_cloud_provider_check_is_skipped_for_an_exempt_request() -> None:
    check = CloudProviderCheck(
        _middleware(_config(exempt_ips=[EXEMPT_IP], block_cloud_providers={"AWS"}))
    )
    check.cloud_handler = Mock()
    check.cloud_handler.is_cloud_ip = Mock(return_value=True)
    check.cloud_handler.get_cloud_provider_details = Mock(
        return_value=("AWS", "3.0.0.0/8")
    )

    with patch(f"{_IMPL}.cloud_provider.log_activity", new=MagicMock()):
        exempt, not_exempt = _run_twice(check)

    assert exempt is None
    assert not_exempt is not None


def test_penetration_detection_still_scans_an_exempt_request() -> None:
    threat = DetectionResult(
        is_threat=True, trigger_info="xss", threat_categories=["xss"]
    )

    with (
        patch(
            f"{_IMPL}.suspicious_activity.get_cached_detection_result",
            new=MagicMock(return_value=threat),
        ),
        patch(f"{_IMPL}.suspicious_activity.log_activity", new=MagicMock()),
    ):
        result = SuspiciousActivityCheck(
            _middleware(_config(exempt_ips=[EXEMPT_IP]))
        ).check(_request(EXEMPT_IP, is_whitelisted=False, is_exempt=True))

    assert result is not None


def test_exempt_ips_defaults_to_empty() -> None:
    assert SyncSecurityConfig().exempt_ips == ()


def test_a_prefix_zero_exempt_entry_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(exempt_ips=["0.0.0.0/0"])

    assert any(
        "exempt_ips contains a /0 network" in record.getMessage()
        for record in caplog.records
    )
