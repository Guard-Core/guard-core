from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.sync.decorators.base import RouteConfig


@pytest.fixture
def security_config() -> SyncSecurityConfig:
    config = SyncSecurityConfig(ban_on_hostile_signals=False)
    config.passive_mode = False
    return config


@pytest.fixture
def mock_middleware(security_config: SyncSecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = security_config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=403))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.geo_ip_handler = None
    return middleware


@pytest.fixture
def ip_security_check(mock_middleware: Mock) -> IpSecurityCheck:
    return IpSecurityCheck(mock_middleware)


def _request_for(route_config: RouteConfig | None) -> Mock:
    request = Mock()
    request.state = Mock()
    request.state.client_ip = "1.2.3.4"
    request.state.route_config = route_config
    return request


def _unbanned(ip_security_check: IpSecurityCheck) -> object:
    mgr = patch.object(ip_security_check, "ip_ban_manager").start()
    mgr.is_ip_banned = MagicMock(return_value=False)
    return mgr


@pytest.fixture(autouse=True)
def _patches(ip_security_check: IpSecurityCheck) -> object:
    _unbanned(ip_security_check)
    patch(
        "guard_core.sync.core.checks.implementations.ip_security.log_activity"
    ).start()
    patch(
        "guard_core.sync.core.checks.helpers.escalate_identity_violation",
        new=MagicMock(),
    ).start()
    yield
    patch.stopall()


def test_decorated_route_still_enforces_global_blacklist(
    ip_security_check: IpSecurityCheck, security_config: SyncSecurityConfig
) -> None:
    security_config.blacklist = ("1.2.3.4",)
    route_config = RouteConfig()
    route_config.rate_limit = 5

    result = ip_security_check.check(_request_for(route_config))

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.call_args
    assert event_call.kwargs["event_type"] == "ip_blocked"


def test_route_ip_whitelist_does_not_override_global_blacklist(
    ip_security_check: IpSecurityCheck, security_config: SyncSecurityConfig
) -> None:
    security_config.blacklist = ("1.2.3.4",)
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    request = _request_for(route_config)

    result = ip_security_check.check(request)

    assert result is not None
    assert request.state.is_whitelisted is False


def test_route_country_rules_keep_global_ip_blacklist_active(
    ip_security_check: IpSecurityCheck,
    security_config: SyncSecurityConfig,
    mock_middleware: Mock,
) -> None:
    security_config.blacklist = ("1.2.3.4",)
    mock_middleware.geo_ip_handler = Mock()
    mock_middleware.geo_ip_handler.get_country = Mock(return_value="US")
    route_config = RouteConfig()
    route_config.blocked_countries = ["RU"]

    result = ip_security_check.check(_request_for(route_config))

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.call_args
    assert event_call.kwargs["event_type"] == "ip_blocked"
    assert event_call.kwargs["filter_type"] == "global"


def test_route_without_ip_fields_leaves_global_whitelist_semantics(
    ip_security_check: IpSecurityCheck, security_config: SyncSecurityConfig
) -> None:
    security_config.whitelist = ("9.9.9.9",)
    route_config = RouteConfig()
    route_config.rate_limit = 5
    request = _request_for(route_config)

    result = ip_security_check.check(request)

    assert result is not None
    assert request.state.is_whitelisted is False


def test_global_whitelist_match_sets_is_whitelisted_with_route_config(
    ip_security_check: IpSecurityCheck, security_config: SyncSecurityConfig
) -> None:
    security_config.whitelist = ("1.2.3.4",)
    security_config.whitelist_access_only = False
    route_config = RouteConfig()
    route_config.rate_limit = 5
    request = _request_for(route_config)

    result = ip_security_check.check(request)

    assert result is None
    assert request.state.is_whitelisted is True


def test_route_whitelist_with_unparseable_ip_blocks_at_route_step(
    ip_security_check: IpSecurityCheck, security_config: SyncSecurityConfig
) -> None:
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    request = _request_for(route_config)
    request.state.client_ip = "not-an-ip"

    result = ip_security_check.check(request)

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.call_args
    assert event_call.kwargs["event_type"] == "decorator_violation"


def test_globally_whitelisted_config_with_unparseable_client_ip_not_whitelisted(
    ip_security_check: IpSecurityCheck, security_config: SyncSecurityConfig
) -> None:
    security_config.whitelist = ("1.2.3.4",)
    route_config = RouteConfig()
    route_config.ip_whitelist = ["9.9.9.9"]
    request = _request_for(route_config)
    request.state = SimpleNamespace(client_ip="not-an-ip", route_config=route_config)

    result = ip_security_check.check(request)

    assert result is not None
    assert getattr(request.state, "is_whitelisted", False) is False


def test_global_check_unparseable_ip_with_route_whitelist_not_whitelisted(
    ip_security_check: IpSecurityCheck, security_config: SyncSecurityConfig
) -> None:
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    request = _request_for(route_config)
    request.state.client_ip = "not-an-ip"

    result = ip_security_check._check_global_ip_restrictions(
        request, "not-an-ip", route_config
    )

    assert request.state.is_whitelisted is False
    assert result is not None


def test_route_blacklist_only_still_enforces_global_whitelist(
    ip_security_check: IpSecurityCheck, security_config: SyncSecurityConfig
) -> None:
    security_config.whitelist = ("1.1.1.1",)
    route_config = RouteConfig()
    route_config.ip_blacklist = ["6.6.6.6"]

    result = ip_security_check.check(_request_for(route_config))

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.call_args
    assert event_call.kwargs["event_type"] == "ip_blocked"
    assert event_call.kwargs["filter_type"] == "global"


def test_route_blacklist_only_allows_globally_whitelisted_client(
    ip_security_check: IpSecurityCheck, security_config: SyncSecurityConfig
) -> None:
    security_config.whitelist = ("1.2.3.4",)
    security_config.whitelist_access_only = False
    route_config = RouteConfig()
    route_config.ip_blacklist = ["6.6.6.6"]
    request = _request_for(route_config)

    result = ip_security_check.check(request)

    assert result is None
    assert request.state.is_whitelisted is True


def test_route_blocked_countries_only_still_enforces_global_blocked_countries(
    ip_security_check: IpSecurityCheck,
    security_config: SyncSecurityConfig,
    mock_middleware: Mock,
) -> None:
    security_config.whitelist = ()
    security_config.blacklist = ()
    security_config.geo_ip_handler = Mock()
    security_config.blocked_countries = frozenset({"CN"})
    mock_middleware.geo_ip_handler = Mock()
    mock_middleware.geo_ip_handler.get_country = Mock(return_value="CN")
    route_config = RouteConfig()
    route_config.blocked_countries = ["RU"]

    result = ip_security_check.check(_request_for(route_config))

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.call_args
    assert event_call.kwargs["event_type"] == "ip_blocked"
    assert event_call.kwargs["filter_type"] == "global"


def test_route_whitelist_match_overrides_global_whitelist_default_deny(
    ip_security_check: IpSecurityCheck, security_config: SyncSecurityConfig
) -> None:
    security_config.whitelist = ("1.1.1.1",)
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    request = _request_for(route_config)

    result = ip_security_check.check(request)

    assert result is None
    assert request.state.is_whitelisted is False


def test_route_whitelist_set_but_client_excluded_blocks_at_route_step(
    ip_security_check: IpSecurityCheck, security_config: SyncSecurityConfig
) -> None:
    route_config = RouteConfig()
    route_config.ip_whitelist = ["9.9.9.9"]
    request = _request_for(route_config)

    result = ip_security_check.check(request)

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.call_args
    assert event_call.kwargs["event_type"] == "decorator_violation"


def test_route_ip_whitelist_match_still_denied_by_route_country_mismatch(
    ip_security_check: IpSecurityCheck,
    security_config: SyncSecurityConfig,
    mock_middleware: Mock,
) -> None:
    mock_middleware.geo_ip_handler = Mock()
    mock_middleware.geo_ip_handler.get_country = Mock(return_value="CN")
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    route_config.whitelist_countries = ["US"]
    request = _request_for(route_config)

    result = ip_security_check.check(request)

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.call_args
    assert event_call.kwargs["event_type"] == "decorator_violation"


def test_route_ip_whitelist_match_does_not_bypass_global_blocked_countries(
    ip_security_check: IpSecurityCheck,
    security_config: SyncSecurityConfig,
    mock_middleware: Mock,
) -> None:
    security_config.geo_ip_handler = Mock()
    security_config.blocked_countries = frozenset({"CN"})
    mock_middleware.geo_ip_handler = Mock()
    mock_middleware.geo_ip_handler.get_country = Mock(return_value="CN")
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    request = _request_for(route_config)

    result = ip_security_check.check(request)

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.call_args
    assert event_call.kwargs["event_type"] == "ip_blocked"
    assert event_call.kwargs["filter_type"] == "global"


def test_route_whitelist_countries_match_skips_global_blocked_countries(
    ip_security_check: IpSecurityCheck,
    security_config: SyncSecurityConfig,
    mock_middleware: Mock,
) -> None:
    security_config.geo_ip_handler = Mock()
    security_config.blocked_countries = frozenset({"US"})
    mock_middleware.geo_ip_handler = Mock()
    mock_middleware.geo_ip_handler.get_country = Mock(return_value="US")
    route_config = RouteConfig()
    route_config.whitelist_countries = ["US"]
    request = _request_for(route_config)

    result = ip_security_check.check(request)

    assert result is None
    assert request.state.is_whitelisted is False


def test_route_ip_whitelist_overrides_route_ip_blacklist_same_ip(
    ip_security_check: IpSecurityCheck, security_config: SyncSecurityConfig
) -> None:
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    route_config.ip_blacklist = ["1.2.3.4"]
    request = _request_for(route_config)

    result = ip_security_check.check(request)

    assert result is None
    assert request.state.is_whitelisted is False


def test_global_cloud_provider_list_is_not_evaluated_by_ip_security(
    ip_security_check: IpSecurityCheck, security_config: SyncSecurityConfig
) -> None:
    from guard_core.sync.handlers.cloud_handler import cloud_handler

    security_config.block_cloud_providers = frozenset({"AWS"})

    with patch.object(cloud_handler, "is_cloud_ip", return_value=True) as is_cloud:
        result = ip_security_check.check(_request_for(None))

    assert result is None
    is_cloud.assert_not_called()


def test_global_country_block_names_the_country(
    ip_security_check: IpSecurityCheck,
    security_config: SyncSecurityConfig,
    mock_middleware: Mock,
) -> None:
    security_config.geo_ip_handler = Mock()
    security_config.blocked_countries = frozenset({"RU"})
    mock_middleware.geo_ip_handler = Mock()
    mock_middleware.geo_ip_handler.get_country = Mock(return_value="RU")

    result = ip_security_check.check(_request_for(None))

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.call_args
    assert event_call.kwargs["event_type"] == "ip_blocked"
    assert event_call.kwargs["filter_type"] == "global"
    assert "RU" in event_call.kwargs["reason"]
    assert "allowlist/blocklist" not in event_call.kwargs["reason"]
    assert "cloud_provider" not in event_call.kwargs
    assert "network" not in event_call.kwargs


def test_global_blacklist_block_keeps_existing_reason(
    ip_security_check: IpSecurityCheck, security_config: SyncSecurityConfig
) -> None:
    security_config.blacklist = ("1.2.3.4",)

    result = ip_security_check.check(_request_for(None))

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.call_args
    assert event_call.kwargs["event_type"] == "ip_blocked"
    assert event_call.kwargs["filter_type"] == "global"
    assert event_call.kwargs["reason"] == "IP 1.2.3.4 not in global allowlist/blocklist"
    assert "cloud_provider" not in event_call.kwargs
