from typing import Any, cast
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.utils import IpAccessResult


@pytest.fixture
def security_config() -> SecurityConfig:
    config = SecurityConfig()
    config.passive_mode = False
    return config


@pytest.fixture
def mock_middleware(security_config: SecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = security_config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=403))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.geo_ip_handler = Mock()
    return middleware


@pytest.fixture
def ip_security_check(mock_middleware: Mock) -> IpSecurityCheck:
    return IpSecurityCheck(mock_middleware)


@pytest.fixture
def mock_request() -> Mock:
    request = Mock()
    request.state = Mock()
    request.state.client_ip = "1.2.3.4"
    request.state.route_config = None
    return request


def test_check_banned_ip_bypass(
    ip_security_check: IpSecurityCheck, mock_request: Mock
) -> None:
    route_config = RouteConfig()
    mock_resolver = Mock()
    mock_resolver.should_bypass_check = Mock(return_value=True)
    cast(Any, ip_security_check.middleware).route_resolver = mock_resolver

    result = ip_security_check._check_banned_ip(mock_request, "1.2.3.4", route_config)
    assert result is None


def test_check_banned_ip_passive_mode(
    ip_security_check: IpSecurityCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    security_config.passive_mode = True

    with patch.object(ip_security_check, "ip_ban_manager") as mock_ban_mgr:
        mock_ban_mgr.is_ip_banned = MagicMock(return_value=True)

        with patch(
            "guard_core.sync.core.checks.implementations.ip_security.log_activity"
        ) as mock_log:
            mock_log.return_value = MagicMock()

            result = ip_security_check._check_banned_ip(mock_request, "1.2.3.4", None)
            assert result is None


def test_check_route_ip_restrictions_passive_mode(
    ip_security_check: IpSecurityCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    security_config.passive_mode = True
    route_config = RouteConfig()

    with patch(
        "guard_core.sync.core.checks.implementations.ip_security.check_route_ip_access"
    ) as mock_check:
        mock_check.return_value = False

        with patch(
            "guard_core.sync.core.checks.implementations.ip_security.log_activity"
        ) as mock_log:
            mock_log.return_value = None

            result = ip_security_check._check_route_ip_restrictions(
                mock_request, "1.2.3.4", route_config
            )
            assert result is None


def test_check_no_client_ip(
    ip_security_check: IpSecurityCheck, mock_request: Mock
) -> None:
    mock_request.state.client_ip = None

    result = ip_security_check.check(mock_request)
    assert result is None


def test_check_global_ip_restrictions_passive_mode(
    ip_security_check: IpSecurityCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    security_config.passive_mode = True

    with patch(
        "guard_core.sync.core.checks.implementations.ip_security.check_ip_access",
        return_value=IpAccessResult(
            False, "IP 1.2.3.4 not in global allowlist/blocklist"
        ),
    ):
        with patch(
            "guard_core.sync.core.checks.implementations.ip_security.log_activity"
        ) as mock_log:
            mock_log.return_value = MagicMock()

            result = ip_security_check._check_global_ip_restrictions(
                mock_request, "1.2.3.4"
            )
            assert result is None


def test_check_with_bypass_ip_check(
    ip_security_check: IpSecurityCheck, mock_request: Mock
) -> None:
    with patch.object(ip_security_check, "ip_ban_manager") as mock_ban_mgr:
        mock_ban_mgr.is_ip_banned = MagicMock(return_value=False)

        mock_bypass = Mock(side_effect=lambda check, config: check == "ip")
        mock_resolver2 = Mock()
        mock_resolver2.should_bypass_check = mock_bypass
        cast(Any, ip_security_check.middleware).route_resolver = mock_resolver2

        result = ip_security_check.check(mock_request)
        assert result is None


def test_full_flow_with_route_config(
    ip_security_check: IpSecurityCheck, mock_request: Mock
) -> None:
    route_config = RouteConfig()
    mock_request.state.route_config = route_config

    with patch.object(ip_security_check, "ip_ban_manager") as mock_ban_mgr:
        mock_ban_mgr.is_ip_banned = MagicMock(return_value=False)

        with patch(
            "guard_core.sync.core.checks.implementations.ip_security.check_route_ip_access"
        ) as mock_check:
            mock_check.return_value = MagicMock(return_value=True)

            result = ip_security_check.check(mock_request)
            assert result is None


def test_unknown_client_identity_not_blocked_with_default_config(
    ip_security_check: IpSecurityCheck, mock_request: Mock
) -> None:
    mock_request.state.client_ip = "unknown"

    with patch.object(ip_security_check, "ip_ban_manager") as mock_ban_mgr:
        mock_ban_mgr.is_ip_banned = MagicMock(return_value=False)

        result = ip_security_check.check(mock_request)
        assert result is None


def test_unknown_client_identity_blocked_when_whitelist_configured(
    ip_security_check: IpSecurityCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    security_config.whitelist = ("10.0.0.1",)
    mock_request.state.client_ip = "unknown"

    with patch.object(ip_security_check, "ip_ban_manager") as mock_ban_mgr:
        mock_ban_mgr.is_ip_banned = MagicMock(return_value=False)

        with patch(
            "guard_core.sync.core.checks.implementations.ip_security.log_activity"
        ):
            with patch(
                "guard_core.sync.core.checks.helpers.escalate_identity_violation",
                new=MagicMock(),
            ):
                result = ip_security_check.check(mock_request)
                assert result is not None
                assert result.status_code == 403


def test_unknown_client_identity_blocked_when_whitelist_countries_configured(
    ip_security_check: IpSecurityCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    security_config.geo_ip_handler = Mock()
    security_config.whitelist_countries = frozenset({"US"})
    mock_request.state.client_ip = "unknown"

    with patch.object(ip_security_check, "ip_ban_manager") as mock_ban_mgr:
        mock_ban_mgr.is_ip_banned = MagicMock(return_value=False)

        with patch(
            "guard_core.sync.core.checks.implementations.ip_security.log_activity"
        ):
            with patch(
                "guard_core.sync.core.checks.helpers.escalate_identity_violation",
                new=MagicMock(),
            ):
                result = ip_security_check.check(mock_request)
                assert result is not None
                assert result.status_code == 403


def test_unknown_client_identity_with_empty_route_config_not_blocked(
    ip_security_check: IpSecurityCheck, mock_request: Mock
) -> None:
    mock_request.state.client_ip = "unknown"
    mock_request.state.route_config = RouteConfig()

    with patch.object(ip_security_check, "ip_ban_manager") as mock_ban_mgr:
        mock_ban_mgr.is_ip_banned = MagicMock(return_value=False)

        result = ip_security_check.check(mock_request)
        assert result is None


def test_unknown_client_identity_with_route_whitelist_blocked(
    ip_security_check: IpSecurityCheck, mock_request: Mock
) -> None:
    mock_request.state.client_ip = "unknown"
    route_config = RouteConfig()
    route_config.ip_whitelist = ["10.0.0.1"]
    mock_request.state.route_config = route_config

    with patch.object(ip_security_check, "ip_ban_manager") as mock_ban_mgr:
        mock_ban_mgr.is_ip_banned = MagicMock(return_value=False)

        with patch(
            "guard_core.sync.core.checks.implementations.ip_security.log_activity"
        ):
            with patch(
                "guard_core.sync.core.checks.helpers.escalate_identity_violation",
                new=MagicMock(),
            ):
                result = ip_security_check.check(mock_request)
                assert result is not None
                assert result.status_code == 403


def test_unknown_client_identity_with_route_whitelist_countries_blocked(
    ip_security_check: IpSecurityCheck, mock_request: Mock
) -> None:
    mock_request.state.client_ip = "unknown"
    route_config = RouteConfig()
    route_config.whitelist_countries = ["US"]
    mock_request.state.route_config = route_config

    with patch.object(ip_security_check, "ip_ban_manager") as mock_ban_mgr:
        mock_ban_mgr.is_ip_banned = MagicMock(return_value=False)

        with patch(
            "guard_core.sync.core.checks.implementations.ip_security.log_activity"
        ):
            with patch(
                "guard_core.sync.core.checks.helpers.escalate_identity_violation",
                new=MagicMock(),
            ):
                result = ip_security_check.check(mock_request)
                assert result is not None
                assert result.status_code == 403


def test_unknown_client_identity_with_route_blacklist_not_blocked(
    ip_security_check: IpSecurityCheck, mock_request: Mock
) -> None:
    mock_request.state.client_ip = "unknown"
    route_config = RouteConfig()
    route_config.ip_blacklist = ["10.0.0.1"]
    mock_request.state.route_config = route_config

    with patch.object(ip_security_check, "ip_ban_manager") as mock_ban_mgr:
        mock_ban_mgr.is_ip_banned = MagicMock(return_value=False)

        result = ip_security_check.check(mock_request)
        assert result is None


def test_route_blacklist_match_ignores_an_unparseable_client_ip() -> None:
    from guard_core.sync.core.checks.implementations.ip_security import (
        _route_blacklist_matches,
    )

    route_config = RouteConfig()
    route_config.ip_blacklist = ["10.0.0.0/8"]

    assert _route_blacklist_matches(route_config, "unknown") is False
    assert _route_blacklist_matches(route_config, "10.1.2.3") is True
