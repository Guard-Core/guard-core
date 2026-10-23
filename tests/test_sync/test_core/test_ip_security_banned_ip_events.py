from typing import Any, cast
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.ip_security import IpSecurityCheck


@pytest.fixture
def security_config() -> SyncSecurityConfig:
    config = SyncSecurityConfig()
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


@pytest.fixture
def mock_request() -> Mock:
    request = Mock()
    request.state = Mock()
    request.state.client_ip = "1.2.3.4"
    request.state.route_config = None
    return request


def test_banned_ip_block_emits_ip_blocked_event(
    ip_security_check: IpSecurityCheck, mock_request: Mock
) -> None:
    with (
        patch.object(ip_security_check, "ip_ban_manager") as mock_ban_mgr,
        patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"),
    ):
        mock_ban_mgr.is_ip_banned = MagicMock(return_value=True)
        result = ip_security_check.check(mock_request)

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.call_args
    assert event_call.kwargs["event_type"] == "ip_blocked"
    assert event_call.kwargs["filter_type"] == "banned"
    assert event_call.kwargs["ip_address"] == "1.2.3.4"
    assert event_call.kwargs["action_taken"] == "request_blocked"


def test_banned_ip_in_passive_mode_emits_logged_only_event(
    ip_security_check: IpSecurityCheck,
    mock_request: Mock,
    security_config: SyncSecurityConfig,
) -> None:
    security_config.passive_mode = True
    with (
        patch.object(ip_security_check, "ip_ban_manager") as mock_ban_mgr,
        patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"),
    ):
        mock_ban_mgr.is_ip_banned = MagicMock(return_value=True)
        ip_security_check._check_banned_ip(mock_request, "1.2.3.4", None)

    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.call_args
    assert event_call.kwargs["action_taken"] == "logged_only"
