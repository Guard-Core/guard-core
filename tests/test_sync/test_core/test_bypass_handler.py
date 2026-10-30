from collections.abc import Callable
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.bypass import handler as bypass_handler_module
from guard_core.sync.core.bypass.context import BypassContext
from guard_core.sync.core.bypass.handler import BypassHandler
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


@pytest.fixture(autouse=True)
def _reset_no_client_address_warning() -> None:
    bypass_handler_module._no_client_address_warned = False


@pytest.fixture
def mock_response_factory() -> Mock:
    factory = Mock()
    factory.apply_modifier = MagicMock(return_value=Mock(status_code=200))
    factory.apply_security_headers = MagicMock(
        side_effect=lambda response, path=None: response
    )
    factory.create_error_response = MagicMock(return_value=Mock(status_code=403))
    return factory


@pytest.fixture
def mock_validator() -> Mock:
    validator = Mock()
    validator.is_path_excluded = MagicMock(return_value=False)
    return validator


@pytest.fixture
def mock_route_resolver() -> Mock:
    resolver = Mock()
    resolver.should_bypass_check = Mock(return_value=False)
    return resolver


@pytest.fixture
def mock_event_bus() -> Mock:
    event_bus = Mock()
    event_bus.send_middleware_event = MagicMock()
    return event_bus


@pytest.fixture
def mock_config() -> Mock:
    config = Mock()
    config.passive_mode = False
    config.emergency_mode = False
    config.fail_secure = True
    config.trusted_proxies = ()
    config.trusted_proxy_depth = 1
    config.log_sensitive_params = frozenset()
    config.log_sensitive_body_fields = frozenset()
    config.log_sensitive_headers = frozenset()
    return config


@pytest.fixture
def bypass_context(
    mock_config: Mock,
    mock_response_factory: Mock,
    mock_validator: Mock,
    mock_route_resolver: Mock,
    mock_event_bus: Mock,
) -> BypassContext:
    return BypassContext(
        config=mock_config,
        logger=Mock(),
        response_factory=mock_response_factory,
        validator=mock_validator,
        route_resolver=mock_route_resolver,
        event_bus=mock_event_bus,
    )


@pytest.fixture
def bypass_handler(bypass_context: BypassContext) -> BypassHandler:
    return BypassHandler(bypass_context)


@pytest.fixture
def mock_request() -> Mock:
    request = Mock()
    request.url_path = "/test"
    request.client_host = "127.0.0.1"
    request.headers = {}
    request.state = SimpleNamespace()
    return request


@pytest.fixture
def call_next() -> Callable[[Mock], Mock]:
    def _call_next(request: Mock) -> Mock:
        return Mock(status_code=200)

    return _call_next


def test_init(bypass_context: BypassContext) -> None:
    handler = BypassHandler(bypass_context)
    assert handler.context == bypass_context


def test_handle_passthrough_no_client_fail_secure_rejects(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_response_factory: Mock,
) -> None:
    mock_request.client_host = None

    response = bypass_handler.handle_passthrough(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
    )

    assert response is not None
    assert response.status_code == 403
    assert mock_request.state.client_ip == "unknown"
    mock_response_factory.create_error_response.assert_called_once_with(
        403, "Client address could not be determined"
    )


def test_handle_passthrough_no_client_fail_open_runs_pipeline_as_unknown(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_response_factory: Mock,
    mock_config: Mock,
) -> None:
    mock_config.fail_secure = False
    mock_request.client_host = None

    response = bypass_handler.handle_passthrough(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
    )

    assert response is None
    assert mock_request.state.client_ip == "unknown"
    mock_response_factory.create_error_response.assert_not_called()


def test_handle_passthrough_no_client_resolves_via_unix_trusted_proxy(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_response_factory: Mock,
    mock_config: Mock,
) -> None:
    mock_config.trusted_proxies = ("unix",)
    mock_request.client_host = None
    mock_request.headers = {"X-Forwarded-For": "9.9.9.9"}

    response = bypass_handler.handle_passthrough(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
    )

    assert response is None
    assert mock_request.state.client_ip == "9.9.9.9"
    mock_response_factory.create_error_response.assert_not_called()


def test_handle_passthrough_no_client_warns_once(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    bypass_context: BypassContext,
) -> None:
    mock_request.client_host = None
    another_request = Mock()
    another_request.client_host = None
    another_request.headers = {}
    another_request.state = SimpleNamespace()
    another_request.url_path = "/test"

    bypass_handler.handle_passthrough(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
    )
    bypass_handler.handle_passthrough(
        another_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
    )

    assert cast(Mock, bypass_context.logger).warning.call_count == 1


def test_fail_open_warning_says_peerless_clients_share_one_bucket(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    bypass_context: BypassContext,
    mock_config: Mock,
) -> None:
    mock_config.fail_secure = False
    mock_request.client_host = None

    bypass_handler.handle_passthrough(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
    )

    warning = cast(Mock, bypass_context.logger).warning.call_args
    message = warning.args[0] % warning.args[1:]
    assert "share one rate-limit bucket" in message
    assert 'add "unix" to trusted_proxies' in message


def test_fail_secure_warning_does_not_mention_the_bucket(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    bypass_context: BypassContext,
) -> None:
    mock_request.client_host = None

    bypass_handler.handle_passthrough(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
    )

    warning = cast(Mock, bypass_context.logger).warning.call_args
    assert "bucket" not in warning.args[0] % warning.args[1:]


def test_handle_passthrough_excluded_path_no_client_skips_warning(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_validator: Mock,
    mock_response_factory: Mock,
    bypass_context: BypassContext,
) -> None:
    mock_validator.is_path_excluded.return_value = True
    mock_request.client_host = None

    response = bypass_handler.handle_passthrough(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
    )

    assert response is None
    assert mock_request.state.guard_exclusion_scoped is True
    assert not hasattr(mock_request.state, "client_ip")
    mock_response_factory.create_error_response.assert_not_called()
    cast(Mock, bypass_context.logger).warning.assert_not_called()


def test_handle_passthrough_excluded_path_falls_through_marked_exclusion_scoped(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_validator: Mock,
    mock_response_factory: Mock,
) -> None:
    mock_validator.is_path_excluded.return_value = True

    response = bypass_handler.handle_passthrough(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
    )

    assert response is None
    assert mock_request.state.guard_exclusion_scoped is True
    mock_validator.is_path_excluded.assert_called_once_with(mock_request)
    mock_response_factory.apply_modifier.assert_not_called()


def test_handle_passthrough_non_excluded_path_does_not_mark_request(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_validator: Mock,
) -> None:
    mock_validator.is_path_excluded.return_value = False

    response = bypass_handler.handle_passthrough(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
    )

    assert response is None
    assert not hasattr(mock_request.state, "guard_exclusion_scoped")


def test_handle_passthrough_no_bypass(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_validator: Mock,
) -> None:
    mock_validator.is_path_excluded.return_value = False

    response = bypass_handler.handle_passthrough(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
    )

    assert response is None
    mock_validator.is_path_excluded.assert_called_once_with(mock_request)


def test_handle_security_bypass_no_route_config(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
) -> None:
    response = bypass_handler.handle_security_bypass(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
        None,
    )

    assert response is None


def test_handle_security_bypass_should_not_bypass(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_route_resolver: Mock,
) -> None:
    route_config = RouteConfig()
    route_config.bypassed_checks = {"ip_check"}
    mock_route_resolver.should_bypass_check.return_value = False

    response = bypass_handler.handle_security_bypass(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
        route_config,
    )

    assert response is None
    mock_route_resolver.should_bypass_check.assert_called_once_with("all", route_config)


def test_handle_security_bypass_active_mode(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_route_resolver: Mock,
    mock_event_bus: Mock,
    mock_response_factory: Mock,
    bypass_context: BypassContext,
) -> None:
    route_config = RouteConfig()
    route_config.bypassed_checks = {"all"}
    mock_route_resolver.should_bypass_check.return_value = True
    bypass_context.config.passive_mode = False

    response = bypass_handler.handle_security_bypass(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
        route_config,
    )

    assert response is not None
    assert response.status_code == 200
    mock_event_bus.send_middleware_event.assert_called_once()
    call_args = mock_event_bus.send_middleware_event.call_args[1]
    assert call_args["event_type"] == "security_bypass"
    assert call_args["action_taken"] == "all_checks_bypassed"
    assert call_args["endpoint"] == "/test"
    mock_response_factory.apply_security_headers.assert_called_once()
    mock_response_factory.apply_modifier.assert_called_once()


def test_handle_security_bypass_passive_mode(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_route_resolver: Mock,
    mock_event_bus: Mock,
    mock_response_factory: Mock,
    bypass_context: BypassContext,
) -> None:
    route_config = RouteConfig()
    route_config.bypassed_checks = {"all"}
    mock_route_resolver.should_bypass_check.return_value = True
    bypass_context.config.passive_mode = True

    response = bypass_handler.handle_security_bypass(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
        route_config,
    )

    assert response is not None
    assert response.status_code == 200
    mock_event_bus.send_middleware_event.assert_called_once()
    mock_response_factory.apply_security_headers.assert_called_once()
    mock_response_factory.apply_modifier.assert_called_once()


def test_handle_security_bypass_with_multiple_bypassed_checks(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_route_resolver: Mock,
    mock_event_bus: Mock,
    bypass_context: BypassContext,
) -> None:
    route_config = RouteConfig()
    route_config.bypassed_checks = {"ip_check", "rate_limit", "https_check"}
    mock_route_resolver.should_bypass_check.return_value = True
    bypass_context.config.passive_mode = False

    response = bypass_handler.handle_security_bypass(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
        route_config,
    )

    assert response is not None
    mock_event_bus.send_middleware_event.assert_called_once()
    call_args = mock_event_bus.send_middleware_event.call_args[1]
    assert set(call_args["bypassed_checks"]) == {
        "ip_check",
        "rate_limit",
        "https_check",
    }
