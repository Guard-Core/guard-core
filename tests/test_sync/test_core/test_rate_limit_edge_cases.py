from typing import Any, cast
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck


@pytest.fixture
def security_config() -> SecurityConfig:
    config = SecurityConfig()
    config.passive_mode = False
    config.endpoint_rate_limits = {"/api/test": (5, 60)}
    return config


@pytest.fixture
def mock_middleware(security_config: SecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = security_config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=429))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.redis_handler = None
    middleware.rate_limit_handler = Mock()
    middleware.rate_limit_handler.check_rate_limit = MagicMock(return_value=None)
    return middleware


@pytest.fixture
def rate_limit_check(mock_middleware: Mock) -> RateLimitCheck:
    return RateLimitCheck(mock_middleware)


@pytest.fixture
def mock_request() -> Mock:
    request = Mock()
    request.state = Mock()
    request.state.client_ip = "1.2.3.4"
    request.state.route_config = None
    request.state.is_whitelisted = False
    request.url_path = "/api/test"
    request.state.guard_route_id = "app.api.test"
    return request


def test_apply_rate_limit_check_passive_mode(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    security_config.passive_mode = True

    rate_limit_check.middleware.rate_limit_handler.check_rate_limit = MagicMock(
        return_value=Mock(status_code=429)
    )

    result = rate_limit_check._apply_rate_limit_check(
        mock_request,
        "1.2.3.4",
        5,
        60,
        "test_event",
        {"reason": "test"},
    )
    assert result is None


def test_check_global_rate_limit_passive_mode(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    security_config.passive_mode = True

    mock_handler = Mock()
    mock_handler.check_rate_limit = MagicMock(return_value=Mock(status_code=429))
    cast(Any, rate_limit_check.middleware).rate_limit_handler = mock_handler

    result = rate_limit_check._check_global_rate_limit(mock_request, "1.2.3.4")
    assert result is None


def test_check_no_client_ip(
    rate_limit_check: RateLimitCheck, mock_request: Mock
) -> None:
    mock_request.state.client_ip = None

    result = rate_limit_check.check(mock_request)
    assert result is None


def test_check_global_rate_limit_not_exceeded(
    rate_limit_check: RateLimitCheck, mock_request: Mock
) -> None:
    mock_handler = Mock()
    mock_handler.check_rate_limit = MagicMock(return_value=None)
    cast(Any, rate_limit_check.middleware).rate_limit_handler = mock_handler

    result = rate_limit_check._check_global_rate_limit(mock_request, "1.2.3.4")
    assert result is None


def test_check_global_rate_limit_exceeded_active_mode(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    security_config.passive_mode = False

    response = Mock(status_code=429)
    mock_handler = Mock()
    mock_handler.check_rate_limit = MagicMock(return_value=response)
    cast(Any, rate_limit_check.middleware).rate_limit_handler = mock_handler

    result = rate_limit_check._check_global_rate_limit(mock_request, "1.2.3.4")
    assert result == response


def test_apply_rate_limit_check_active_mode_exceeded(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    security_config.passive_mode = False

    response = Mock(status_code=429)
    rate_limit_check.middleware.rate_limit_handler.check_rate_limit = MagicMock(
        return_value=response
    )

    result = rate_limit_check._apply_rate_limit_check(
        mock_request,
        "1.2.3.4",
        5,
        60,
        "test_event",
        {"reason": "test"},
    )
    assert result == response


def test_apply_rate_limit_check_not_exceeded(
    rate_limit_check: RateLimitCheck, mock_request: Mock
) -> None:
    rate_limit_check.middleware.rate_limit_handler.check_rate_limit = MagicMock(
        return_value=None
    )

    result = rate_limit_check._apply_rate_limit_check(
        mock_request,
        "1.2.3.4",
        5,
        60,
        "test_event",
        {"reason": "test"},
    )
    assert result is None


def test_check_geo_rate_limit_no_geo_handler(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    security_config.geo_ip_handler = None
    route_config = Mock()
    route_config.geo_rate_limits = {"US": (10, 60)}

    result = rate_limit_check._check_geo_rate_limit(
        mock_request, "1.2.3.4", route_config
    )
    assert result is None


def test_check_geo_rate_limit_country_match(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    geo_handler = Mock()
    geo_handler.get_country.return_value = "US"
    security_config.geo_ip_handler = geo_handler

    route_config = Mock()
    route_config.geo_rate_limits = {"US": (10, 60)}

    response = Mock(status_code=429)
    with patch.object(rate_limit_check, "_apply_rate_limit_check") as mock_apply:
        mock_apply.return_value = response
        result = rate_limit_check._check_geo_rate_limit(
            mock_request, "1.2.3.4", route_config
        )
        assert result == response
        mock_apply.assert_called_once()
        call_kwargs = mock_apply.call_args[1]
        assert call_kwargs["endpoint_path"] == "app.api.test"


def test_check_geo_rate_limit_wildcard_match(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    geo_handler = Mock()
    geo_handler.get_country.return_value = "FR"
    security_config.geo_ip_handler = geo_handler

    route_config = Mock()
    route_config.geo_rate_limits = {"US": (10, 60), "*": (5, 30)}

    response = Mock(status_code=429)
    with patch.object(rate_limit_check, "_apply_rate_limit_check") as mock_apply:
        mock_apply.return_value = response
        result = rate_limit_check._check_geo_rate_limit(
            mock_request, "1.2.3.4", route_config
        )
        assert result == response
        call_args = mock_apply.call_args
        assert call_args[0][2] == 5
        assert call_args[0][3] == 30
        assert call_args[1]["endpoint_path"] == "app.api.test"


def test_check_geo_rate_limit_no_match(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    geo_handler = Mock()
    geo_handler.get_country.return_value = "FR"
    security_config.geo_ip_handler = geo_handler

    route_config = Mock()
    route_config.geo_rate_limits = {"US": (10, 60)}

    result = rate_limit_check._check_geo_rate_limit(
        mock_request, "1.2.3.4", route_config
    )
    assert result is None


def test_check_geo_rate_limit_no_country(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    geo_handler = Mock()
    geo_handler.get_country.return_value = None
    security_config.geo_ip_handler = geo_handler

    route_config = Mock()
    route_config.geo_rate_limits = {"*": (5, 30)}

    response = Mock(status_code=429)
    with patch.object(rate_limit_check, "_apply_rate_limit_check") as mock_apply:
        mock_apply.return_value = response
        result = rate_limit_check._check_geo_rate_limit(
            mock_request, "1.2.3.4", route_config
        )
        assert result == response


def test_check_geo_rate_limit_exceeded_without_decorator_uses_event_bus(
    rate_limit_check: RateLimitCheck,
    mock_middleware: Mock,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    geo_handler = Mock()
    geo_handler.get_country.return_value = "US"
    security_config.geo_ip_handler = geo_handler
    mock_middleware.rate_limit_handler.check_rate_limit = MagicMock(
        return_value=Mock(status_code=429)
    )

    route_config = Mock()
    route_config.geo_rate_limits = {"US": (10, 60)}

    result = rate_limit_check._check_geo_rate_limit(
        mock_request, "1.2.3.4", route_config
    )

    assert result is not None
    mock_middleware.event_bus.send_middleware_event.assert_called_once()
    call_kwargs = mock_middleware.event_bus.send_middleware_event.call_args[1]
    assert call_kwargs["decorator_type"] == "geo_rate_limiting"
    assert call_kwargs["violation_type"] == "geo_rate_limit"
    assert call_kwargs["rate_limit"] == 10
    assert call_kwargs["window"] == 60


def test_check_geo_rate_limit_exceeded_with_decorator_uses_send_decorator_event(
    rate_limit_check: RateLimitCheck,
    mock_middleware: Mock,
    security_config: SecurityConfig,
) -> None:
    from guard_core.sync.core.routing.context import RoutingContext
    from guard_core.sync.core.routing.resolver import RouteConfigResolver
    from guard_core.sync.decorators.base import BaseSecurityDecorator
    from tests.test_sync.conftest import SyncMockGuardRequest

    geo_handler = Mock()
    geo_handler.get_country.return_value = "US"
    security_config.geo_ip_handler = geo_handler
    mock_middleware.rate_limit_handler.check_rate_limit = MagicMock(
        return_value=Mock(status_code=429)
    )

    decorator = BaseSecurityDecorator(security_config)
    recording_agent = MagicMock()
    decorator.initialize_agent(recording_agent)
    mock_middleware.route_resolver = RouteConfigResolver(
        RoutingContext(config=security_config, logger=Mock(), guard_decorator=decorator)
    )

    route_config = Mock()
    route_config.geo_rate_limits = {"US": (10, 60)}
    request = SyncMockGuardRequest(client_host="1.2.3.4")

    result = rate_limit_check._check_geo_rate_limit(request, "1.2.3.4", route_config)

    assert result is not None
    mock_middleware.event_bus.send_middleware_event.assert_not_called()
    recording_agent.send_event.assert_called_once()
    event = recording_agent.send_event.call_args[0][0]
    assert event.event_type == "decorator_violation"
    assert event.decorator_type == "geo_rate_limiting"
    assert event.metadata["violation_type"] == "geo_rate_limit"
    assert event.metadata["rate_limit"] == 10
    assert event.metadata["window"] == 60


def test_check_returns_geo_rate_limit_response(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    route_config = Mock()
    route_config.geo_rate_limits = {"US": (10, 60)}
    route_config.rate_limit = None
    mock_request.state.route_config = route_config
    mock_request.state.is_whitelisted = False

    security_config.endpoint_rate_limits = {}

    geo_response = Mock(status_code=429)
    with patch.object(rate_limit_check, "_check_geo_rate_limit") as mock_geo:
        mock_geo.return_value = geo_response
        result = rate_limit_check.check(mock_request)
        assert result == geo_response


def test_apply_rate_limit_passes_endpoint_path(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
) -> None:
    rate_limit_check.middleware.rate_limit_handler.check_rate_limit = MagicMock(
        return_value=None
    )

    rate_limit_check._apply_rate_limit_check(
        mock_request,
        "1.2.3.4",
        5,
        60,
        "test_event",
        {"reason": "test"},
        endpoint_path="/api/test",
    )

    call_kwargs = (
        rate_limit_check.middleware.rate_limit_handler.check_rate_limit.call_args[1]
    )
    assert call_kwargs["endpoint_path"] == "/api/test"
    assert call_kwargs["rate_limit"] == 5
    assert call_kwargs["rate_limit_window"] == 60


def test_endpoint_rate_limit_passes_path(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    security_config.endpoint_rate_limits = {"/api/test": (5, 60)}

    with patch.object(rate_limit_check, "_apply_rate_limit_check") as mock_apply:
        mock_apply.return_value = None
        rate_limit_check._check_endpoint_rate_limit(
            mock_request, "1.2.3.4", "/api/test"
        )
        call_kwargs = mock_apply.call_args[1]
        assert call_kwargs["endpoint_path"] == "/api/test"


def test_endpoint_rate_limit_redacts_sensitive_endpoint_path(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    secret_path = "/resource;token=super-secret-value"
    security_config.endpoint_rate_limits = {secret_path: (5, 60)}
    security_config.log_sensitive_params = frozenset({"token"})

    with patch.object(rate_limit_check, "_apply_rate_limit_check") as mock_apply:
        mock_apply.return_value = None
        rate_limit_check._check_endpoint_rate_limit(
            mock_request, "1.2.3.4", secret_path
        )
        call_args, call_kwargs = mock_apply.call_args
        event_kwargs = call_args[5]
        assert "super-secret-value" not in event_kwargs["reason"]
        assert "super-secret-value" not in event_kwargs["endpoint"]
        assert call_kwargs["endpoint_path"] == secret_path


def test_route_rate_limit_passes_path(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
) -> None:
    route_config = Mock()
    route_config.rate_limit = 10
    route_config.rate_limit_window = 30

    with patch.object(rate_limit_check, "_apply_rate_limit_check") as mock_apply:
        mock_apply.return_value = None
        rate_limit_check._check_route_rate_limit(mock_request, "1.2.3.4", route_config)
        call_kwargs = mock_apply.call_args[1]
        assert call_kwargs["endpoint_path"] == "app.api.test"


def test_global_rate_limit_passes_its_own_config_and_no_endpoint_path(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    mock_handler = Mock()
    mock_handler.check_rate_limit = MagicMock(return_value=None)
    cast(Any, rate_limit_check.middleware).rate_limit_handler = mock_handler

    rate_limit_check._check_global_rate_limit(mock_request, "1.2.3.4")

    mock_handler.check_rate_limit.assert_called_once_with(
        mock_request,
        "1.2.3.4",
        rate_limit_check.middleware.create_error_response,
        rate_limit=security_config.rate_limit,
        rate_limit_window=security_config.rate_limit_window,
        config=security_config,
    )
    call_kwargs = mock_handler.check_rate_limit.call_args[1]
    assert "endpoint_path" not in call_kwargs


def test_initialize_redis_noop_when_redis_disabled() -> None:
    from guard_core.models import SecurityConfig
    from guard_core.sync.handlers.ratelimit_handler import RateLimitManager

    config = SecurityConfig(enable_redis=False)
    manager = RateLimitManager(config)
    redis_handler = MagicMock()
    manager.initialize_redis(redis_handler)
    assert manager.redis_handler is redis_handler
    # script_sha not loaded because enable_redis was False.


def test_reset_noop_when_redis_keys_missing() -> None:
    from guard_core.models import SecurityConfig
    from guard_core.sync.handlers.ratelimit_handler import RateLimitManager

    manager = RateLimitManager(SecurityConfig(enable_redis=True))
    manager.redis_handler = MagicMock()
    manager.redis_handler.keys = MagicMock(return_value=[])
    manager.reset()
