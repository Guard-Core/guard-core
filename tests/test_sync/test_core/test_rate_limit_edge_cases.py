from typing import cast
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.handlers.ratelimit_handler import RateLimitBlock, RateLimitTier


@pytest.fixture
def security_config() -> SyncSecurityConfig:
    config = SyncSecurityConfig()
    config.passive_mode = False
    config.endpoint_rate_limits = {"/api/test": (5, 60)}
    return config


@pytest.fixture
def mock_middleware(security_config: SyncSecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = security_config
    middleware.resolve_route = None
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=429))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.redis_handler = None
    middleware.rate_limit_handler = Mock()
    middleware.rate_limit_handler.report_rate_limit_block = MagicMock()
    middleware.rate_limit_handler.check_rate_limit_tiers = MagicMock(return_value=None)
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
    return request


def _block(tier_index: int = 0, count: int = 6) -> RateLimitBlock:
    return RateLimitBlock(tier_index, count, Mock(status_code=429))


def _tiers_handler(rate_limit_check: RateLimitCheck) -> MagicMock:
    handler = rate_limit_check.middleware.rate_limit_handler.check_rate_limit_tiers
    return cast(MagicMock, handler)


def test_check_passive_mode_never_returns_the_block(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SyncSecurityConfig,
) -> None:
    security_config.passive_mode = True
    _tiers_handler(rate_limit_check).return_value = _block()

    assert rate_limit_check.check(mock_request) is None


def test_check_returns_the_block_response_in_active_mode(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SyncSecurityConfig,
) -> None:
    security_config.passive_mode = False
    block = _block()
    _tiers_handler(rate_limit_check).return_value = block

    assert rate_limit_check.check(mock_request) is block.response


def test_check_no_client_ip(
    rate_limit_check: RateLimitCheck, mock_request: Mock
) -> None:
    mock_request.state.client_ip = None

    result = rate_limit_check.check(mock_request)
    assert result is None


def test_check_not_exceeded_returns_none(
    rate_limit_check: RateLimitCheck, mock_request: Mock
) -> None:
    _tiers_handler(rate_limit_check).return_value = None

    assert rate_limit_check.check(mock_request) is None


def test_check_passes_every_tier_in_one_call_with_its_own_config(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SyncSecurityConfig,
) -> None:
    mock_request.state.route_config = Mock(
        rate_limit=7, rate_limit_window=30, geo_rate_limits=None
    )
    handler = _tiers_handler(rate_limit_check)

    rate_limit_check.check(mock_request)

    handler.assert_called_once()
    args, kwargs = handler.call_args
    assert args[0] is mock_request
    assert args[1] == "1.2.3.4"
    assert args[2] is rate_limit_check.middleware.create_error_response
    assert args[3] == [
        RateLimitTier("endpoint", 5, 60, "/api/test"),
        RateLimitTier("route", 7, 30, "/api/test"),
        RateLimitTier(
            "global", security_config.rate_limit, security_config.rate_limit_window
        ),
    ]
    assert kwargs == {"config": security_config, "window_identity": "1.2.3.4"}


def test_the_old_whitelist_value_passes_no_window_identity(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SyncSecurityConfig,
) -> None:
    security_config.whitelist_access_only = False
    mock_request.state.route_config = Mock(
        rate_limit=7, rate_limit_window=30, geo_rate_limits=None
    )
    handler = _tiers_handler(rate_limit_check)

    rate_limit_check.check(mock_request)

    assert handler.call_args.kwargs == {"config": security_config}


def test_the_global_tier_is_left_out_when_rate_limiting_is_off(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SyncSecurityConfig,
) -> None:
    security_config.enable_rate_limiting = False
    handler = _tiers_handler(rate_limit_check)

    rate_limit_check.check(mock_request)

    assert [tier.kind for tier in handler.call_args[0][3]] == ["endpoint"]


def test_check_does_nothing_without_any_tier(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SyncSecurityConfig,
) -> None:
    security_config.enable_rate_limiting = False
    security_config.endpoint_rate_limits = {}
    handler = _tiers_handler(rate_limit_check)

    assert rate_limit_check.check(mock_request) is None
    handler.assert_not_called()


def test_geo_plan_without_a_geo_handler_is_none(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
) -> None:
    cast(Mock, rate_limit_check.middleware).geo_ip_handler = None
    route_config = Mock()
    route_config.geo_rate_limits = {"US": (10, 60)}

    assert rate_limit_check._geo_plan(mock_request, "1.2.3.4", route_config) is None


def test_geo_plan_country_match(
    rate_limit_check: RateLimitCheck, mock_request: Mock
) -> None:
    geo_handler = Mock()
    geo_handler.get_country.return_value = "US"
    cast(Mock, rate_limit_check.middleware).geo_ip_handler = geo_handler
    route_config = Mock()
    route_config.geo_rate_limits = {"US": (10, 60)}

    plan = rate_limit_check._geo_plan(mock_request, "1.2.3.4", route_config)

    assert plan is not None
    assert plan.tier == RateLimitTier("geo", 10, 60, "/api/test")


def test_geo_plan_wildcard_match(
    rate_limit_check: RateLimitCheck, mock_request: Mock
) -> None:
    geo_handler = Mock()
    geo_handler.get_country.return_value = "FR"
    cast(Mock, rate_limit_check.middleware).geo_ip_handler = geo_handler
    route_config = Mock()
    route_config.geo_rate_limits = {"US": (10, 60), "*": (5, 30)}

    plan = rate_limit_check._geo_plan(mock_request, "1.2.3.4", route_config)

    assert plan is not None
    assert plan.tier == RateLimitTier("geo", 5, 30, "/api/test")


def test_geo_plan_no_match(
    rate_limit_check: RateLimitCheck, mock_request: Mock
) -> None:
    geo_handler = Mock()
    geo_handler.get_country.return_value = "FR"
    cast(Mock, rate_limit_check.middleware).geo_ip_handler = geo_handler
    route_config = Mock()
    route_config.geo_rate_limits = {"US": (10, 60)}

    assert rate_limit_check._geo_plan(mock_request, "1.2.3.4", route_config) is None


def test_geo_plan_no_country_uses_the_wildcard(
    rate_limit_check: RateLimitCheck, mock_request: Mock
) -> None:
    geo_handler = Mock()
    geo_handler.get_country.return_value = None
    cast(Mock, rate_limit_check.middleware).geo_ip_handler = geo_handler
    route_config = Mock()
    route_config.geo_rate_limits = {"*": (5, 30)}

    plan = rate_limit_check._geo_plan(mock_request, "1.2.3.4", route_config)

    assert plan is not None
    assert plan.tier == RateLimitTier("geo", 5, 30, "/api/test")
    assert "unknown" in str(plan.event_kwargs["reason"])


def test_geo_block_without_decorator_uses_event_bus(
    rate_limit_check: RateLimitCheck,
    mock_middleware: Mock,
    mock_request: Mock,
) -> None:
    geo_handler = Mock()
    geo_handler.get_country.return_value = "US"
    cast(Mock, rate_limit_check.middleware).geo_ip_handler = geo_handler
    route_config = Mock()
    route_config.geo_rate_limits = {"US": (10, 60)}
    route_config.rate_limit = None
    mock_request.state.route_config = route_config
    mock_middleware.config.endpoint_rate_limits = {}
    mock_middleware.rate_limit_handler.report_rate_limit_block = MagicMock()
    mock_middleware.rate_limit_handler.check_rate_limit_tiers = MagicMock(
        return_value=_block()
    )

    result = rate_limit_check.check(mock_request)

    assert result is not None
    mock_middleware.event_bus.send_middleware_event.assert_called_once()
    call_kwargs = mock_middleware.event_bus.send_middleware_event.call_args[1]
    assert call_kwargs["decorator_type"] == "geo_rate_limiting"
    assert call_kwargs["violation_type"] == "geo_rate_limit"
    assert call_kwargs["rate_limit"] == 10
    assert call_kwargs["window"] == 60


def test_geo_block_with_decorator_uses_send_decorator_event(
    rate_limit_check: RateLimitCheck,
    mock_middleware: Mock,
    security_config: SyncSecurityConfig,
) -> None:
    from guard_core.sync.core.routing.context import RoutingContext
    from guard_core.sync.core.routing.resolver import RouteConfigResolver
    from guard_core.sync.decorators.base import BaseSecurityDecorator
    from tests.test_sync.conftest import SyncMockGuardRequest

    geo_handler = Mock()
    geo_handler.get_country.return_value = "US"
    cast(Mock, rate_limit_check.middleware).geo_ip_handler = geo_handler
    mock_middleware.rate_limit_handler.report_rate_limit_block = MagicMock()
    mock_middleware.rate_limit_handler.check_rate_limit_tiers = MagicMock(
        return_value=_block()
    )
    security_config.endpoint_rate_limits = {}

    decorator = BaseSecurityDecorator(security_config)
    recording_agent = MagicMock()
    decorator.initialize_agent(recording_agent)
    mock_middleware.route_resolver = RouteConfigResolver(
        RoutingContext(config=security_config, logger=Mock(), guard_decorator=decorator)
    )

    route_config = Mock()
    route_config.geo_rate_limits = {"US": (10, 60)}
    route_config.rate_limit = None
    route_config.bypassed_checks = set()
    request = SyncMockGuardRequest(client_host="1.2.3.4")
    request.state.client_ip = "1.2.3.4"
    request.state.route_config = route_config
    request.state.is_whitelisted = False

    result = rate_limit_check.check(request)

    assert result is not None
    mock_middleware.event_bus.send_middleware_event.assert_not_called()
    recording_agent.send_event.assert_called_once()
    event = recording_agent.send_event.call_args[0][0]
    assert event.event_type == "decorator_violation"
    assert event.decorator_type == "geo_rate_limiting"
    assert event.metadata["violation_type"] == "geo_rate_limit"
    assert event.metadata["rate_limit"] == 10
    assert event.metadata["window"] == 60


def test_endpoint_plan_passes_the_path(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SyncSecurityConfig,
) -> None:
    security_config.endpoint_rate_limits = {"/api/test": (5, 60)}

    (plan,) = rate_limit_check._endpoint_plans(mock_request)

    assert plan.tier == RateLimitTier("endpoint", 5, 60, "/api/test")


def test_endpoint_plan_redacts_sensitive_endpoint_path(
    rate_limit_check: RateLimitCheck,
    mock_request: Mock,
    security_config: SyncSecurityConfig,
) -> None:
    secret_path = "/resource;token=super-secret-value"
    security_config.endpoint_rate_limits = {secret_path: (5, 60)}
    security_config.log_sensitive_params = frozenset({"token"})
    mock_request.url_path = secret_path

    (plan,) = rate_limit_check._endpoint_plans(mock_request)

    assert "super-secret-value" not in plan.event_kwargs["reason"]
    assert "super-secret-value" not in plan.event_kwargs["endpoint"]
    assert "super-secret-value" not in plan.trigger_info
    assert plan.tier.bucket == secret_path


def test_route_plan_passes_the_path(
    rate_limit_check: RateLimitCheck, mock_request: Mock
) -> None:
    route_config = Mock()
    route_config.rate_limit = 10
    route_config.rate_limit_window = 30

    plan = rate_limit_check._route_plan(mock_request, route_config)

    assert plan is not None
    assert plan.tier == RateLimitTier("route", 10, 30, "/api/test")


def test_global_plan_carries_its_own_config_and_no_bucket(
    rate_limit_check: RateLimitCheck, security_config: SyncSecurityConfig
) -> None:
    plan = rate_limit_check._global_plan()

    assert plan is not None
    assert plan.tier == RateLimitTier(
        "global", security_config.rate_limit, security_config.rate_limit_window
    )
    assert plan.event_type is None


def test_initialize_redis_noop_when_redis_disabled() -> None:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.handlers.ratelimit_handler import RateLimitManager

    config = SyncSecurityConfig(enable_redis=False)
    manager = RateLimitManager(config)
    redis_handler = MagicMock()
    manager.initialize_redis(redis_handler)
    assert manager.redis_handler is redis_handler
    # script_sha not loaded because enable_redis was False.


def test_reset_noop_when_redis_keys_missing() -> None:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.handlers.ratelimit_handler import RateLimitManager

    manager = RateLimitManager(SyncSecurityConfig(enable_redis=True))
    manager.redis_handler = MagicMock()
    manager.redis_handler.keys = MagicMock(return_value=[])
    manager.reset()
