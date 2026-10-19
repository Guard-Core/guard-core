from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from guard_core.core.checks.implementations import rate_limit as rate_limit_module
from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.decorators.base import RouteConfig
from guard_core.handlers.ratelimit_handler import RateLimitBlock
from guard_core.models import SecurityConfig

CLIENT_IP = "198.51.100.40"


def _middleware(config: SecurityConfig, country: str | None = None) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.guard_decorator = None
    middleware.resolve_route = None
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=429))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.geo_ip_handler = Mock()
    middleware.geo_ip_handler.get_country = Mock(return_value=country)
    middleware.suspicious_request_counts = {}
    middleware.rate_limit_handler = Mock(redis_handler=None)
    middleware.rate_limit_handler.report_rate_limit_block = AsyncMock()
    middleware.rate_limit_handler.check_rate_limit_tiers = AsyncMock(
        return_value=RateLimitBlock(0, 2, Mock(status_code=429))
    )
    return middleware


def _request(route_config: RouteConfig | None = None) -> MagicMock:
    request = MagicMock()
    request.state.client_ip = CLIENT_IP
    request.state.route_config = route_config
    request.state.is_whitelisted = False
    request.state.is_exempt = False
    request.state.guard_route_identity = None
    request.state.guard_route_id = "app.limited"
    request.url_path = "/api/test"
    request.method = "GET"
    request.url_full = "https://test/api/test"
    request.headers = {}
    request.query_params = {}
    return request


def _config(**settings: Any) -> SecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_rate_limiting": False,
    }
    return SecurityConfig(**{**defaults, **settings})


async def _blocked_event(
    config: SecurityConfig,
    route_config: RouteConfig | None = None,
    country: str | None = None,
) -> dict[str, Any]:
    middleware = _middleware(config, country)
    await RateLimitCheck(middleware).check(_request(route_config))
    middleware.event_bus.send_middleware_event.assert_awaited_once()
    return dict(middleware.event_bus.send_middleware_event.await_args.kwargs)


async def test_an_endpoint_block_sends_the_dynamic_rule_violation_payload() -> None:
    event = await _blocked_event(_config(endpoint_rate_limits={"/api/test": (1, 20)}))

    assert event["event_type"] == "dynamic_rule_violation"
    assert event["action_taken"] == "request_blocked"
    assert event["reason"] == (
        "Endpoint-specific rate limit exceeded: 1 requests per 20s for /api/test"
    )
    assert event["rule_type"] == "endpoint_rate_limit"
    assert event["endpoint"] == "/api/test"
    assert event["rate_limit"] == 1
    assert event["window"] == 20


async def test_a_passive_endpoint_block_is_logged_only() -> None:
    event = await _blocked_event(
        _config(endpoint_rate_limits={"/api/test": (1, 20)}, passive_mode=True)
    )

    assert event["action_taken"] == "logged_only"


async def test_a_route_block_sends_the_rate_limiting_decorator_payload() -> None:
    route_config = RouteConfig()
    route_config.rate_limit = 5
    event = await _blocked_event(_config(), route_config)

    assert event["event_type"] == "decorator_violation"
    assert event["action_taken"] == "request_blocked"
    assert event["reason"] == "Route-specific rate limit exceeded: 5 requests per 60s"
    assert event["decorator_type"] == "rate_limiting"
    assert event["violation_type"] == "rate_limit"
    assert event["rate_limit"] == 5
    assert event["window"] == 60


async def test_a_passive_route_block_is_logged_only() -> None:
    route_config = RouteConfig()
    route_config.rate_limit = 5
    route_config.rate_limit_window = 30
    event = await _blocked_event(_config(passive_mode=True), route_config)

    assert event["action_taken"] == "logged_only"
    assert event["window"] == 30


async def test_a_geo_block_sends_the_geo_decorator_payload() -> None:
    route_config = RouteConfig()
    route_config.geo_rate_limits = {"US": (3, 45)}
    event = await _blocked_event(_config(), route_config, country="US")

    assert event["event_type"] == "decorator_violation"
    assert event["action_taken"] == "request_blocked"
    assert event["reason"] == "Geo rate limit exceeded for US: 3 requests per 45s"
    assert event["decorator_type"] == "geo_rate_limiting"
    assert event["violation_type"] == "geo_rate_limit"
    assert event["rate_limit"] == 3
    assert event["window"] == 45


async def test_a_geo_block_without_a_country_names_it_unknown() -> None:
    route_config = RouteConfig()
    route_config.geo_rate_limits = {"*": (2, 30)}
    event = await _blocked_event(_config(), route_config, country=None)

    assert event["reason"] == "Geo rate limit exceeded for unknown: 2 requests per 30s"


async def test_a_passive_geo_block_is_logged_only() -> None:
    route_config = RouteConfig()
    route_config.geo_rate_limits = {"US": (3, 45)}
    event = await _blocked_event(_config(passive_mode=True), route_config, country="US")

    assert event["action_taken"] == "logged_only"


async def test_a_global_block_names_the_global_limit_in_the_ban_log() -> None:
    config = _config(
        enable_rate_limiting=True,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
    )
    middleware = _middleware(config)
    check = RateLimitCheck(middleware)
    check.ip_ban_manager = Mock()
    check.ip_ban_manager._ban_ip_escalating = AsyncMock(return_value=3600)

    await check.check(_request())

    (call,) = middleware.logger.warning.call_args_list
    assert (
        "IP banned due to suspicious activity: 198.51.100.40 - "
        "Global rate limit exceeded (ban duration 3600s) - Headers: {}"
    ) in call.args[0]


async def test_a_failing_auto_ban_is_logged_with_the_client_ip() -> None:
    config = _config(
        enable_rate_limiting=True,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
    )
    middleware = _middleware(config)
    check = RateLimitCheck(middleware)

    with patch.object(
        rate_limit_module, "_try_threshold_ban", AsyncMock(side_effect=RuntimeError)
    ):
        await check.check(_request())

    middleware.logger.exception.assert_called_once_with(
        "rate-limit auto-ban failed for %s", CLIENT_IP
    )


async def test_an_unavailable_shared_counter_is_logged_and_counted_locally() -> None:
    config = _config(
        enable_rate_limiting=True,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        enable_redis=True,
        redis_url="redis://localhost:1",
    )
    middleware = _middleware(config)
    middleware.rate_limit_handler.redis_handler = Mock()
    check = RateLimitCheck(middleware)
    check.ip_ban_manager = Mock()
    check.ip_ban_manager._ban_ip_escalating = AsyncMock(return_value=3600)

    with patch.object(
        rate_limit_module,
        "record_shared_violation",
        AsyncMock(side_effect=RuntimeError("redis down")),
    ):
        await check.check(_request())

    (call,) = middleware.logger.warning.call_args_list
    assert call.args[0] == (
        "Shared rate-limit violation counter unavailable, counting this "
        "violation in this process only: %s"
    )
    assert str(call.args[1]) == "redis down"
    assert middleware.suspicious_request_counts[CLIENT_IP]["rate_limit"] == 1


async def test_the_non_ip_refusal_warning_names_the_identity_and_the_fix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rate_limit_module, "_non_ip_ban_refusal_logged", False)
    config = _config(
        enable_rate_limiting=True,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
    )
    middleware = _middleware(config)
    request = _request()
    request.state.client_ip = "unknown"

    await RateLimitCheck(middleware).check(request)

    (call,) = middleware.logger.warning.call_args_list
    message = call.args[0] % call.args[1:]
    assert message == (
        "Not auto-banning 'unknown': it is not an IP address, so every client with "
        "this identity shares one rate-limit counter and cannot be banned. If "
        'the app is served over a Unix socket add "unix" to trusted_proxies. '
        "This is logged once."
    )


async def test_a_request_without_whitelist_or_exempt_flags_is_rate_limited() -> None:
    middleware = _middleware(_config(enable_rate_limiting=True))
    request = _request()
    request.state = Mock(spec=["client_ip", "route_config", "guard_route_identity"])
    request.state.client_ip = CLIENT_IP
    request.state.route_config = None
    request.state.guard_route_identity = None

    response = await RateLimitCheck(middleware).check(request)

    assert response is not None
    middleware.rate_limit_handler.check_rate_limit_tiers.assert_awaited_once()


async def test_the_rate_limit_check_asks_the_resolver_about_a_route_bypass() -> None:
    route_config = RouteConfig()
    route_config.rate_limit = 5
    middleware = _middleware(_config())

    await RateLimitCheck(middleware).check(_request(route_config))

    middleware.route_resolver.should_bypass_check.assert_called_once_with(
        "rate_limit", route_config
    )
