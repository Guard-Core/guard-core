import logging
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from guard_core.core.checks.implementations.emergency_mode import EmergencyModeCheck
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.core.responses.modifier_view import report_body_refused
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.models import SecurityConfig
from guard_core.utils import extract_client_ip
from tests.conftest import MockGuardRequest, MockGuardResponse
from tests.test_core.conftest import build_route_pipeline, send_request


def _config(
    *,
    trusted_proxies: list[str] | None = None,
    enable_penetration_detection: bool = False,
    enable_ip_banning: bool = True,
    emergency_mode: bool = False,
    emergency_whitelist: list[str] | None = None,
) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_rate_limiting=False,
        lazy_init=False,
        trusted_proxies=trusted_proxies or [],
        enable_penetration_detection=enable_penetration_detection,
        enable_ip_banning=enable_ip_banning,
        emergency_mode=emergency_mode,
        emergency_whitelist=emergency_whitelist or [],
    )


async def _xff_events(config: SecurityConfig) -> int:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    request = MockGuardRequest(
        headers={"X-Forwarded-For": "198.51.100.77"}, client_host="203.0.113.9"
    )
    await extract_client_ip(request, config, agent)
    return int(agent.send_event.await_count)


async def test_each_app_reports_the_untrusted_forwarded_for_of_a_peer() -> None:
    app_a = _config(trusted_proxies=["10.0.0.5"])
    app_b = _config(trusted_proxies=["10.0.0.5"])

    assert await _xff_events(app_a) == 1
    assert await _xff_events(app_a) == 0
    assert await _xff_events(app_b) == 1


async def _disabled_detection_events(config: SecurityConfig) -> int:
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda decorator: decorator.suspicious_detection(False)
    )
    await send_request(pipeline, route_id, ip="203.0.113.110")
    calls = middleware.event_bus.send_middleware_event.call_args_list
    return sum(
        call.kwargs.get("action_taken") == "detection_disabled" for call in calls
    )


async def test_each_app_reports_a_client_whose_detection_is_disabled() -> None:
    app_a = _config(enable_penetration_detection=True, enable_ip_banning=False)
    app_b = _config(enable_penetration_detection=True, enable_ip_banning=False)

    assert await _disabled_detection_events(app_a) == 1
    assert await _disabled_detection_events(app_a) == 0
    assert await _disabled_detection_events(app_b) == 1


async def _emergency_events(config: SecurityConfig) -> int:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("guard_core.test.per_app_emergency")
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code, {}
        )
    )
    request = MockGuardRequest(client_host="203.0.113.9")
    request.state.client_ip = "203.0.113.9"
    await EmergencyModeCheck(middleware).check(request)
    return int(middleware.event_bus.send_middleware_event.await_count)


async def test_each_app_reports_a_client_denied_by_emergency_mode() -> None:
    def emergency_app() -> SecurityConfig:
        return _config(emergency_mode=True, emergency_whitelist=["10.0.0.1"])

    app_a = emergency_app()
    app_b = emergency_app()

    assert await _emergency_events(app_a) == 1
    assert await _emergency_events(app_a) == 0
    assert await _emergency_events(app_b) == 1


async def _init_failure_lines(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> int:
    redis = Mock()
    redis.initialize = AsyncMock(side_effect=GuardRedisError(503, "down"))
    redis.initialize_agent = AsyncMock()
    geo = Mock()
    geo.initialize = AsyncMock()
    geo.initialize_redis = AsyncMock()
    geo.initialize_agent = AsyncMock()
    agent = Mock()
    agent.start = AsyncMock()
    agent.initialize_redis = AsyncMock()
    rate_limit = Mock()
    rate_limit.initialize_redis = AsyncMock()
    rate_limit.initialize_agent = AsyncMock()
    decorator = Mock()
    decorator.initialize_agent = AsyncMock()
    decorator.initialize_behavior_tracking = AsyncMock()
    decorator._route_configs = {}
    initializer = HandlerInitializer(
        config=config,
        redis_handler=redis,
        agent_handler=agent,
        geo_ip_handler=geo,
        rate_limit_handler=rate_limit,
        guard_decorator=decorator,
    )
    caplog.clear()
    with caplog.at_level(logging.ERROR, logger="guard_core.core.initialization"):
        await initializer.initialize_redis_handlers()
    return sum(
        "Redis unavailable during initialization" in record.getMessage()
        for record in caplog.records
    )


async def test_each_app_logs_its_redis_failure_during_initialization(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def failing_app() -> SecurityConfig:
        config = SecurityConfig(lazy_init=False)
        config.enable_redis = True
        config.agent_api_key = "test-api-key"
        config.enable_agent = True
        config.enable_dynamic_rules = False
        config.block_cloud_providers = frozenset()
        config.redis_fail_open = True
        return config

    app_a = failing_app()
    app_b = failing_app()

    assert await _init_failure_lines(app_a, caplog) == 1
    assert await _init_failure_lines(app_a, caplog) == 0
    assert await _init_failure_lines(app_b, caplog) == 1


async def _attribution_failure_lines(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> int:
    manager = IPBanManager._fresh()
    manager.config = config
    redis = MagicMock()
    redis.owned_ban_state = AsyncMock(side_effect=RuntimeError("down"))
    manager.redis_handler = redis
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        await manager.rule_owns_live_ban("banned_ips:203.0.113.5")
    return sum("Ban attribution skipped" in record.message for record in caplog.records)


async def test_each_app_logs_a_failed_ban_attribution(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app_a = _config()
    app_b = _config()

    assert await _attribution_failure_lines(app_a, caplog) == 1
    assert await _attribution_failure_lines(app_a, caplog) == 0
    assert await _attribution_failure_lines(app_b, caplog) == 1


async def _refusal_lines(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> int:
    logger = logging.getLogger("guard_core.test.per_app_refusal")
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=logger.name):
        await report_body_refused(logger, config, None, MockGuardRequest(), "reason")
    return len(caplog.records)


async def test_each_app_reports_a_refused_response_body(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app_a = _config()
    app_b = _config()

    assert await _refusal_lines(app_a, caplog) == 1
    assert await _refusal_lines(app_a, caplog) == 0
    assert await _refusal_lines(app_b, caplog) == 1
