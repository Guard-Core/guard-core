import logging
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.emergency_mode import (
    EmergencyModeCheck,
)
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.core.responses.modifier_view import report_body_refused
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.utils import extract_client_ip
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest
from tests.test_sync.test_core.conftest import build_route_pipeline, send_request


def _config(**overrides: Any) -> SyncSecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_rate_limiting": False,
        "lazy_init": False,
    }
    fields.update(overrides)
    return SyncSecurityConfig(**fields)


def _xff_events(config: SyncSecurityConfig) -> int:
    agent = MagicMock()
    agent.send_event = MagicMock()
    request = SyncMockGuardRequest(
        headers={"X-Forwarded-For": "198.51.100.77"}, client_host="203.0.113.9"
    )
    extract_client_ip(request, config, agent)
    return int(agent.send_event.call_count)


def test_each_app_reports_the_untrusted_forwarded_for_of_a_peer() -> None:
    app_a = _config(trusted_proxies=["10.0.0.5"])
    app_b = _config(trusted_proxies=["10.0.0.5"])

    assert _xff_events(app_a) == 1
    assert _xff_events(app_a) == 0
    assert _xff_events(app_b) == 1


def _disabled_detection_events(config: SyncSecurityConfig) -> int:
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda decorator: decorator.suspicious_detection(False)
    )
    send_request(pipeline, route_id, ip="203.0.113.110")
    calls = middleware.event_bus.send_middleware_event.call_args_list
    return sum(
        call.kwargs.get("action_taken") == "detection_disabled" for call in calls
    )


def test_each_app_reports_a_client_whose_detection_is_disabled() -> None:
    app_a = _config(enable_penetration_detection=True, enable_ip_banning=False)
    app_b = _config(enable_penetration_detection=True, enable_ip_banning=False)

    assert _disabled_detection_events(app_a) == 1
    assert _disabled_detection_events(app_a) == 0
    assert _disabled_detection_events(app_b) == 1


def _emergency_events(config: SyncSecurityConfig) -> int:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("guard_core.test.per_app_emergency")
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code, {}
        )
    )
    request = SyncMockGuardRequest(client_host="203.0.113.9")
    request.state.client_ip = "203.0.113.9"
    EmergencyModeCheck(middleware).check(request)
    return int(middleware.event_bus.send_middleware_event.call_count)


def test_each_app_reports_a_client_denied_by_emergency_mode() -> None:
    def emergency_app() -> SyncSecurityConfig:
        return _config(emergency_mode=True, emergency_whitelist=["10.0.0.1"])

    app_a = emergency_app()
    app_b = emergency_app()

    assert _emergency_events(app_a) == 1
    assert _emergency_events(app_a) == 0
    assert _emergency_events(app_b) == 1


def _init_failure_lines(
    config: SyncSecurityConfig, caplog: pytest.LogCaptureFixture
) -> int:
    redis = Mock()
    redis.initialize = MagicMock(side_effect=GuardRedisError(503, "down"))
    redis.initialize_agent = MagicMock()
    geo = Mock()
    geo.initialize = MagicMock()
    geo.initialize_redis = MagicMock()
    geo.initialize_agent = MagicMock()
    agent = Mock()
    agent.start = MagicMock()
    agent.initialize_redis = MagicMock()
    rate_limit = Mock()
    rate_limit.initialize_redis = MagicMock()
    rate_limit.initialize_agent = MagicMock()
    decorator = Mock()
    decorator.initialize_agent = MagicMock()
    decorator.initialize_behavior_tracking = MagicMock()
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
    with caplog.at_level(logging.ERROR, logger="guard_core.sync.core.initialization"):
        initializer.initialize_redis_handlers()
    return sum(
        "Redis unavailable during initialization" in record.getMessage()
        for record in caplog.records
    )


def test_each_app_logs_its_redis_failure_during_initialization(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def failing_app() -> SyncSecurityConfig:
        config = SyncSecurityConfig(lazy_init=False)
        config.enable_redis = True
        config.enable_agent = True
        config.enable_dynamic_rules = False
        config.block_cloud_providers = frozenset()
        config.redis_fail_open = True
        return config

    app_a = failing_app()
    app_b = failing_app()

    assert _init_failure_lines(app_a, caplog) == 1
    assert _init_failure_lines(app_a, caplog) == 0
    assert _init_failure_lines(app_b, caplog) == 1


def _attribution_failure_lines(
    config: SyncSecurityConfig, caplog: pytest.LogCaptureFixture
) -> int:
    manager = IPBanManager._fresh()
    manager.config = config
    redis = MagicMock()
    redis.owned_ban_state = MagicMock(side_effect=RuntimeError("down"))
    manager.redis_handler = redis
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        manager.rule_owns_live_ban("banned_ips:203.0.113.5")
    return sum("Ban attribution skipped" in record.message for record in caplog.records)


def test_each_app_logs_a_failed_ban_attribution(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app_a = _config()
    app_b = _config()

    assert _attribution_failure_lines(app_a, caplog) == 1
    assert _attribution_failure_lines(app_a, caplog) == 0
    assert _attribution_failure_lines(app_b, caplog) == 1


def _refusal_lines(config: SyncSecurityConfig, caplog: pytest.LogCaptureFixture) -> int:
    logger = logging.getLogger("guard_core.test.per_app_refusal")
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=logger.name):
        report_body_refused(logger, config, None, SyncMockGuardRequest(), "reason")
    return len(caplog.records)


def test_each_app_reports_a_refused_response_body(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app_a = _config()
    app_b = _config()

    assert _refusal_lines(app_a, caplog) == 1
    assert _refusal_lines(app_a, caplog) == 0
    assert _refusal_lines(app_b, caplog) == 1
