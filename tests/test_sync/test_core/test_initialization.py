import logging
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer


@pytest.fixture
def security_config() -> SyncSecurityConfig:
    config = SyncSecurityConfig(lazy_init=False)
    config.enable_redis = True
    config.agent_api_key = "test-api-key"
    config.enable_agent = True
    config.enable_dynamic_rules = False
    config.block_cloud_providers = frozenset()
    return config


@pytest.fixture
def mock_redis_handler() -> Mock:
    handler = Mock()
    handler.initialize = MagicMock()
    handler.initialize_agent = MagicMock()
    return handler


@pytest.fixture
def mock_agent_handler() -> Mock:
    handler = Mock()
    handler.start = MagicMock()
    handler.initialize_redis = MagicMock()
    return handler


@pytest.fixture
def mock_geo_ip_handler() -> Mock:
    handler = Mock()
    handler.initialize_redis = MagicMock()
    handler.initialize_agent = MagicMock()
    return handler


@pytest.fixture
def mock_rate_limit_handler() -> Mock:
    handler = Mock()
    handler.initialize_redis = MagicMock()
    handler.initialize_agent = MagicMock()
    return handler


@pytest.fixture
def mock_guard_decorator() -> Mock:
    decorator = Mock()
    decorator.initialize_agent = MagicMock()
    decorator.initialize_behavior_tracking = MagicMock()
    decorator._route_configs = {}
    return decorator


@pytest.fixture
def initializer(
    security_config: SyncSecurityConfig,
    mock_redis_handler: Mock,
    mock_agent_handler: Mock,
    mock_geo_ip_handler: Mock,
    mock_rate_limit_handler: Mock,
    mock_guard_decorator: Mock,
) -> HandlerInitializer:
    return HandlerInitializer(
        config=security_config,
        redis_handler=mock_redis_handler,
        agent_handler=mock_agent_handler,
        geo_ip_handler=mock_geo_ip_handler,
        rate_limit_handler=mock_rate_limit_handler,
        guard_decorator=mock_guard_decorator,
    )


def test_init(
    initializer: HandlerInitializer,
    security_config: SyncSecurityConfig,
    mock_redis_handler: Mock,
) -> None:
    assert initializer.config == security_config
    assert initializer.redis_handler == mock_redis_handler


def test_initialize_redis_handlers_disabled(
    security_config: SyncSecurityConfig,
) -> None:
    security_config.enable_redis = False
    initializer = HandlerInitializer(config=security_config)

    initializer.initialize_redis_handlers()


def test_initialize_redis_handlers_no_handler(
    security_config: SyncSecurityConfig,
) -> None:
    initializer = HandlerInitializer(config=security_config, redis_handler=None)

    initializer.initialize_redis_handlers()


def test_initialize_redis_handlers_basic(
    initializer: HandlerInitializer,
    mock_redis_handler: Mock,
    mock_geo_ip_handler: Mock,
    mock_rate_limit_handler: Mock,
) -> None:
    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_redis = MagicMock()
        mock_ipban.initialize_redis = MagicMock()
        mock_sus.initialize_redis = MagicMock()

        initializer.initialize_redis_handlers()

        mock_redis_handler.initialize.assert_called_once()

        mock_ipban.initialize_redis.assert_called_once_with(mock_redis_handler)
        mock_geo_ip_handler.initialize_redis.assert_called_once_with(mock_redis_handler)
        mock_rate_limit_handler.initialize_redis.assert_called_once_with(
            mock_redis_handler
        )
        mock_sus.initialize_redis.assert_called_once_with(mock_redis_handler)


def test_initialize_redis_handlers_with_cloud(
    initializer: HandlerInitializer,
    security_config: SyncSecurityConfig,
    mock_redis_handler: Mock,
) -> None:
    security_config.block_cloud_providers = frozenset({"AWS", "GCP"})

    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_redis = MagicMock()
        mock_ipban.initialize_redis = MagicMock()
        mock_sus.initialize_redis = MagicMock()

        initializer.initialize_redis_handlers()

        mock_cloud.initialize_redis.assert_called_once_with(
            mock_redis_handler,
            security_config.block_cloud_providers,
            ttl=security_config.cloud_ip_refresh_interval,
        )


def test_initialize_redis_handlers_sets_cloud_ip_store_when_configured(
    initializer: HandlerInitializer,
    security_config: SyncSecurityConfig,
) -> None:
    custom_store = Mock()
    custom_store.get = MagicMock()
    custom_store.set = MagicMock()
    custom_store.clear = MagicMock()
    security_config.cloud_ip_store = custom_store

    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_redis = MagicMock()
        mock_cloud.set_store = Mock()
        mock_ipban.initialize_redis = MagicMock()
        mock_sus.initialize_redis = MagicMock()

        initializer.initialize_redis_handlers()

        mock_cloud.set_store.assert_called_once_with(custom_store)


def test_initialize_redis_handlers_no_optional_handlers(
    security_config: SyncSecurityConfig, mock_redis_handler: Mock
) -> None:
    initializer = HandlerInitializer(
        config=security_config,
        redis_handler=mock_redis_handler,
        geo_ip_handler=None,
        rate_limit_handler=None,
    )

    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_redis = MagicMock()
        mock_ipban.initialize_redis = MagicMock()
        mock_sus.initialize_redis = MagicMock()

        initializer.initialize_redis_handlers()

        mock_redis_handler.initialize.assert_called_once()


def test_initialize_redis_handlers_initializes_behavior_tracking_with_rules(
    initializer: HandlerInitializer,
    mock_redis_handler: Mock,
    mock_guard_decorator: Mock,
) -> None:
    from guard_core.sync.decorators.base import RouteConfig
    from guard_core.sync.handlers.behavior_handler import BehaviorRule

    route_config = RouteConfig()
    route_config.behavior_rules = [
        BehaviorRule(rule_type="usage", threshold=5, window=60, action="ban")
    ]
    mock_guard_decorator._route_configs = {"route": route_config}

    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_redis = MagicMock()
        mock_ipban.initialize_redis = MagicMock()
        mock_sus.initialize_redis = MagicMock()

        initializer.initialize_redis_handlers()

    mock_guard_decorator.initialize_behavior_tracking.assert_called_once_with(
        mock_redis_handler
    )


def test_initialize_redis_handlers_connects_behavior_tracking_without_rules(
    initializer: HandlerInitializer,
    mock_guard_decorator: Mock,
    mock_redis_handler: Mock,
) -> None:
    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_redis = MagicMock()
        mock_ipban.initialize_redis = MagicMock()
        mock_sus.initialize_redis = MagicMock()

        initializer.initialize_redis_handlers()

    mock_guard_decorator.initialize_behavior_tracking.assert_called_once_with(
        mock_redis_handler
    )


def test_initialize_redis_handlers_connects_standalone_behavior_tracker(
    security_config: SyncSecurityConfig,
    mock_redis_handler: Mock,
) -> None:
    initializer = HandlerInitializer(
        config=security_config,
        redis_handler=mock_redis_handler,
        guard_decorator=None,
    )
    standalone_tracker = Mock()
    standalone_tracker.initialize_redis = MagicMock()
    initializer.behavior_tracker = standalone_tracker

    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_redis = MagicMock()
        mock_ipban.initialize_redis = MagicMock()
        mock_sus.initialize_redis = MagicMock()

        initializer.initialize_redis_handlers()

    standalone_tracker.initialize_redis.assert_called_once_with(mock_redis_handler)


def test_initialize_agent_for_handlers_no_agent(
    security_config: SyncSecurityConfig,
) -> None:
    initializer = HandlerInitializer(config=security_config, agent_handler=None)

    initializer.initialize_agent_for_handlers()


def test_initialize_agent_for_handlers_basic(
    initializer: HandlerInitializer,
    mock_agent_handler: Mock,
    mock_rate_limit_handler: Mock,
) -> None:
    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
        patch(
            "guard_core.sync.handlers.security_headers_handler.security_headers_manager"
        ) as mock_headers,
    ):
        mock_cloud.initialize_agent = MagicMock()
        mock_ipban.initialize_agent = MagicMock()
        mock_sus.initialize_agent = MagicMock()
        mock_headers.initialize_agent = MagicMock()

        initializer.initialize_agent_for_handlers()

        mock_ipban.initialize_agent.assert_called_once_with(mock_agent_handler)
        mock_rate_limit_handler.initialize_agent.assert_called_once_with(
            mock_agent_handler
        )
        mock_sus.initialize_agent.assert_called_once_with(mock_agent_handler)
        mock_headers.initialize_agent.assert_called_once_with(mock_agent_handler)


def test_initialize_agent_for_handlers_with_cloud(
    initializer: HandlerInitializer,
    security_config: SyncSecurityConfig,
    mock_agent_handler: Mock,
) -> None:
    security_config.block_cloud_providers = frozenset({"AWS"})

    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
        patch(
            "guard_core.sync.handlers.security_headers_handler.security_headers_manager"
        ) as mock_headers,
    ):
        mock_cloud.initialize_agent = MagicMock()
        mock_ipban.initialize_agent = MagicMock()
        mock_sus.initialize_agent = MagicMock()
        mock_headers.initialize_agent = MagicMock()

        initializer.initialize_agent_for_handlers()

        mock_cloud.initialize_agent.assert_called_once_with(mock_agent_handler)


def test_initialize_agent_for_handlers_with_geoip(
    initializer: HandlerInitializer,
    mock_agent_handler: Mock,
    mock_geo_ip_handler: Mock,
) -> None:
    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
        patch(
            "guard_core.sync.handlers.security_headers_handler.security_headers_manager"
        ) as mock_headers,
    ):
        mock_cloud.initialize_agent = MagicMock()
        mock_ipban.initialize_agent = MagicMock()
        mock_sus.initialize_agent = MagicMock()
        mock_headers.initialize_agent = MagicMock()

        initializer.initialize_agent_for_handlers()

        mock_geo_ip_handler.initialize_agent.assert_called_once_with(mock_agent_handler)


def test_initialize_agent_for_handlers_without_rate_limit_handler(
    security_config: SyncSecurityConfig,
    mock_agent_handler: Mock,
) -> None:
    initializer = HandlerInitializer(
        config=security_config,
        agent_handler=mock_agent_handler,
        rate_limit_handler=None,
    )
    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
        patch(
            "guard_core.sync.handlers.security_headers_handler.security_headers_manager"
        ) as mock_headers,
    ):
        mock_cloud.initialize_agent = MagicMock()
        mock_ipban.initialize_agent = MagicMock()
        mock_sus.initialize_agent = MagicMock()
        mock_headers.initialize_agent = MagicMock()

        initializer.initialize_agent_for_handlers()

        mock_ipban.initialize_agent.assert_called_once_with(mock_agent_handler)
        mock_sus.initialize_agent.assert_called_once_with(mock_agent_handler)
        mock_headers.initialize_agent.assert_called_once_with(mock_agent_handler)


def test_initialize_agent_for_handlers_geoip_without_initialize_agent(
    security_config: SyncSecurityConfig,
    mock_agent_handler: Mock,
) -> None:
    geo_ip = Mock(spec=[])
    initializer = HandlerInitializer(
        config=security_config,
        agent_handler=mock_agent_handler,
        geo_ip_handler=geo_ip,
    )
    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
        patch(
            "guard_core.sync.handlers.security_headers_handler.security_headers_manager"
        ) as mock_headers,
    ):
        mock_cloud.initialize_agent = MagicMock()
        mock_ipban.initialize_agent = MagicMock()
        mock_sus.initialize_agent = MagicMock()
        mock_headers.initialize_agent = MagicMock()

        initializer.initialize_agent_for_handlers()


def test_initialize_dynamic_rule_manager_disabled(
    security_config: SyncSecurityConfig,
    caplog: pytest.LogCaptureFixture,
) -> None:
    initializer = HandlerInitializer(config=security_config)

    with caplog.at_level(logging.WARNING, logger="guard_core.sync.core.initialization"):
        initializer.initialize_dynamic_rule_manager()

    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 0


def test_initialize_dynamic_rule_manager_no_agent(
    security_config: SyncSecurityConfig,
    caplog: pytest.LogCaptureFixture,
) -> None:
    security_config.enable_dynamic_rules = True
    initializer = HandlerInitializer(config=security_config, agent_handler=None)

    with caplog.at_level(logging.WARNING, logger="guard_core.sync.core.initialization"):
        initializer.initialize_dynamic_rule_manager()

    warnings = [
        r
        for r in caplog.records
        if r.levelname == "WARNING"
        and r.name == "guard_core.sync.core.initialization"
        and "Dynamic rules enabled but agent unavailable" in r.getMessage()
    ]
    assert len(warnings) == 1


def test_initialize_dynamic_rule_manager_enabled(
    initializer: HandlerInitializer,
    security_config: SyncSecurityConfig,
    mock_agent_handler: Mock,
    mock_redis_handler: Mock,
) -> None:
    security_config.enable_dynamic_rules = True

    with patch(
        "guard_core.sync.handlers.dynamic_rule_handler.DynamicRuleManager"
    ) as MockDRM:
        mock_drm_instance = Mock()
        mock_drm_instance.initialize_agent = MagicMock()
        mock_drm_instance.initialize_redis = MagicMock()
        MockDRM.return_value = mock_drm_instance

        initializer.initialize_dynamic_rule_manager()

        MockDRM.assert_called_once_with(security_config)
        mock_drm_instance.initialize_agent.assert_called_once_with(mock_agent_handler)
        mock_drm_instance.initialize_redis.assert_called_once_with(mock_redis_handler)


def test_initialize_dynamic_rule_manager_no_redis(
    security_config: SyncSecurityConfig, mock_agent_handler: Mock
) -> None:
    security_config.enable_dynamic_rules = True
    initializer = HandlerInitializer(
        config=security_config,
        agent_handler=mock_agent_handler,
        redis_handler=None,
    )

    with patch(
        "guard_core.sync.handlers.dynamic_rule_handler.DynamicRuleManager"
    ) as MockDRM:
        mock_drm_instance = Mock()
        mock_drm_instance.initialize_agent = MagicMock()
        mock_drm_instance.initialize_redis = MagicMock()
        MockDRM.return_value = mock_drm_instance

        initializer.initialize_dynamic_rule_manager()

        mock_drm_instance.initialize_redis.assert_not_called()


def test_initialize_dynamic_rule_manager_initializes_redis_before_agent(
    initializer: HandlerInitializer,
    security_config: SyncSecurityConfig,
    mock_agent_handler: Mock,
    mock_redis_handler: Mock,
) -> None:
    security_config.enable_dynamic_rules = True
    call_order: list[str] = []

    with patch(
        "guard_core.sync.handlers.dynamic_rule_handler.DynamicRuleManager"
    ) as MockDRM:
        mock_drm_instance = Mock()
        mock_drm_instance.initialize_redis = MagicMock(
            side_effect=lambda handler: call_order.append("redis")
        )
        mock_drm_instance.initialize_agent = MagicMock(
            side_effect=lambda telemetry: call_order.append("agent")
        )
        MockDRM.return_value = mock_drm_instance

        initializer.initialize_dynamic_rule_manager()

    assert call_order == ["redis", "agent"]
    mock_drm_instance.initialize_redis.assert_called_once_with(mock_redis_handler)
    mock_drm_instance.initialize_agent.assert_called_once()


def test_initialize_agent_integrations_no_agent(
    security_config: SyncSecurityConfig,
) -> None:
    initializer = HandlerInitializer(config=security_config, agent_handler=None)

    initializer.initialize_agent_integrations()


def test_initialize_agent_integrations_full(
    initializer: HandlerInitializer,
    mock_agent_handler: Mock,
    mock_redis_handler: Mock,
    mock_guard_decorator: Mock,
) -> None:
    mock_init_handlers = MagicMock()
    mock_init_drm = MagicMock()
    with (
        patch.object(initializer, "initialize_agent_for_handlers", mock_init_handlers),
        patch.object(initializer, "initialize_dynamic_rule_manager", mock_init_drm),
    ):
        initializer.initialize_agent_integrations()

        mock_agent_handler.start.assert_called_once()

        mock_agent_handler.initialize_redis.assert_called_once_with(mock_redis_handler)
        mock_redis_handler.initialize_agent.assert_called_once_with(mock_agent_handler)

        mock_init_handlers.assert_called_once()

        from guard_core.sync.core.events.composite_handler import CompositeAgentHandler

        mock_guard_decorator.initialize_agent.assert_called_once()
        passed = mock_guard_decorator.initialize_agent.call_args.args[0]
        assert isinstance(passed, CompositeAgentHandler)
        assert mock_agent_handler in passed._handlers

        mock_init_drm.assert_called_once()


def test_initialize_agent_integrations_no_redis(
    security_config: SyncSecurityConfig, mock_agent_handler: Mock
) -> None:
    initializer = HandlerInitializer(
        config=security_config,
        agent_handler=mock_agent_handler,
        redis_handler=None,
    )

    with (
        patch.object(initializer, "initialize_agent_for_handlers", MagicMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", MagicMock()),
    ):
        initializer.initialize_agent_integrations()

        mock_agent_handler.initialize_redis.assert_not_called()


def test_initialize_agent_integrations_no_decorator(
    security_config: SyncSecurityConfig, mock_agent_handler: Mock
) -> None:
    initializer = HandlerInitializer(
        config=security_config,
        agent_handler=mock_agent_handler,
        guard_decorator=None,
    )

    with (
        patch.object(initializer, "initialize_agent_for_handlers", MagicMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", MagicMock()),
    ):
        initializer.initialize_agent_integrations()

        mock_agent_handler.start.assert_called_once()


def test_initialize_agent_integrations_decorator_no_method(
    security_config: SyncSecurityConfig, mock_agent_handler: Mock
) -> None:
    decorator_no_method = Mock(spec=[])
    initializer = HandlerInitializer(
        config=security_config,
        agent_handler=mock_agent_handler,
        guard_decorator=decorator_no_method,
    )

    with (
        patch.object(initializer, "initialize_agent_for_handlers", MagicMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", MagicMock()),
    ):
        initializer.initialize_agent_integrations()

        mock_agent_handler.start.assert_called_once()


def test_build_composite_handler_agent_only(
    security_config: SyncSecurityConfig,
) -> None:
    agent = Mock()
    security_config.enable_otel = False
    security_config.enable_logfire = False
    initializer = HandlerInitializer(config=security_config, agent_handler=agent)
    result = initializer.build_composite_handler()
    from guard_core.sync.core.events.composite_handler import CompositeAgentHandler

    assert isinstance(result, CompositeAgentHandler)
    assert result._handlers == [agent]


def test_build_composite_handler_with_otel(security_config: SyncSecurityConfig) -> None:
    agent = Mock()
    security_config.enable_otel = True
    security_config.enable_logfire = False
    initializer = HandlerInitializer(config=security_config, agent_handler=agent)
    with patch("guard_core.sync.core.events.otel_handler.OtelHandler") as MockOtel:
        MockOtel.return_value = Mock()
        result = initializer.build_composite_handler()
    from guard_core.sync.core.events.composite_handler import CompositeAgentHandler

    assert isinstance(result, CompositeAgentHandler)


def test_build_composite_handler_with_logfire(
    security_config: SyncSecurityConfig,
) -> None:
    agent = Mock()
    security_config.enable_otel = False
    security_config.enable_logfire = True
    initializer = HandlerInitializer(config=security_config, agent_handler=agent)
    with patch("guard_core.sync.core.events.logfire_handler.LogfireHandler") as MockLF:
        MockLF.return_value = Mock()
        result = initializer.build_composite_handler()
    from guard_core.sync.core.events.composite_handler import CompositeAgentHandler

    assert isinstance(result, CompositeAgentHandler)


def test_build_composite_handler_otel_and_logfire(
    security_config: SyncSecurityConfig,
) -> None:
    agent = Mock()
    security_config.enable_otel = True
    security_config.enable_logfire = True
    initializer = HandlerInitializer(config=security_config, agent_handler=agent)
    with (
        patch("guard_core.sync.core.events.otel_handler.OtelHandler") as MockOtel,
        patch("guard_core.sync.core.events.logfire_handler.LogfireHandler") as MockLF,
    ):
        MockOtel.return_value = Mock()
        MockLF.return_value = Mock()
        result = initializer.build_composite_handler()
    from guard_core.sync.core.events.composite_handler import CompositeAgentHandler

    assert isinstance(result, CompositeAgentHandler)


def test_build_composite_handler_no_agent(security_config: SyncSecurityConfig) -> None:
    security_config.enable_otel = True
    security_config.enable_logfire = False
    initializer = HandlerInitializer(config=security_config, agent_handler=None)
    with patch("guard_core.sync.core.events.otel_handler.OtelHandler") as MockOtel:
        mock_otel = Mock()
        MockOtel.return_value = mock_otel
        result = initializer.build_composite_handler()
    from guard_core.sync.core.events.composite_handler import CompositeAgentHandler

    assert isinstance(result, CompositeAgentHandler)
    assert result._handlers == [mock_otel]


def test_build_event_filter(security_config: SyncSecurityConfig) -> None:
    from guard_core.sync.core.events.event_types import EventFilter

    security_config.muted_event_types = frozenset({"penetration_attempt"})
    security_config.muted_metric_types = frozenset({"response_time"})
    initializer = HandlerInitializer(config=security_config)
    result = initializer.build_event_filter()
    assert isinstance(result, EventFilter)
    assert result.muted_event_types == frozenset({"penetration_attempt"})
    assert result.muted_metric_types == frozenset({"response_time"})


def test_get_initialization_status_reports_cloud_and_geo(
    initializer: HandlerInitializer, mock_geo_ip_handler: Mock
) -> None:
    mock_geo_ip_handler.get_status = Mock(
        return_value={"ready": True, "last_refreshed": None, "entries": 5}
    )

    status = initializer.get_initialization_status()

    assert "cloud_providers" in status
    assert status["geo_ip"] == {"ready": True, "last_refreshed": None, "entries": 5}


def test_get_initialization_status_falls_back_without_get_status_method(
    security_config: SyncSecurityConfig,
) -> None:
    geo_ip_handler = Mock(spec=["is_initialized"])
    geo_ip_handler.is_initialized = True
    initializer = HandlerInitializer(
        config=security_config, geo_ip_handler=geo_ip_handler
    )

    status = initializer.get_initialization_status()

    assert status["geo_ip"] == {"ready": True, "last_refreshed": None, "entries": 0}


def test_get_initialization_status_geo_none_when_no_geo_handler(
    security_config: SyncSecurityConfig,
) -> None:
    initializer = HandlerInitializer(config=security_config, geo_ip_handler=None)

    status = initializer.get_initialization_status()

    assert status["geo_ip"] is None
    assert "cloud_providers" in status


def test_initialize_redis_handlers_degrades_to_memory_when_unreachable_fail_open(
    initializer: HandlerInitializer,
    security_config: SyncSecurityConfig,
    mock_redis_handler: Mock,
    mock_geo_ip_handler: Mock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    security_config.redis_fail_open = True
    mock_redis_handler.initialize = MagicMock(
        side_effect=GuardRedisError(503, "Redis connection failed")
    )
    mock_geo_ip_handler.initialize = MagicMock()

    with (
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
        caplog.at_level(logging.ERROR, logger="guard_core.sync.core.initialization"),
    ):
        mock_ipban.initialize_redis = MagicMock()
        mock_sus.initialize_redis = MagicMock()

        initializer.initialize_redis_handlers()

        mock_geo_ip_handler.initialize.assert_called_once()
        mock_ipban.initialize_redis.assert_not_called()
        mock_sus.initialize_redis.assert_not_called()

    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert any(
        "Redis unavailable during initialization" in r.getMessage() for r in errors
    )


def test_initialize_redis_handlers_reraises_redis_unreachable_fail_open_is_false(
    initializer: HandlerInitializer,
    mock_redis_handler: Mock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    mock_redis_handler.initialize = MagicMock(
        side_effect=GuardRedisError(503, "Redis connection failed")
    )

    with caplog.at_level(logging.ERROR, logger="guard_core.sync.core.initialization"):
        with pytest.raises(GuardRedisError):
            initializer.initialize_redis_handlers()

    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert any(
        "Redis unavailable during initialization" in r.getMessage() for r in errors
    )


@pytest.mark.parametrize("redis_fail_open", [True, False])
def test_initialize_redis_handlers_completes_when_sus_patterns_get_key_fails(
    initializer: HandlerInitializer,
    security_config: SyncSecurityConfig,
    mock_redis_handler: Mock,
    redis_fail_open: bool,
) -> None:
    from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

    security_config.redis_fail_open = redis_fail_open
    mock_redis_handler.get_key = MagicMock(
        side_effect=GuardRedisError(503, "Redis connection failed")
    )

    SusPatternsManager._instance = None
    real_sus = SusPatternsManager()

    with (
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler",
            real_sus,
        ),
    ):
        mock_ipban.initialize_redis = MagicMock()

        initializer.initialize_redis_handlers()

    assert real_sus.redis_handler is mock_redis_handler


@pytest.mark.parametrize("redis_fail_open", [True, False])
def test_initialize_redis_handlers_completes_when_geo_ip_handler_get_key_fails(
    security_config: SyncSecurityConfig,
    mock_redis_handler: Mock,
    redis_fail_open: bool,
    tmp_path: Path,
) -> None:
    from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
    from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

    security_config.redis_fail_open = redis_fail_open
    mock_redis_handler.get_key = MagicMock(
        side_effect=GuardRedisError(503, "Redis connection failed")
    )

    IPInfoManager._instance = None
    real_geo = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")
    SusPatternsManager._instance = None
    real_sus = SusPatternsManager()

    initializer = HandlerInitializer(
        config=security_config,
        redis_handler=mock_redis_handler,
        geo_ip_handler=real_geo,
    )

    with (
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler",
            real_sus,
        ),
        patch.object(real_geo, "_download_database", new=MagicMock()),
    ):
        mock_ipban.initialize_redis = MagicMock()

        initializer.initialize_redis_handlers()

    assert real_geo.redis_handler is mock_redis_handler
    IPInfoManager._instance = None


def test_initialize_redis_handlers_logs_the_failure_once_inside_the_window(
    initializer: HandlerInitializer,
    security_config: SyncSecurityConfig,
    mock_redis_handler: Mock,
    mock_geo_ip_handler: Mock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    security_config.redis_fail_open = True
    mock_redis_handler.initialize = MagicMock(
        side_effect=GuardRedisError(503, "Redis connection failed")
    )
    mock_geo_ip_handler.initialize = MagicMock()

    with caplog.at_level(logging.ERROR, logger="guard_core.sync.core.initialization"):
        initializer.initialize_redis_handlers()
        initializer.initialize_redis_handlers()

    lines = [
        r
        for r in caplog.records
        if "Redis unavailable during initialization" in r.getMessage()
    ]
    assert len(lines) == 1
