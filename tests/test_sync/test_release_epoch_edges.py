from collections.abc import Iterator
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.app_managers import release_app, release_epoch_of
from guard_core.sync.core.checks import build_default_pipeline
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers import ipban_handler as ipban_module
from guard_core.sync.handlers import suspatterns_handler as patterns_module
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for


@pytest.fixture(autouse=True)
def _defaults_unserved() -> Iterator[None]:
    ipban_module._APP_BAN_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()
    yield
    ipban_module._APP_BAN_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()


def _middleware(config: SyncSecurityConfig, initializer: object | None) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.handler_initializer = initializer
    middleware.guard_decorator = None
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.route_resolver = Mock()
    middleware.geo_ip_handler = None
    middleware.suspicious_request_counts = {}
    return middleware


def _request() -> MagicMock:
    request = MagicMock()
    request.state.client_ip = "203.0.113.95"
    request.url_path = "/api/test"
    return request


def test_releasing_an_object_that_cannot_hold_the_epoch_raises_nothing() -> None:
    plain = object()
    release_app(plain)
    assert release_epoch_of(plain) == 0


def test_each_release_moves_the_epoch_of_the_config() -> None:
    config = SyncSecurityConfig(enable_redis=False)
    before = release_epoch_of(config)
    release_app(config)
    release_app(config)
    assert release_epoch_of(config) == before + 2


def test_a_middleware_without_an_initializer_is_rebound_by_the_bare_bind() -> None:
    config = SyncSecurityConfig(enable_redis=False)
    HandlerInitializer(config)
    pipeline = build_default_pipeline(_middleware(config, None))
    release_app(config)
    assert pipeline._rebuild_response(_request()) is None
    assert ip_ban_manager_for(config) is ipban_module.ip_ban_manager
    assert pipeline._built_release_epoch == release_epoch_of(config)


def test_a_pipeline_without_a_reinitializer_still_rebuilds() -> None:
    config = SyncSecurityConfig(enable_redis=False)
    pipeline = SecurityCheckPipeline([], config=config, rebuild_checks=lambda: [])
    release_app(config)
    assert pipeline._rebuild_response(_request()) is None
    assert pipeline._built_release_epoch == release_epoch_of(config)


def test_the_reinitialization_wires_the_agent_of_the_app() -> None:
    config = SyncSecurityConfig(enable_redis=False)
    agent = MagicMock()
    initializer = HandlerInitializer(config, agent_handler=agent)
    release_app(config)
    initializer.reinitialize_after_release()
    agent.initialize_redis.assert_not_called()
    assert ip_ban_manager_for(config).agent_handler is not None


def test_the_enricher_adopts_a_rule_manager_that_holds_the_bound_ban_manager() -> None:
    first = SyncSecurityConfig(enable_redis=False)
    HandlerInitializer(first)
    config = SyncSecurityConfig(
        enable_redis=True,
        redis_url="redis://localhost:6538/6",
        redis_prefix="wp616:edges:",
        enable_enrichment=True,
        enable_dynamic_rules=True,
        enable_agent=True,
        agent_api_key="k" * 10,
        agent_project_id="p",
    )
    initializer = HandlerInitializer(config)
    enricher = initializer.build_enricher()
    assert enricher is not None
    rules = enricher._context.dynamic_rule_handler
    assert isinstance(rules, DynamicRuleManager)
    assert rules.ban_manager_of_the_app() is ip_ban_manager_for(config)
