from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from guard_core._utils.app_managers import release_app, release_epoch_of
from guard_core.core.checks import build_default_pipeline
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers import suspatterns_handler as patterns_module
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.models import SecurityConfig


@pytest.fixture(autouse=True)
def _defaults_unserved() -> Iterator[None]:
    ipban_module._APP_BAN_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()
    yield
    ipban_module._APP_BAN_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()


def _middleware(config: SecurityConfig, initializer: object | None) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.handler_initializer = initializer
    middleware.guard_decorator = None
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
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
    config = SecurityConfig(enable_redis=False)
    before = release_epoch_of(config)
    release_app(config)
    release_app(config)
    assert release_epoch_of(config) == before + 2


async def test_a_middleware_without_an_initializer_is_rebound_by_the_bare_bind() -> (
    None
):
    config = SecurityConfig(enable_redis=False)
    HandlerInitializer(config)
    pipeline = build_default_pipeline(_middleware(config, None))
    release_app(config)
    assert await pipeline._rebuild_response(_request()) is None
    assert ip_ban_manager_for(config) is ipban_module.ip_ban_manager
    assert pipeline._built_release_epoch == release_epoch_of(config)


async def test_a_pipeline_without_a_reinitializer_still_rebuilds() -> None:
    config = SecurityConfig(enable_redis=False)
    pipeline = SecurityCheckPipeline([], config=config, rebuild_checks=lambda: [])
    release_app(config)
    assert await pipeline._rebuild_response(_request()) is None
    assert pipeline._built_release_epoch == release_epoch_of(config)


async def test_the_reinitialization_wires_the_agent_of_the_app() -> None:
    config = SecurityConfig(enable_redis=False)
    agent = AsyncMock()
    initializer = HandlerInitializer(config, agent_handler=agent)
    release_app(config)
    await initializer.reinitialize_after_release()
    agent.initialize_redis.assert_not_called()
    assert ip_ban_manager_for(config).agent_handler is not None


def test_the_enricher_adopts_a_rule_manager_that_holds_the_bound_ban_manager() -> None:
    first = SecurityConfig(enable_redis=False)
    HandlerInitializer(first)
    config = SecurityConfig(
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


def _rules_of(manager: DynamicRuleManager) -> object:
    return manager.current_rules


def test_a_failed_withdrawal_is_logged_and_release_goes_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_redis=False)
    manager = DynamicRuleManager(config)
    manager.current_rules = Mock()
    monkeypatch.setattr(
        manager, "_revert_to_base_config", Mock(side_effect=RuntimeError("boom"))
    )
    release_app(config)
    assert _rules_of(manager) is None


def test_the_enricher_has_no_rule_manager_when_dynamic_rules_are_off() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_enrichment=True,
        enable_agent=True,
        agent_api_key="k" * 10,
        agent_project_id="p",
    )
    enricher = HandlerInitializer(config).build_enricher()
    assert enricher is not None
    assert enricher._context.dynamic_rule_handler is None


async def test_a_withdrawal_leaves_the_overlay_while_an_update_holds_the_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_redis=False)
    manager = DynamicRuleManager(config)
    manager.current_rules = Mock()
    revert = Mock()
    monkeypatch.setattr(manager, "_revert_to_base_config", revert)
    async with manager._lock:
        manager._withdraw_the_applied_rules()
    revert.assert_not_called()
    manager._withdraw_the_applied_rules()
    revert.assert_called_once()
