from typing import Any

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events.enricher import EventEnricher
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.decorators.base import BaseSecurityDecorator


class _FakeAgent:
    started = 0
    stopped = 0

    def start(self) -> None:
        type(self).started += 1

    def stop(self) -> None:
        type(self).stopped += 1

    def send_event(self, _: Any) -> None:
        return None

    def send_metric(self, _: Any) -> None:
        return None

    def initialize_redis(self, _: Any) -> None:
        return None

    def flush_buffer(self) -> None:
        return None

    def get_dynamic_rules(self) -> Any | None:
        return None

    def health_check(self) -> bool:
        return True

    def get_stats(self) -> dict[str, Any]:
        return {}


def test_build_enricher_returns_none_when_disabled() -> None:
    config = SyncSecurityConfig()
    initializer = HandlerInitializer(config=config)
    assert initializer.build_enricher() is None


def test_build_enricher_returns_event_enricher_when_enabled() -> None:
    config = SyncSecurityConfig(
        enable_agent=True, agent_api_key="a" * 10, enable_enrichment=True
    )
    initializer = HandlerInitializer(config=config, agent_handler=_FakeAgent())
    enricher = initializer.build_enricher()
    assert isinstance(enricher, EventEnricher)
    assert enricher._context.config is config
    assert isinstance(enricher._context.agent_handler, _FakeAgent)


def test_initialize_agent_integrations_wires_enricher_into_composite() -> None:
    config = SyncSecurityConfig(
        enable_agent=True, agent_api_key="a" * 10, enable_enrichment=True
    )
    initializer = HandlerInitializer(config=config, agent_handler=_FakeAgent())

    initializer.initialize_agent_integrations()

    assert initializer.enricher is not None
    assert isinstance(initializer.enricher, EventEnricher)
    assert initializer.composite_handler is not None
    assert initializer.composite_handler._enricher is initializer.enricher


def test_initialize_agent_integrations_skips_enricher_when_flag_off() -> None:
    config = SyncSecurityConfig(
        enable_agent=True, agent_api_key="a" * 10, enable_enrichment=False
    )
    initializer = HandlerInitializer(config=config, agent_handler=_FakeAgent())

    initializer.initialize_agent_integrations()

    assert initializer.enricher is None
    assert initializer.composite_handler is not None
    assert initializer.composite_handler._enricher is None


def test_build_enricher_resolves_dynamic_rule_handler_when_enabled() -> None:
    config = SyncSecurityConfig(
        enable_agent=True,
        agent_api_key="a" * 10,
        enable_enrichment=True,
        enable_dynamic_rules=True,
    )
    initializer = HandlerInitializer(config=config, agent_handler=_FakeAgent())
    enricher = initializer.build_enricher()
    assert enricher is not None
    assert enricher._context.dynamic_rule_handler is not None


def test_build_enricher_resolves_behavior_tracker_from_decorator() -> None:
    config = SyncSecurityConfig(
        enable_agent=True, agent_api_key="a" * 10, enable_enrichment=True
    )
    decorator = BaseSecurityDecorator(config)
    initializer = HandlerInitializer(
        config=config, agent_handler=_FakeAgent(), guard_decorator=decorator
    )
    enricher = initializer.build_enricher()
    assert enricher is not None
    assert enricher._context.behavior_tracker is decorator.behavior_tracker


def test_shutdown_clears_enricher() -> None:
    config = SyncSecurityConfig(
        enable_agent=True, agent_api_key="a" * 10, enable_enrichment=True
    )
    initializer = HandlerInitializer(config=config, agent_handler=_FakeAgent())

    initializer.initialize_agent_integrations()
    wired_enricher = initializer.enricher
    assert wired_enricher is not None

    initializer.shutdown_agent_integrations()
    assert initializer.enricher is None
    assert initializer.composite_handler is None
