from types import SimpleNamespace

import pytest

from guard_core.core.events.enricher import EnrichmentContext, EventEnricher
from guard_core.models import SecurityConfig


def _mk_context() -> EnrichmentContext:
    return EnrichmentContext(config=SecurityConfig())


@pytest.mark.asyncio
async def test_enrich_event_returns_early_when_metadata_is_missing() -> None:
    enricher = EventEnricher(_mk_context())
    event = SimpleNamespace(event_type="ip_blocked")
    await enricher.enrich_event(event)


@pytest.mark.asyncio
async def test_enrich_event_does_not_raise_on_faulty_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enricher = EventEnricher(_mk_context())

    def _boom(*_: object, **__: object) -> None:
        raise RuntimeError("strategy explode")

    monkeypatch.setattr(enricher, "_apply_identity", _boom)
    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    await enricher.enrich_event(event)


@pytest.mark.asyncio
async def test_enrich_metric_returns_early_when_tags_is_missing() -> None:
    enricher = EventEnricher(_mk_context())
    metric = SimpleNamespace(metric_type="response_time")
    await enricher.enrich_metric(metric)


@pytest.mark.asyncio
async def test_enrich_metric_does_not_raise_on_faulty_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enricher = EventEnricher(_mk_context())

    def _boom(*_: object, **__: object) -> None:
        raise RuntimeError("strategy explode")

    monkeypatch.setattr(enricher, "_apply_identity", _boom)
    metric = SimpleNamespace(metric_type="response_time", tags={})
    await enricher.enrich_metric(metric)


@pytest.mark.asyncio
async def test_enrich_event_catches_exceptions_from_late_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enricher = EventEnricher(_mk_context())

    async def _boom(*_: object, **__: object) -> None:
        raise RuntimeError("late strategy explode")

    monkeypatch.setattr(enricher, "_apply_behavior_correlation", _boom)
    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    await enricher.enrich_event(event)


@pytest.mark.asyncio
async def test_enrichment_context_stores_all_handles() -> None:
    cfg = SecurityConfig()
    agent = object()
    rules = object()
    tracker = object()
    ctx = EnrichmentContext(
        config=cfg,
        agent_handler=agent,
        dynamic_rule_handler=rules,
        behavior_tracker=tracker,
    )
    assert ctx.config is cfg
    assert ctx.agent_handler is agent
    assert ctx.dynamic_rule_handler is rules
    assert ctx.behavior_tracker is tracker
