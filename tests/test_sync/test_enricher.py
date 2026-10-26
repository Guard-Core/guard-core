from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events.enricher import EnrichmentContext, EventEnricher


def _mk_context() -> EnrichmentContext:
    return EnrichmentContext(config=SyncSecurityConfig())


def test_enrich_event_returns_early_when_metadata_is_missing() -> None:
    enricher = EventEnricher(_mk_context())
    event = SimpleNamespace(event_type="ip_blocked")
    enricher.enrich_event(event)


def test_enrich_event_does_not_raise_on_faulty_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enricher = EventEnricher(_mk_context())

    def _boom(*_: object, **__: object) -> None:
        raise RuntimeError("strategy explode")

    monkeypatch.setattr(enricher, "_apply_identity", _boom)
    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    enricher.enrich_event(event)


def test_enrich_metric_returns_early_when_tags_is_missing() -> None:
    enricher = EventEnricher(_mk_context())
    metric = SimpleNamespace(metric_type="response_time")
    enricher.enrich_metric(metric)


def test_enrich_metric_does_not_raise_on_faulty_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enricher = EventEnricher(_mk_context())

    def _boom(*_: object, **__: object) -> None:
        raise RuntimeError("strategy explode")

    monkeypatch.setattr(enricher, "_apply_identity", _boom)
    metric = SimpleNamespace(metric_type="response_time", tags={})
    enricher.enrich_metric(metric)


def test_enrich_event_catches_exceptions_from_late_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enricher = EventEnricher(_mk_context())

    def _boom(*_: object, **__: object) -> None:
        raise RuntimeError("late strategy explode")

    monkeypatch.setattr(enricher, "_apply_behavior_correlation", _boom)
    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    enricher.enrich_event(event)


def test_enrichment_context_stores_all_handles() -> None:
    cfg = SyncSecurityConfig()
    agent = MagicMock()
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
