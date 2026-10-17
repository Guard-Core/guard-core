from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.core.events.composite_handler import CompositeAgentHandler
from guard_core.sync.core.events.enricher import EnrichmentContext, EventEnricher
from guard_core.sync.core.events.event_types import EventFilter
from guard_core.sync.handlers.behavior_handler import BehaviorTracker
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager


class _Recorder:
    def __init__(self) -> None:
        self.events: list[Any] = []
        self.metrics: list[Any] = []

    def send_event(self, event: Any) -> None:
        self.events.append(event)

    def send_metric(self, metric: Any) -> None:
        self.metrics.append(metric)


def test_end_to_end_enrichment_on_event_through_composite() -> None:
    DynamicRuleManager._instance = None
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="a" * 10,
        agent_project_id="proj-e2e",
        enable_enrichment=True,
        otel_service_name="api-e2e",
        otel_resource_attributes={"deployment.environment": "prod"},
    )
    rules = DynamicRules(
        rule_id="rule-abc",
        version=7,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=["1.2.3.4"],
    )
    rule_handler = DynamicRuleManager(config)
    rule_handler.current_rules = rules
    tracker = BehaviorTracker(config)
    tracker.usage_counts["/api"]["1.2.3.4"].append(9999999999.0)

    enricher = EventEnricher(
        EnrichmentContext(
            config=config,
            dynamic_rule_handler=rule_handler,
            behavior_tracker=tracker,
        )
    )
    recorder = _Recorder()
    composite = CompositeAgentHandler(
        [recorder], event_filter=EventFilter(), enricher=enricher
    )

    event = SimpleNamespace(event_type="ip_blocked", ip_address="1.2.3.4", metadata={})
    composite.send_event(event)

    (stored,) = recorder.events
    meta = stored.metadata
    assert meta["guard.project_id"] == "proj-e2e"
    assert meta["guard.service.name"] == "api-e2e"
    assert meta["guard.deployment.environment"] == "prod"
    assert meta["guard.threat_score"] == 50
    assert meta["guard.rule.id"] == "rule-abc"
    assert meta["guard.rule.version"] == 7
    assert meta["guard.behavior.recent_event_count"] == 1
    assert isinstance(meta["guard.behavior.correlation_key"], str)
    assert len(meta["guard.behavior.correlation_key"]) == 16


def test_end_to_end_enrichment_on_metric_through_composite() -> None:
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="a" * 10,
        agent_project_id="proj-metric",
        enable_enrichment=True,
        otel_service_name="api-metric",
        otel_resource_attributes={"deployment.environment": "staging"},
    )
    enricher = EventEnricher(EnrichmentContext(config=config))
    recorder = _Recorder()
    composite = CompositeAgentHandler(
        [recorder], event_filter=EventFilter(), enricher=enricher
    )

    metric = SimpleNamespace(
        metric_type="response_time", tags={"endpoint": "/api", "method": "GET"}
    )
    composite.send_metric(metric)

    (stored,) = recorder.metrics
    tags = stored.tags
    assert tags["endpoint"] == "/api"
    assert tags["method"] == "GET"
    assert tags["guard.project_id"] == "proj-metric"
    assert tags["guard.service.name"] == "api-metric"
    assert tags["guard.deployment.environment"] == "staging"


def test_muted_event_is_not_enriched_or_dispatched() -> None:
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="a" * 10,
        enable_enrichment=True,
        muted_event_types={"ip_blocked"},
    )
    enricher = EventEnricher(EnrichmentContext(config=config))
    recorder = _Recorder()
    composite = CompositeAgentHandler(
        [recorder],
        event_filter=EventFilter(muted_event_types=frozenset({"ip_blocked"})),
        enricher=enricher,
    )

    event = SimpleNamespace(event_type="ip_blocked", ip_address="1.2.3.4", metadata={})
    composite.send_event(event)

    assert recorder.events == []
    assert event.metadata == {}
