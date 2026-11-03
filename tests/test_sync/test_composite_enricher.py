from types import SimpleNamespace
from typing import Any

from guard_core.models import DynamicRules
from guard_core.protocols.agent_protocol import JsonValue
from guard_core.sync.core.events.composite_handler import CompositeAgentHandler
from guard_core.sync.core.events.event_types import EventFilter
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol


class NullAgent:
    def initialize_redis(self, redis_handler: SyncRedisHandlerProtocol) -> None:
        return None

    def send_event(self, event: object) -> None:
        return None

    def send_metric(self, metric: object) -> None:
        return None

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def flush_buffer(self) -> None:
        return None

    def get_dynamic_rules(self) -> DynamicRules | None:
        return None

    def get_stats(self) -> dict[str, JsonValue]:
        return {}

    def health_check(self) -> bool:
        return True


class _RecorderHandler(NullAgent):
    def __init__(self) -> None:
        self.events: list[Any] = []
        self.metrics: list[Any] = []

    def send_event(self, event: object) -> None:
        self.events.append(event)

    def send_metric(self, metric: object) -> None:
        self.metrics.append(metric)


class _StampEnricher:
    def __init__(self) -> None:
        self.events_seen: list[object] = []
        self.metrics_seen: list[object] = []

    def enrich_event(self, event: object) -> None:
        assert isinstance(event, SimpleNamespace)
        self.events_seen.append(event)
        event.metadata["enriched"] = True

    def enrich_metric(self, metric: object) -> None:
        assert isinstance(metric, SimpleNamespace)
        self.metrics_seen.append(metric)
        metric.tags["enriched"] = "true"


def test_composite_invokes_enricher_before_fanout_on_event() -> None:
    inner = _RecorderHandler()
    enricher = _StampEnricher()
    composite = CompositeAgentHandler([inner], enricher=enricher)

    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    composite.send_event(event)

    assert enricher.events_seen == [event]
    assert inner.events[0].metadata["enriched"] is True


def test_composite_invokes_enricher_before_fanout_on_metric() -> None:
    inner = _RecorderHandler()
    enricher = _StampEnricher()
    composite = CompositeAgentHandler([inner], enricher=enricher)

    metric = SimpleNamespace(metric_type="response_time", tags={"endpoint": "/x"})
    composite.send_metric(metric)

    assert enricher.metrics_seen == [metric]
    assert inner.metrics[0].tags["enriched"] == "true"


def test_composite_skips_enrichment_when_event_muted() -> None:
    inner = _RecorderHandler()
    enricher = _StampEnricher()
    composite = CompositeAgentHandler(
        [inner],
        event_filter=EventFilter(muted_event_types=frozenset({"ip_blocked"})),
        enricher=enricher,
    )

    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    composite.send_event(event)

    assert enricher.events_seen == []
    assert inner.events == []


def test_composite_skips_enrichment_when_metric_muted() -> None:
    inner = _RecorderHandler()
    enricher = _StampEnricher()
    composite = CompositeAgentHandler(
        [inner],
        event_filter=EventFilter(muted_metric_types=frozenset({"response_time"})),
        enricher=enricher,
    )

    metric = SimpleNamespace(metric_type="response_time", tags={})
    composite.send_metric(metric)

    assert enricher.metrics_seen == []
    assert inner.metrics == []


def test_composite_without_enricher_still_fans_out() -> None:
    inner = _RecorderHandler()
    composite = CompositeAgentHandler([inner])

    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    composite.send_event(event)

    assert inner.events == [event]
