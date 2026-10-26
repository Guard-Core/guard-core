from types import SimpleNamespace
from typing import Any

import pytest

from guard_core.core.events.composite_handler import CompositeAgentHandler
from guard_core.core.events.event_types import EventFilter
from guard_core.models import DynamicRules
from guard_core.protocols.redis_protocol import RedisHandlerProtocol


class NullAgent:
    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        return None

    async def send_event(self, event: object) -> None:
        return None

    async def send_metric(self, metric: object) -> None:
        return None

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def flush_buffer(self) -> None:
        return None

    async def get_dynamic_rules(self) -> DynamicRules | None:
        return None

    async def health_check(self) -> bool:
        return True


class _RecorderHandler(NullAgent):
    def __init__(self) -> None:
        self.events: list[Any] = []
        self.metrics: list[Any] = []

    async def send_event(self, event: object) -> None:
        self.events.append(event)

    async def send_metric(self, metric: object) -> None:
        self.metrics.append(metric)


class _StampEnricher:
    def __init__(self) -> None:
        self.events_seen: list[object] = []
        self.metrics_seen: list[object] = []

    async def enrich_event(self, event: Any) -> None:
        self.events_seen.append(event)
        event.metadata["enriched"] = True

    async def enrich_metric(self, metric: Any) -> None:
        self.metrics_seen.append(metric)
        metric.tags["enriched"] = "true"


@pytest.mark.asyncio
async def test_composite_invokes_enricher_before_fanout_on_event() -> None:
    inner = _RecorderHandler()
    enricher = _StampEnricher()
    composite = CompositeAgentHandler([inner], enricher=enricher)

    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    await composite.send_event(event)

    assert enricher.events_seen == [event]
    assert inner.events[0].metadata["enriched"] is True


@pytest.mark.asyncio
async def test_composite_invokes_enricher_before_fanout_on_metric() -> None:
    inner = _RecorderHandler()
    enricher = _StampEnricher()
    composite = CompositeAgentHandler([inner], enricher=enricher)

    metric = SimpleNamespace(metric_type="response_time", tags={"endpoint": "/x"})
    await composite.send_metric(metric)

    assert enricher.metrics_seen == [metric]
    assert inner.metrics[0].tags["enriched"] == "true"


@pytest.mark.asyncio
async def test_composite_skips_enrichment_when_event_muted() -> None:
    inner = _RecorderHandler()
    enricher = _StampEnricher()
    composite = CompositeAgentHandler(
        [inner],
        event_filter=EventFilter(muted_event_types=frozenset({"ip_blocked"})),
        enricher=enricher,
    )

    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    await composite.send_event(event)

    assert enricher.events_seen == []
    assert inner.events == []


@pytest.mark.asyncio
async def test_composite_skips_enrichment_when_metric_muted() -> None:
    inner = _RecorderHandler()
    enricher = _StampEnricher()
    composite = CompositeAgentHandler(
        [inner],
        event_filter=EventFilter(muted_metric_types=frozenset({"response_time"})),
        enricher=enricher,
    )

    metric = SimpleNamespace(metric_type="response_time", tags={})
    await composite.send_metric(metric)

    assert enricher.metrics_seen == []
    assert inner.metrics == []


@pytest.mark.asyncio
async def test_composite_without_enricher_still_fans_out() -> None:
    inner = _RecorderHandler()
    composite = CompositeAgentHandler([inner])

    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    await composite.send_event(event)

    assert inner.events == [event]
