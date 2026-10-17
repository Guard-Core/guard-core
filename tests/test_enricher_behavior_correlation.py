import time
from types import SimpleNamespace

import pytest

from guard_core.core.events.enricher import EnrichmentContext, EventEnricher
from guard_core.handlers.behavior_handler import BehaviorTracker
from guard_core.models import SecurityConfig


def _tracker_with_events(ip: str, count: int, offsets: list[float]) -> BehaviorTracker:
    tracker = BehaviorTracker(SecurityConfig())
    now = time.time()
    tracker.recent_requests[ip] = [now + offsets[i] for i in range(count)]
    return tracker


def _enricher(tracker: BehaviorTracker | None) -> EventEnricher:
    return EventEnricher(
        EnrichmentContext(
            config=SecurityConfig(otel_service_name="svc-1"),
            behavior_tracker=tracker,
        )
    )


async def test_get_recent_event_count_returns_zero_for_empty_tracker() -> None:
    tracker = BehaviorTracker(SecurityConfig())
    assert await tracker.get_recent_event_count("1.2.3.4", 300) == 0


async def test_get_recent_event_count_returns_zero_for_empty_ip() -> None:
    tracker = BehaviorTracker(SecurityConfig())
    assert await tracker.get_recent_event_count("", 300) == 0


async def test_get_recent_event_count_counts_recorded_requests() -> None:
    tracker = _tracker_with_events("1.2.3.4", 3, [-10, -20, -30])
    assert await tracker.get_recent_event_count("1.2.3.4", 300) == 3


async def test_get_recent_event_count_excludes_timestamps_outside_window() -> None:
    tracker = _tracker_with_events("1.2.3.4", 3, [-10, -600, -700])
    assert await tracker.get_recent_event_count("1.2.3.4", 300) == 1


@pytest.mark.asyncio
async def test_enrich_event_attaches_behavior_correlation_key_and_count() -> None:
    tracker = _tracker_with_events("1.2.3.4", 2, [-10, -20])
    enricher = _enricher(tracker)
    event = SimpleNamespace(
        event_type="penetration_attempt", ip_address="1.2.3.4", metadata={}
    )
    await enricher.enrich_event(event)

    assert event.metadata["guard.behavior.recent_event_count"] == 2
    key = event.metadata["guard.behavior.correlation_key"]
    assert isinstance(key, str)
    assert len(key) == 16


@pytest.mark.asyncio
async def test_enrich_event_same_ip_same_window_yields_same_key() -> None:
    tracker = _tracker_with_events("1.2.3.4", 1, [-5])
    enricher = _enricher(tracker)

    event1 = SimpleNamespace(event_type="ip_blocked", ip_address="1.2.3.4", metadata={})
    event2 = SimpleNamespace(
        event_type="rate_limited", ip_address="1.2.3.4", metadata={}
    )
    await enricher.enrich_event(event1)
    await enricher.enrich_event(event2)

    assert (
        event1.metadata["guard.behavior.correlation_key"]
        == event2.metadata["guard.behavior.correlation_key"]
    )


@pytest.mark.asyncio
async def test_enrich_event_different_ips_yield_different_keys() -> None:
    tracker = BehaviorTracker(SecurityConfig())
    enricher = _enricher(tracker)

    event1 = SimpleNamespace(event_type="ip_blocked", ip_address="1.1.1.1", metadata={})
    event2 = SimpleNamespace(event_type="ip_blocked", ip_address="2.2.2.2", metadata={})
    await enricher.enrich_event(event1)
    await enricher.enrich_event(event2)

    assert (
        event1.metadata["guard.behavior.correlation_key"]
        != event2.metadata["guard.behavior.correlation_key"]
    )


@pytest.mark.asyncio
async def test_enrich_event_skips_behavior_fields_when_no_tracker() -> None:
    enricher = _enricher(None)
    event = SimpleNamespace(event_type="ip_blocked", ip_address="1.2.3.4", metadata={})
    await enricher.enrich_event(event)
    assert "guard.behavior.correlation_key" not in event.metadata
    assert "guard.behavior.recent_event_count" not in event.metadata


@pytest.mark.asyncio
async def test_enrich_event_skips_behavior_fields_when_ip_missing() -> None:
    tracker = BehaviorTracker(SecurityConfig())
    enricher = _enricher(tracker)
    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    await enricher.enrich_event(event)
    assert "guard.behavior.correlation_key" not in event.metadata


@pytest.mark.asyncio
async def test_enrich_event_skips_behavior_when_tracker_lacks_method() -> None:
    enricher = EventEnricher(
        EnrichmentContext(config=SecurityConfig(), behavior_tracker=object())
    )
    event = SimpleNamespace(event_type="ip_blocked", ip_address="1.2.3.4", metadata={})
    await enricher.enrich_event(event)
    assert "guard.behavior.correlation_key" not in event.metadata
