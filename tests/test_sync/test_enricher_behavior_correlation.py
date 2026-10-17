import time
from types import SimpleNamespace

from guard_core.models import SecurityConfig
from guard_core.sync.core.events.enricher import EnrichmentContext, EventEnricher
from guard_core.sync.handlers.behavior_handler import BehaviorTracker


def _tracker_with_events(ip: str, count: int, offsets: list[float]) -> BehaviorTracker:
    tracker = BehaviorTracker(SecurityConfig())
    now = time.time()
    for i in range(count):
        endpoint = f"endpoint-{i % 2}"
        tracker.usage_counts[endpoint][ip].append(now + offsets[i])
    return tracker


def _enricher(tracker: BehaviorTracker | None) -> EventEnricher:
    return EventEnricher(
        EnrichmentContext(
            config=SecurityConfig(otel_service_name="svc-1"),
            behavior_tracker=tracker,
        )
    )


def test_get_recent_event_count_returns_zero_for_empty_tracker() -> None:
    tracker = BehaviorTracker(SecurityConfig())
    assert tracker.get_recent_event_count("1.2.3.4", 300) == 0


def test_get_recent_event_count_returns_zero_for_empty_ip() -> None:
    tracker = BehaviorTracker(SecurityConfig())
    assert tracker.get_recent_event_count("", 300) == 0


def test_get_recent_event_count_sums_across_endpoints() -> None:
    tracker = _tracker_with_events("1.2.3.4", 3, [-10, -20, -30])
    assert tracker.get_recent_event_count("1.2.3.4", 300) == 3


def test_get_recent_event_count_excludes_timestamps_outside_window() -> None:
    tracker = _tracker_with_events("1.2.3.4", 3, [-10, -600, -700])
    assert tracker.get_recent_event_count("1.2.3.4", 300) == 1


def test_count_recent_rule_hits_in_memory_is_the_sync_count() -> None:
    tracker = _tracker_with_events("1.2.3.4", 3, [-10, -20, -600])
    assert tracker.count_recent_rule_hits("1.2.3.4", 300) == 2
    assert tracker.count_recent_rule_hits("", 300) == 0


def test_enrich_event_attaches_behavior_correlation_key_and_count() -> None:
    tracker = _tracker_with_events("1.2.3.4", 2, [-10, -20])
    enricher = _enricher(tracker)
    event = SimpleNamespace(
        event_type="penetration_attempt", ip_address="1.2.3.4", metadata={}
    )
    enricher.enrich_event(event)

    assert event.metadata["guard.behavior.recent_event_count"] == 2
    key = event.metadata["guard.behavior.correlation_key"]
    assert isinstance(key, str)
    assert len(key) == 16


def test_enrich_event_same_ip_same_window_yields_same_key() -> None:
    tracker = _tracker_with_events("1.2.3.4", 1, [-5])
    enricher = _enricher(tracker)

    event1 = SimpleNamespace(event_type="ip_blocked", ip_address="1.2.3.4", metadata={})
    event2 = SimpleNamespace(
        event_type="rate_limited", ip_address="1.2.3.4", metadata={}
    )
    enricher.enrich_event(event1)
    enricher.enrich_event(event2)

    assert (
        event1.metadata["guard.behavior.correlation_key"]
        == event2.metadata["guard.behavior.correlation_key"]
    )


def test_enrich_event_different_ips_yield_different_keys() -> None:
    tracker = BehaviorTracker(SecurityConfig())
    enricher = _enricher(tracker)

    event1 = SimpleNamespace(event_type="ip_blocked", ip_address="1.1.1.1", metadata={})
    event2 = SimpleNamespace(event_type="ip_blocked", ip_address="2.2.2.2", metadata={})
    enricher.enrich_event(event1)
    enricher.enrich_event(event2)

    assert (
        event1.metadata["guard.behavior.correlation_key"]
        != event2.metadata["guard.behavior.correlation_key"]
    )


def test_enrich_event_skips_behavior_fields_when_no_tracker() -> None:
    enricher = _enricher(None)
    event = SimpleNamespace(event_type="ip_blocked", ip_address="1.2.3.4", metadata={})
    enricher.enrich_event(event)
    assert "guard.behavior.correlation_key" not in event.metadata
    assert "guard.behavior.recent_event_count" not in event.metadata


def test_enrich_event_skips_behavior_fields_when_ip_missing() -> None:
    tracker = BehaviorTracker(SecurityConfig())
    enricher = _enricher(tracker)
    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    enricher.enrich_event(event)
    assert "guard.behavior.correlation_key" not in event.metadata


def test_enrich_event_skips_behavior_when_tracker_lacks_method() -> None:
    enricher = EventEnricher(
        EnrichmentContext(config=SecurityConfig(), behavior_tracker=object())
    )
    event = SimpleNamespace(event_type="ip_blocked", ip_address="1.2.3.4", metadata={})
    enricher.enrich_event(event)
    assert "guard.behavior.correlation_key" not in event.metadata


class _SyncOnlyTracker:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def get_recent_event_count(self, ip: str, window_seconds: int) -> int:
        self.calls.append((ip, window_seconds))
        return 7


def test_enrich_event_reads_a_tracker_with_only_the_sync_method() -> None:
    tracker = _SyncOnlyTracker()
    enricher = EventEnricher(
        EnrichmentContext(config=SecurityConfig(), behavior_tracker=tracker)
    )
    event = SimpleNamespace(event_type="ip_blocked", ip_address="1.2.3.4", metadata={})
    enricher.enrich_event(event)
    assert event.metadata["guard.behavior.recent_event_count"] == 7
    assert tracker.calls == [("1.2.3.4", 300)]
    assert len(event.metadata["guard.behavior.correlation_key"]) == 16
