from types import SimpleNamespace

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events.enricher import (
    EnrichmentContext,
    EventEnricher,
    ThreatScorer,
)


def _enricher() -> EventEnricher:
    return EventEnricher(EnrichmentContext(config=SyncSecurityConfig()))


def test_threat_scorer_critical_events() -> None:
    assert ThreatScorer.score_for("penetration_attempt") == 90


def test_threat_scorer_high_events() -> None:
    assert ThreatScorer.score_for("ip_banned") == 70


def test_threat_scorer_medium_events() -> None:
    for et in (
        "ip_blocked",
        "behavioral_violation",
        "cloud_blocked",
        "country_blocked",
        "decorator_violation",
        "authentication_failed",
        "emergency_mode_block",
        "pattern_detected",
    ):
        assert ThreatScorer.score_for(et) == 50, et


def test_threat_scorer_low_events() -> None:
    assert ThreatScorer.score_for("rate_limited") == 20
    assert ThreatScorer.score_for("access_denied") == 30
    assert ThreatScorer.score_for("user_agent_blocked") == 30


def test_threat_scorer_unknown_event_type_defaults_to_20() -> None:
    assert ThreatScorer.score_for("completely_novel_event") == 20


def test_enrich_event_populates_threat_score() -> None:
    enricher = _enricher()
    event = SimpleNamespace(event_type="penetration_attempt", metadata={})
    enricher.enrich_event(event)
    assert event.metadata["guard.threat_score"] == 90


def test_enrich_event_skips_threat_score_when_event_type_missing() -> None:
    enricher = _enricher()
    event = SimpleNamespace(metadata={})
    enricher.enrich_event(event)
    assert "guard.threat_score" not in event.metadata


def test_enrich_event_unknown_type_gets_default_score() -> None:
    enricher = _enricher()
    event = SimpleNamespace(event_type="unknown_type_here", metadata={})
    enricher.enrich_event(event)
    assert event.metadata["guard.threat_score"] == 20
