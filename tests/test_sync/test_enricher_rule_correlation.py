from datetime import datetime, timezone
from types import SimpleNamespace

from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync.core.events.enricher import EnrichmentContext, EventEnricher
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager


def _rules(**overrides: object) -> DynamicRules:
    defaults: dict[str, object] = {
        "rule_id": "rule-42",
        "version": 3,
        "timestamp": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return DynamicRules(**defaults)


def _manager_with(rules: DynamicRules | None) -> DynamicRuleManager:
    DynamicRuleManager._instance = None
    mgr = DynamicRuleManager(SyncSecurityConfig())
    mgr.current_rules = rules
    return mgr


def _enricher(rule_handler: DynamicRuleManager) -> EventEnricher:
    return EventEnricher(
        EnrichmentContext(
            config=SyncSecurityConfig(), dynamic_rule_handler=rule_handler
        )
    )


def test_match_event_returns_none_when_no_current_rules() -> None:
    mgr = _manager_with(None)
    assert mgr.match_event(SimpleNamespace(event_type="ip_blocked")) is None


def test_match_event_matches_ip_blacklist() -> None:
    mgr = _manager_with(_rules(ip_blacklist=["1.2.3.4"]))
    match = mgr.match_event(
        SimpleNamespace(event_type="ip_blocked", ip_address="1.2.3.4")
    )
    assert match == ("rule-42", 3)


def test_match_event_matches_ip_whitelist() -> None:
    mgr = _manager_with(_rules(ip_whitelist=["9.9.9.9"]))
    match = mgr.match_event(
        SimpleNamespace(event_type="access_denied", ip_address="9.9.9.9")
    )
    assert match == ("rule-42", 3)


def test_match_event_matches_blocked_country() -> None:
    mgr = _manager_with(_rules(blocked_countries=["KP"]))
    match = mgr.match_event(
        SimpleNamespace(
            event_type="country_blocked", ip_address="1.1.1.1", country="KP"
        )
    )
    assert match == ("rule-42", 3)


def test_match_event_matches_rate_limited_when_global_rate_limit_set() -> None:
    mgr = _manager_with(_rules(global_rate_limit=100))
    match = mgr.match_event(
        SimpleNamespace(event_type="rate_limited", ip_address="1.1.1.1")
    )
    assert match == ("rule-42", 3)


def test_match_event_matches_rate_limited_when_endpoint_rate_limits_set() -> None:
    mgr = _manager_with(_rules(endpoint_rate_limits={"/api": (10, 60)}))
    match = mgr.match_event(SimpleNamespace(event_type="rate_limited"))
    assert match == ("rule-42", 3)


def test_match_event_matches_cloud_blocked() -> None:
    mgr = _manager_with(_rules(blocked_cloud_providers={"AWS"}))
    match = mgr.match_event(SimpleNamespace(event_type="cloud_blocked"))
    assert match == ("rule-42", 3)


def test_match_event_matches_user_agent_blocked() -> None:
    mgr = _manager_with(_rules(blocked_user_agents=["badbot"]))
    match = mgr.match_event(SimpleNamespace(event_type="user_agent_blocked"))
    assert match == ("rule-42", 3)


def test_match_event_returns_none_when_nothing_matches() -> None:
    mgr = _manager_with(_rules(ip_blacklist=["1.2.3.4"]))
    match = mgr.match_event(
        SimpleNamespace(event_type="ip_blocked", ip_address="5.5.5.5")
    )
    assert match is None


def test_enrich_event_populates_rule_id_and_version() -> None:
    mgr = _manager_with(_rules(ip_blacklist=["1.2.3.4"]))
    enricher = _enricher(mgr)
    event = SimpleNamespace(event_type="ip_blocked", ip_address="1.2.3.4", metadata={})
    enricher.enrich_event(event)
    assert event.metadata["guard.rule.id"] == "rule-42"
    assert event.metadata["guard.rule.version"] == 3


def test_enrich_event_skips_rule_fields_when_no_handler() -> None:
    enricher = EventEnricher(EnrichmentContext(config=SyncSecurityConfig()))
    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    enricher.enrich_event(event)
    assert "guard.rule.id" not in event.metadata


def test_enrich_event_skips_rule_fields_when_handler_has_no_match_event() -> None:
    enricher = EventEnricher(
        EnrichmentContext(config=SyncSecurityConfig(), dynamic_rule_handler=object())
    )
    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    enricher.enrich_event(event)
    assert "guard.rule.id" not in event.metadata


def test_enrich_event_skips_rule_fields_when_no_match() -> None:
    mgr = _manager_with(_rules())
    enricher = _enricher(mgr)
    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    enricher.enrich_event(event)
    assert "guard.rule.id" not in event.metadata
