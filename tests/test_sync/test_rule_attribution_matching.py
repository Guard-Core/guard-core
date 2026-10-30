from datetime import datetime, timezone
from types import SimpleNamespace

from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager


def _manager() -> DynamicRuleManager:
    manager = DynamicRuleManager(SyncSecurityConfig(enable_redis=False))
    manager.current_rules = DynamicRules(
        rule_id="r1",
        version=3,
        timestamp=datetime.now(timezone.utc),
        blocked_countries=["us"],
        ip_blacklist=["203.0.113.0/24", "198.51.100.7"],
    )
    return manager


def _event(**fields: object) -> SimpleNamespace:
    return SimpleNamespace(
        **{"country": None, "ip_address": None, "event_type": "x", **fields}
    )


def test_a_country_matches_whatever_the_case_of_either_side() -> None:
    manager = _manager()

    assert manager.match_event(_event(country="US")) == ("r1", 3)
    assert manager.match_event(_event(country="us")) == ("r1", 3)
    assert manager.match_event(_event(country="DE")) is None


def test_an_ip_inside_a_listed_cidr_matches() -> None:
    manager = _manager()

    assert manager.match_event(_event(ip_address="203.0.113.9")) == ("r1", 3)
    assert manager.match_event(_event(ip_address="198.51.100.7")) == ("r1", 3)
    assert manager.match_event(_event(ip_address="203.0.114.9")) is None


def test_an_unparseable_event_address_does_not_raise() -> None:
    assert _manager().match_event(_event(ip_address="not-an-ip")) is None
