from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.handlers._dynamic_rule_attribution import build_rule_attribution
from tests.test_event_attribution import DYNAMIC, OTHER_IP, RULE_IP, _config, _rules


def test_the_view_ignores_what_it_cannot_parse_or_does_not_own() -> None:
    config = _config(rate_limit=100)
    rules = _rules(ip_blacklist=[RULE_IP], global_rate_limit=5)
    view = build_rule_attribution(rules, config, ["not-an-address", RULE_IP], [], {})

    assert view.for_ban("unknown") == {}
    assert view.for_ban(OTHER_IP) == {}
    assert view.for_ban(RULE_IP) == DYNAMIC
    assert view.for_rate_limit_tier("route", "/x") == {}
    assert view.for_rate_limit_tier("global", "") == DYNAMIC
    assert view.for_cloud_provider("AWS") == {}
    assert view.for_pattern(None) == {}
    assert view.for_user_agent_pattern(None) == {}
    assert view.for_country("country_whitelist", "CN") == {}
    assert view.for_emergency_mode() == {}


def test_a_detection_without_an_id_or_a_category_adds_no_event_fields() -> None:
    result = DetectionResult(is_threat=True, trigger_info="x")

    assert SuspiciousActivityCheck._detection_event_fields(result) == {}
