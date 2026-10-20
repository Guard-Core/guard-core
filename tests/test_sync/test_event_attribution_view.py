import ipaddress
import time

from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.handlers._dynamic_rule_attribution import build_rule_attribution
from guard_core.sync.handlers._ipban_cache import _OperatorNetworks
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from tests.test_event_attribution import DYNAMIC, OTHER_IP, RULE_IP, _config, _rules


def test_the_view_ignores_what_it_cannot_parse_or_does_not_own() -> None:
    config = _config(rate_limit=100)
    rules = _rules(ip_blacklist=[RULE_IP], global_rate_limit=5)
    view = build_rule_attribution(rules, config, ["not-an-address", RULE_IP], [], {})

    assert view.for_ban("unknown", ip_ban_manager) == {}
    assert view.for_ban(OTHER_IP, ip_ban_manager) == {}
    assert view.for_rate_limit_tier("route", "/x") == {}
    assert view.for_rate_limit_tier("global", "") == DYNAMIC
    assert view.for_cloud_provider("AWS", None) == {}
    assert view.for_pattern(None) == {}
    assert view.for_user_agent_pattern(None) == {}
    assert view.for_country("country_whitelist", "CN") == {}
    assert view.for_emergency_mode() == {}


def test_a_detection_without_an_id_or_a_category_adds_no_event_fields() -> None:
    result = DetectionResult(is_threat=True, trigger_info="x")

    assert SuspiciousActivityCheck._detection_event_fields(result) == {}


def test_the_deciding_ban_entry_follows_the_order_of_the_lookup() -> None:
    now = time.time()
    ip_ban_manager.config = _config()
    ip_ban_manager.banned_networks = [
        (ipaddress.ip_network("198.51.100.0/24"), now + 90)
    ]
    ip_ban_manager.banned_ips["198.51.100.7"] = now + 50
    ip_ban_manager.banned_ips["2001:db8:0:1::/64"] = now + 70
    ip_ban_manager._operator_networks = _OperatorNetworks(
        {ipaddress.ip_network("203.0.113.0/24"): now + 80}
    )

    assert ip_ban_manager.deciding_ban_entry("198.51.100.7") == (
        "banned_ips:198.51.100.7",
        now + 50,
    )
    assert ip_ban_manager.deciding_ban_entry("198.51.100.8") == (
        "banned_networks:198.51.100.0/24",
        now + 90,
    )
    assert ip_ban_manager.deciding_ban_entry("2001:db8:0:1::5") == (
        "banned_identities:2001:db8:0:1::/64",
        now + 70,
    )
    assert ip_ban_manager.deciding_ban_entry("203.0.113.9") == (
        "banned_networks:203.0.113.0/24",
        now + 80,
    )
    assert ip_ban_manager.deciding_ban_entry("192.0.2.1") is None
    assert ip_ban_manager.deciding_ban_entry("unknown") is None


def test_the_view_still_exposes_the_owned_networks_and_provider_names() -> None:
    rules = _rules(blocked_cloud_providers={"AWS", "GCP:!us-central1"})
    config = _config(block_cloud_providers={"Azure"})
    view = build_rule_attribution(
        rules,
        config,
        [RULE_IP, "198.51.100.0/24"],
        [],
        {"block_cloud_providers": {"Azure"}},
    )

    assert {str(n) for n in view.ban_networks} == {RULE_IP + "/32", "198.51.100.0/24"}
    assert view.cloud_providers == {"AWS", "GCP"}
    assert view.static_cloud_providers == {"Azure"}
