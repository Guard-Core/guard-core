from datetime import datetime, timezone
from typing import Any

from guard_core.handlers._dynamic_rule_validation import (
    MalformedDynamicRules,
    find_malformed_values,
)
from guard_core.models import DynamicRules


def _rules(**overrides: Any) -> DynamicRules:
    base: dict[str, Any] = {
        "rule_id": "R",
        "version": 1,
        "timestamp": datetime.now(timezone.utc),
    }
    base.update(overrides)
    return DynamicRules(**base)


def test_every_malformed_value_is_reported_with_its_field_and_reason() -> None:
    rules = _rules(
        global_rate_limit=0,
        global_rate_window=-3,
        endpoint_rate_limits={"/x": (0, 5)},
        blocked_countries=["USA"],
        whitelist_countries=["1"],
        blocked_cloud_providers={"Nope"},
        ip_blacklist=["bad-ban"],
        ip_whitelist=["bad-allow"],
        emergency_whitelist=["bad-emergency"],
    )

    assert find_malformed_values(rules) == [
        "ip_blacklist: 'bad-ban' (not an IP address or CIDR range)",
        "ip_whitelist: 'bad-allow' (not an IP address or CIDR range)",
        "emergency_whitelist: 'bad-emergency' (not an IP address or CIDR range)",
        "global_rate_limit: 0 (must be at least 1)",
        "global_rate_window: -3 (must be at least 1)",
        "endpoint_rate_limits[/x]: (0, 5) (requests and window must be at least 1)",
        "blocked_countries: 'USA' (not a two-letter country code)",
        "whitelist_countries: '1' (not a two-letter country code)",
        "blocked_cloud_providers: 'Nope' (unknown cloud provider)",
    ]


def test_boundary_values_and_host_bits_are_well_formed() -> None:
    rules = _rules(
        global_rate_limit=1,
        global_rate_window=1,
        endpoint_rate_limits={"/x": (1, 1)},
        blocked_countries=["ru", "DE"],
        whitelist_countries=["us"],
        blocked_cloud_providers={"azure", "AWS:!us-east-1"},
        ip_blacklist=["198.51.100.7/24", "2001:db8::1"],
        ip_whitelist=["10.0.0.1"],
        emergency_whitelist=["::1"],
    )
    assert find_malformed_values(rules) == []


def test_the_exception_joins_the_problems_and_keeps_the_list() -> None:
    error = MalformedDynamicRules(["a", "b"])
    assert str(error) == "a; b"
    assert error.problems == ["a", "b"]
