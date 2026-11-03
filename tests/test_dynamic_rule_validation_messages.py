from datetime import datetime, timezone
from typing import Any

import pytest

from guard_core.handlers._dynamic_rule_validation import (
    MalformedDynamicRules,
    endpoint_rate_limit_key_problems,
    find_malformed_values,
)
from guard_core.models import DynamicRules


def _rules(**overrides: object) -> DynamicRules:
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


def test_an_anomalous_endpoint_key_is_reported_with_its_key_and_reason() -> None:
    rules = _rules(
        endpoint_rate_limits={
            "/a/../b": (5, 60),
            "/ok": (5, 60),
            "/a%2fb": (0, 60),
            "/downloads/file..txt": (5, 60),
        }
    )

    assert find_malformed_values(rules) == [
        "endpoint_rate_limits[/a%2fb]: (0, 60) (requests and window must be at "
        "least 1)",
        "endpoint_rate_limits[/a/../b]: (5, 60) (a dot segment, an empty segment, a "
        "backslash or an encoded dot or separator, in any decoding round)",
        "endpoint_rate_limits[/a%2fb]: (0, 60) (a dot segment, an empty segment, a "
        "backslash or an encoded dot or separator, in any decoding round)",
    ]


def test_the_public_predicate_gives_the_lines_find_malformed_values_gives() -> None:
    limits = {
        "/a/../b": (5, 60),
        "/ok": (5, 60),
        "/a%2fb": (0, 60),
        "/downloads/file..txt": (5, 60),
    }
    lines = endpoint_rate_limit_key_problems(limits)

    assert lines == [
        line
        for line in find_malformed_values(_rules(endpoint_rate_limits=limits))
        if "a dot segment" in line
    ]
    assert len(lines) == 2


@pytest.mark.parametrize(
    "key",
    ["/%2e%2e/admin", "/%252e%252e/admin", "/a\\b", "/a//b"],
)
def test_the_public_predicate_refuses_every_anomalous_spelling(key: str) -> None:
    lines = endpoint_rate_limit_key_problems({key: (5, 60)})

    assert lines == [
        f"endpoint_rate_limits[{key}]: (5, 60) (a dot segment, an empty segment, a "
        "backslash or an encoded dot or separator, in any decoding round)"
    ]


def test_the_public_predicate_accepts_a_plain_key() -> None:
    assert endpoint_rate_limit_key_problems({"/api/users": (5, 60)}) == []


@pytest.mark.parametrize("duration", [0, -5])
def test_a_non_positive_ip_ban_duration_is_a_malformed_value(duration: int) -> None:
    rules = _rules(ip_blacklist=["203.0.113.9"], ip_ban_duration=duration)

    assert find_malformed_values(rules) == [
        f"ip_ban_duration: {duration} (must be at least 1)"
    ]


def test_a_positive_ip_ban_duration_is_accepted() -> None:
    assert find_malformed_values(_rules(ip_ban_duration=1)) == []
