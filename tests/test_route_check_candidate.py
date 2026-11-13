import pytest

from guard_core._security_config_fields import DEFAULT_EXCLUDE_PATHS
from guard_core.core.checks.route_prefixes import is_route_check_candidate


@pytest.mark.parametrize("entry", list(DEFAULT_EXCLUDE_PATHS))
def test_a_default_entry_is_not_a_candidate(entry: str) -> None:
    assert not is_route_check_candidate(entry)


def test_the_defaults_in_another_order_or_reduced_stay_non_candidates() -> None:
    reordered = list(reversed(DEFAULT_EXCLUDE_PATHS))
    assert not any(is_route_check_candidate(entry) for entry in reordered)
    assert not any(is_route_check_candidate(entry) for entry in reordered[:1])


def test_no_entries_have_no_candidates() -> None:
    entries: list[str] = []
    assert [entry for entry in entries if is_route_check_candidate(entry)] == []


@pytest.mark.parametrize("entry", ["/", "//", "///"])
def test_a_slash_only_entry_is_not_a_candidate(entry: str) -> None:
    assert not is_route_check_candidate(entry)


@pytest.mark.parametrize("entry", ["/a/../b", "/a/%2e%2e/b", "/a//b/..;/c"])
def test_an_entry_with_a_routing_anomaly_is_not_a_candidate(entry: str) -> None:
    assert not is_route_check_candidate(entry)


@pytest.mark.parametrize("entry", ["/api/v1", "/static/", "/health-extra"])
def test_an_ordinary_entry_outside_the_defaults_is_a_candidate(entry: str) -> None:
    assert entry not in DEFAULT_EXCLUDE_PATHS
    assert is_route_check_candidate(entry)
