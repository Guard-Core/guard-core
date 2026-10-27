import ipaddress

import pytest

from guard_core.handlers._dynamic_rule_plan import (
    _covered_by,
    _merge_unique,
    _stored_entries,
)

_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("2001:db8::/32"),
]


@pytest.mark.parametrize(
    ("entry", "covered"),
    [
        ("10.1.2.3", True),
        ("192.0.2.1", False),
        ("2001:db8::1", True),
        ("2001:db9::1", False),
    ],
)
def test_entry_is_covered_only_by_a_network_of_its_own_family(
    entry: str, covered: bool
) -> None:
    assert _covered_by(entry, _NETWORKS) is covered


def test_a_family_with_no_network_is_never_covered() -> None:
    assert _covered_by("10.1.2.3", _NETWORKS[1:]) is False
    assert _covered_by("2001:db8::1", _NETWORKS[:1]) is False


def test_stored_entries_accepts_none_and_every_collection_the_plan_stores() -> None:
    assert list(_stored_entries(None)) == []
    assert set(_stored_entries(frozenset({"a"}))) == {"a"}
    assert list(_stored_entries(("a", "b"))) == ["a", "b"]
    assert _merge_unique(frozenset({"a"}), ["a", "b"]) == ["a", "b"]


def test_stored_entries_rejects_a_value_that_is_not_a_collection() -> None:
    with pytest.raises(TypeError, match="stored rule entries must be a collection"):
        _stored_entries(5)
