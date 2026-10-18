import pytest

from guard_core.sync._utils.ip_extraction import _client_identity


@pytest.mark.parametrize(
    "address", ["203.0.113.9", "::ffff:203.0.113.9", "[::ffff:203.0.113.9]"]
)
def test_rule_2_ipv4_and_ipv4_mapped_are_the_address_itself(address: str) -> None:
    assert _client_identity(address, 64) == "203.0.113.9"
    assert _client_identity(address, 128) == "203.0.113.9"
    assert _client_identity(address, 64, "203.0.113.0/24") == "203.0.113.9"


def test_rule_1_non_ip_text_comes_back_unchanged() -> None:
    assert _client_identity("malformed-xff@2001:db8::1", 64) == (
        "malformed-xff@2001:db8::1"
    )
    assert _client_identity("not an ip", 64, "2001:db8::/32") == "not an ip"


def test_rule_1_canonicalizes_before_grouping() -> None:
    assert _client_identity("2001:0DB8:0:1:0:0:0:5", 64) == "2001:db8:0:1::/64"


def test_rule_6_native_ipv6_groups_at_the_prefix_as_cidr_text() -> None:
    assert _client_identity("2001:db8:0:1:aaaa:bbbb:cccc:dddd", 64) == (
        "2001:db8:0:1::/64"
    )
    assert _client_identity("2001:db8:0:1:aaaa:bbbb:cccc:dddd", 56) == ("2001:db8::/56")
    assert _client_identity("2001:db8:0:1::5", 64) == _client_identity(
        "2001:db8:0:1::6", 64
    )


def test_rule_6_the_default_range_edges_group_and_never_bare() -> None:
    assert _client_identity("2001:db8:1:2:3:4:5:6", 48) == "2001:db8:1::/48"
    assert _client_identity("::1", 64) == "::/64"


def test_rule_3_prefix_128_is_per_address_for_every_family() -> None:
    assert _client_identity("2001:db8:0:1::5", 128) == "2001:db8:0:1::5"
    assert _client_identity("2002:c000:204:1::7", 128) == "2002:c000:204:1::7"
    assert _client_identity("2001:0:4136:e378:8000:63bf:3fff:fdd2", 128) == (
        "2001:0:4136:e378:8000:63bf:3fff:fdd2"
    )
    assert _client_identity("64:ff9b::cb00:7109", 128) == "64:ff9b::cb00:7109"


@pytest.mark.parametrize("prefix_length", [48, 56, 64, 96, 127])
def test_rule_4_teredo_is_per_address_at_every_prefix(prefix_length: int) -> None:
    teredo = "2001:0:4136:e378:8000:63bf:3fff:fdd2"
    assert _client_identity(teredo, prefix_length) == teredo


@pytest.mark.parametrize(
    "first,second",
    [
        ("64:ff9b::c000:201", "64:ff9b::cb00:7109"),
        ("64:ff9b:1::c000:201", "64:ff9b:1::cb00:7109"),
    ],
)
def test_rule_4_nat64_clients_stay_distinct_identities_at_64(
    first: str, second: str
) -> None:
    assert _client_identity(first, 64) == first
    assert _client_identity(second, 64) == second
    assert _client_identity(first, 64) != _client_identity(second, 64)


@pytest.mark.parametrize("prefix_length", [48, 64, 96])
def test_rule_4_nat64_is_per_address_at_every_prefix(prefix_length: int) -> None:
    assert _client_identity("64:ff9b:1:0:0:0:c000:201", prefix_length) == (
        "64:ff9b:1::c000:201"
    )


def test_rule_5_6to4_groups_by_its_48_never_merged_with_ipv4() -> None:
    assert _client_identity("2002:c000:204:1::7", 64) == "2002:c000:204::/48"
    assert _client_identity("2002:c000:204:ffff::9", 64) == "2002:c000:204::/48"
    assert _client_identity("2002:c000:204:1::7", 56) == "2002:c000:204::/48"
    assert _client_identity("2002:c000:204:1::7", 64) != "192.0.2.4"


def test_rule_7_single_address_entry_is_its_slash_128() -> None:
    assert _client_identity("2001:db8:0:1::5", 64, "2001:db8:0:1::5") == (
        "2001:db8:0:1::5/128"
    )
    assert _client_identity("2001:db8:0:1::5", 64, "2001:db8:0:1::5/128") == (
        "2001:db8:0:1::5/128"
    )


def test_rule_7_longer_entry_than_the_group_is_the_identity_itself() -> None:
    assert _client_identity("2001:db8:0:1:0:0:0:5", 64, "2001:db8:0:1::/72") == (
        "2001:db8:0:1::/72"
    )


def test_rule_7_entry_as_short_as_or_shorter_than_the_group_gives_the_group() -> None:
    assert _client_identity("2001:db8:0:1::5", 64, "2001:db8:0:1::/64") == (
        "2001:db8:0:1::/64"
    )
    assert _client_identity("2001:db8:0:1::5", 64, "2001:db8::/48") == (
        "2001:db8:0:1::/64"
    )


def test_rule_7_6to4_entry_clips_to_the_48_group() -> None:
    assert _client_identity("2002:c000:204:1::7", 64, "2002:c000:204::/56") == (
        "2002:c000:204::/56"
    )
    assert _client_identity("2002:c000:204:1::7", 64, "2002:c000::/32") == (
        "2002:c000:204::/48"
    )
    assert _client_identity("2002:c000:204:1::7", 64, "2002:c000:204:1::7") == (
        "2002:c000:204:1::7/128"
    )


def test_rule_7_the_carve_is_a_no_op_at_prefix_128() -> None:
    assert _client_identity("2001:db8:0:1::5", 128, "2001:db8:0:1::/64") == (
        "2001:db8:0:1::5"
    )
    assert _client_identity("2002:c000:204:1::7", 128, "2002:c000::/32") == (
        "2002:c000:204:1::7"
    )


def test_rule_7_entry_text_is_canonicalized_to_one_key() -> None:
    lower = _client_identity("2001:db8:0:1::5", 64, "2001:db8:0:1::5/128")
    assert _client_identity("2001:DB8:0:1::5", 64, "2001:DB8:0:1::5") == lower
    assert _client_identity("2001:db8:0:1::5", 64, "2001:db8:0:1::0:5") == lower
    assert _client_identity("2001:db8:0:1:0:0:0:5", 64, "2001:db8:0:1::5/72") == (
        "2001:db8:0:1::/72"
    )
    assert _client_identity("2001:db8:0:1:0:0:0:5", 64, "2001:DB8:0:1::FF/72") == (
        "2001:db8:0:1::/72"
    )


def test_rule_7_per_address_families_ignore_the_carve() -> None:
    teredo = "2001:0:4136:e378:8000:63bf:3fff:fdd2"
    assert _client_identity(teredo, 64, "2001::/32") == teredo
    assert _client_identity(teredo, 64, teredo) == teredo
    assert _client_identity("203.0.113.9", 64, "203.0.113.9") == "203.0.113.9"
    assert _client_identity("64:ff9b::cb00:7109", 64, "64:ff9b::/96") == (
        "64:ff9b::cb00:7109"
    )


@pytest.mark.parametrize(
    "address,entry",
    [
        ("203.0.113.9", "198.51.100.0/24"),
        ("203.0.113.9", "::ffff:203.0.113.9"),
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:db8::/32"),
        ("64:ff9b::cb00:7109", "2001:db8::/32"),
        ("64:ff9b:1::c000:201", "203.0.113.0/24"),
    ],
)
def test_rule_7_per_address_identities_ignore_any_entry_and_never_raise(
    address: str, entry: str
) -> None:
    assert _client_identity(address, 64, entry) == address


@pytest.mark.parametrize(
    "address,entry",
    [
        ("2001:db8:0:1::5", "2001:db8:0:2::/64"),
        ("2001:db8:0:1::5", "2001:db8:0:1::6"),
        ("2001:db8:0:1::5", "203.0.113.0/24"),
        ("2002:c000:204:1::7", "2002:c000:205::/48"),
    ],
)
def test_rule_7_an_entry_that_does_not_contain_a_grouped_address_raises(
    address: str, entry: str
) -> None:
    with pytest.raises(ValueError):
        _client_identity(address, 64, entry)


@pytest.mark.parametrize("prefix_length", [48, 64, 128])
def test_rule_7_grouped_identities_have_a_slash_and_others_do_not(
    prefix_length: int,
) -> None:
    per_address = [
        "203.0.113.9",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "64:ff9b:1::c000:201",
        "malformed-xff@2001:db8::1",
    ]
    for address in per_address:
        assert "/" not in _client_identity(address, prefix_length)
    grouped = _client_identity("2001:db8:0:1::5", prefix_length)
    assert ("/" in grouped) == (prefix_length < 128)


@pytest.mark.parametrize(
    "address", ["fe80::1%eth0", "2001:db8:0:1::5%eth0", "2002:c000:204:1::7%2"]
)
def test_rule_8_zone_ids_do_not_raise(address: str) -> None:
    for prefix_length in (48, 64, 128):
        assert isinstance(_client_identity(address, prefix_length), str)
    assert isinstance(_client_identity(address, 64, "::/0"), str)
