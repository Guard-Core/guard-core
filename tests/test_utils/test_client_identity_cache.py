import random
from ipaddress import IPv6Address, IPv6Network, ip_network

from guard_core._utils.ip_extraction import _client_identity
from guard_core._utils.nat64 import Nat64Table


def test_a_repeated_identity_is_answered_from_the_cache() -> None:
    _client_identity.cache_clear()

    first = _client_identity("2001:db8:0:1::5", 64)
    second = _client_identity("2001:db8:0:1::5", 64)

    assert first == second == "2001:db8:0:1::/64"
    assert _client_identity.cache_info().hits == 1


def test_the_identity_matches_the_network_text_for_random_native_addresses() -> None:
    generator = random.Random(20261019)
    for _ in range(3000):
        value = generator.getrandbits(128)
        address = IPv6Address(value)
        if address.is_private or address.is_multicast or address.is_reserved:
            value = (0x2A00 << 112) | (value & ((1 << 112) - 1))
            address = IPv6Address(value)
        length = generator.randint(48, 127)
        expected = str(ip_network(f"{address}/{length}", strict=False))

        assert _client_identity.__wrapped__(str(address), length) == expected


def test_each_nat64_table_has_its_own_cached_identities() -> None:
    prefix = IPv6Network("2001:db8:122:344::/64")
    translated = str(IPv6Address(int(prefix.network_address) | (0x08080808 << 24)))
    decoding = Nat64Table([prefix])
    plain = Nat64Table()

    assert _client_identity(translated, 64, None, plain) == "2001:db8:122:344::/64"
    assert _client_identity(translated, 64, None, decoding) == "8.8.8.8"
    assert _client_identity(translated, 64, None, plain) == "2001:db8:122:344::/64"


def test_a_cached_failure_is_never_stored() -> None:
    _client_identity.cache_clear()

    for _ in range(2):
        try:
            _client_identity("2001:db8::5", 64, "198.51.100.0/24")
        except ValueError:
            continue
        raise AssertionError("an entry that does not contain the address must raise")

    assert _client_identity.cache_info().currsize == 0
