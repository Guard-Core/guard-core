"""The shared entry index answers exactly what the linear scans it replaced answered.

``old_ip_in_list`` and ``old_is_trusted_proxy`` are the pre-index implementations,
copied verbatim; every list and client below goes through both and the outcome,
a verdict or the ValueError an invalid entry raises, must be equal.
"""

import random
from collections.abc import Sequence
from ipaddress import IPv6Network, ip_address, ip_network
from typing import Any

import pytest

from guard_core._utils.ip_extraction import (
    _canonicalize_ip,
    _is_trusted_proxy,
    _peer_address_for_matching,
)
from guard_core._utils.nat64 import DEFAULT_NAT64_TABLE, Nat64Table
from guard_core._utils.whitelist_match import (
    INITIAL_CACHE_SIZE,
    ContentCache,
    clear_entry_indexes,
    entry_index,
    unwrap_ipv4_mapped_network,
)
from guard_core.models import SecurityConfig
from guard_core.utils import _ip_in_list

EXACT = [
    "1.2.3.4",
    "10.0.0.5",
    "8.8.8.8",
    "2001:db8::1",
    "2001:DB8:0:0:0:0:0:1",
    "::ffff:1.2.3.4",
    "::ffff:10.0.0.5",
    "64:ff9b::808:808",
    "[2001:db8::1]",
    "fe80::1%eth0",
    "  1.2.3.4",
    "unix",
    "bad",
    "",
]
CIDRS = [
    "10.0.0.0/8",
    "10.0.0.7/8",
    "2001:db8::/32",
    "2001:db8::1/128",
    "::ffff:10.0.0.0/104",
    "192.168.0.0/16",
    "0.0.0.0/0",
    "::/0",
    "1.2.3.4/32",
    "64:ff9b::/96",
]
INVALID = ["10.0.0.0/33", "2001:db8::/129", "bad/8", "1.2.3/24", "/8", "10.0.0.0/"]
CLIENTS = [
    "1.2.3.4",
    "10.0.0.5",
    "10.200.1.1",
    "8.8.8.8",
    "192.168.5.5",
    "2001:db8::1",
    "2001:db8::2",
    "2001:DB8::1",
    "::ffff:1.2.3.4",
    "::ffff:10.0.0.5",
    "64:ff9b::808:808",
    "fe80::1",
    "[2001:db8::1]",
    "fe80::1%eth0",
]
POOL = EXACT + CIDRS + INVALID


def old_ip_in_list(
    ip_addr: Any,
    ip: str,
    entries: Sequence[str] | None,
    nat64: Nat64Table = DEFAULT_NAT64_TABLE,
) -> bool:
    if not entries:
        return False
    canonical_ip = _canonicalize_ip(ip, nat64)
    if getattr(ip_addr, "ipv4_mapped", None) is not None:
        # a mapped client address is read as the IPv4 address it carries (6.348)
        ip_addr = ip_addr.ipv4_mapped
    for entry in entries:
        if "/" in entry:
            if ip_addr in unwrap_ipv4_mapped_network(ip_network(entry, strict=False)):
                return True
        elif canonical_ip == _canonicalize_ip(entry, nat64):
            return True
    return False


def old_proxy_matches(peer_address: Any, proxy: str, nat64: Nat64Table) -> bool:
    if "/" in proxy:
        return bool(
            peer_address in unwrap_ipv4_mapped_network(ip_network(proxy, strict=False))
        )
    return bool(peer_address == _peer_address_for_matching(proxy, nat64))


def old_is_trusted_proxy(
    connecting_ip: str,
    trusted_proxies: Sequence[str],
    nat64: Nat64Table = DEFAULT_NAT64_TABLE,
) -> bool:
    peer_address = _peer_address_for_matching(connecting_ip, nat64)
    if peer_address is None:
        return False
    try:
        return any(
            old_proxy_matches(peer_address, proxy, nat64) for proxy in trusted_proxies
        )
    except ValueError:
        return False


def outcome(call: Any, *args: Any) -> tuple[str, Any]:
    try:
        return "verdict", call(*args)
    except ValueError as error:
        return "error", (type(error), str(error))


def address_of(client: str) -> Any:
    return ip_address(client.strip("[]").partition("%")[0])


def assert_same_everywhere(entries: list[str]) -> None:
    for client in CLIENTS:
        addr = address_of(client)
        assert outcome(_ip_in_list, addr, client, entries) == outcome(
            old_ip_in_list, addr, client, entries
        ), (entries, client)
        assert outcome(_is_trusted_proxy, client, entries) == outcome(
            old_is_trusted_proxy, client, entries
        ), (entries, client)


def test_every_single_entry_gives_the_old_verdict() -> None:
    for entry in POOL:
        assert_same_everywhere([entry])


def test_every_pair_of_entries_gives_the_old_verdict_in_either_order() -> None:
    for first in POOL:
        for second in POOL:
            assert_same_everywhere([first, second])


def test_random_lists_with_invalid_entries_before_and_after_a_match() -> None:
    generator = random.Random(20261019)
    for _ in range(1500):
        entries = generator.sample(POOL, generator.randint(0, 8))
        assert_same_everywhere(entries)


def test_the_verdicts_hold_with_a_network_specific_nat64_prefix() -> None:
    prefix = IPv6Network("2001:db8:122:344::/64")
    translated = str(
        next(prefix.hosts()).__class__(int(prefix.network_address) | 0x08080808 << 24)
    )
    pool = [translated, "8.8.8.8", "2001:db8:122:344::/64", "8.8.8.0/24", *INVALID[:2]]
    table = Nat64Table([prefix])
    for first in pool:
        for second in pool:
            for client in (translated, "8.8.8.8", "2001:db8:122:344::1"):
                entries = [first, second]
                addr = address_of(client)
                assert outcome(_ip_in_list, addr, client, entries, table) == outcome(
                    old_ip_in_list, addr, client, entries, table
                )
                assert outcome(_is_trusted_proxy, client, entries, table) == outcome(
                    old_is_trusted_proxy, client, entries, table
                )


def test_a_list_is_indexed_once_and_a_changed_list_is_a_new_index() -> None:
    clear_entry_indexes()
    entries = ["10.0.0.0/8", "192.168.0.0/16"]

    first = entry_index(tuple(entries), "list")
    second = entry_index(tuple(entries), "list")
    entries.append("172.16.0.0/12")

    assert first is second
    assert entry_index(tuple(entries), "list") is not first


def test_more_lists_than_any_fixed_size_are_not_re_indexed_every_round() -> None:
    builds: list[int] = []

    def build(key: int) -> int:
        builds.append(key)
        return key

    cache: ContentCache[int, int] = ContentCache(build)
    lists = 3072

    for key in range(lists):
        cache.get(key)
    for key in range(lists):
        cache.get(key)
    settled = len(builds)
    for key in range(lists):
        assert cache.get(key) == key

    assert len(builds) == settled
    assert settled < 3 * lists
    assert len(cache) >= lists


def test_replaced_lists_leave_the_cache_without_growing_it() -> None:
    cache: ContentCache[int, int] = ContentCache(lambda key: key)
    live = [0, 1, 2, 3, 4]

    for update in range(5, 3000):
        for key in live:
            cache.get(key)
        cache.get(update)

    assert len(cache) <= INITIAL_CACHE_SIZE


def test_an_index_is_never_shared_between_two_nat64_tables() -> None:
    entries = ("2001:db8:122:344:0:808:808:0",)
    first = entry_index(entries, "list", Nat64Table())
    second = entry_index(entries, "list", Nat64Table())

    assert first is not second


def test_an_invalid_cidr_reached_before_a_match_still_raises() -> None:
    addr = ip_address("1.2.3.4")

    with pytest.raises(ValueError):
        _ip_in_list(addr, "1.2.3.4", ["10.0.0.0/33", "1.2.3.4"])
    assert _ip_in_list(addr, "1.2.3.4", ["1.2.3.4", "10.0.0.0/33"]) is True


def test_the_trusted_proxy_networks_of_a_ban_are_parsed_once_per_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core._utils import whitelist_match
    from guard_core.handlers.ipban_handler import IPBanManager

    clear_entry_indexes()
    parsed: list[str] = []
    original = whitelist_match.ip_network

    def counting(value: str, strict: bool = True) -> Any:
        parsed.append(value)
        return original(value, strict=strict)

    monkeypatch.setattr(whitelist_match, "ip_network", counting)
    IPBanManager._instance = None
    manager = IPBanManager()
    manager.config = SecurityConfig.model_construct(
        trusted_proxies=("10.0.0.0/8", "not-a-network")
    )

    first = manager._trusted_proxy_networks()
    second = manager._trusted_proxy_networks()

    assert first == second == [ip_network("10.0.0.0/8")]
    assert parsed == ["10.0.0.0/8", "not-a-network"]
    IPBanManager._instance = None


def _large_list(version: int) -> list[str]:
    networks = [
        f"10.{(index >> 8) & 255}.{index & 255}.0/24" for index in range(10_000)
    ]
    return [*networks, f"203.0.{version // 256}.{version % 256}"]


def test_replaced_large_lists_retain_the_working_set() -> None:  # async-only
    import gc
    import tracemalloc

    clear_entry_indexes()
    client = "8.8.8.8"
    address = ip_address(client)
    tracemalloc.start()
    try:
        gc.collect()
        baseline = tracemalloc.get_traced_memory()[0]
        _ip_in_list(address, client, _large_list(0))
        gc.collect()
        one_list = tracemalloc.get_traced_memory()[0] - baseline

        for version in range(1, 41):
            _ip_in_list(address, client, _large_list(version))
        gc.collect()
        retained = tracemalloc.get_traced_memory()[0] - baseline
    finally:
        tracemalloc.stop()
        clear_entry_indexes()

    assert one_list > 500_000
    assert retained < 12 * one_list


def test_a_whitelist_with_an_invalid_entry_is_refused_by_the_carve_index() -> None:
    from guard_core._utils.whitelist_match import most_specific_whitelist_entry

    clear_entry_indexes()

    with pytest.raises(ValueError, match="does not appear to be an IPv4 or IPv6"):
        most_specific_whitelist_entry(ip_address("1.2.3.4"), ["10.0.0.0/8", "bad/33"])


def test_the_evicted_hashes_stay_bounded_when_many_lists_are_replaced() -> None:
    cache: ContentCache[int, int] = ContentCache(lambda key: key)
    replaced = 4096 * 3

    for update in range(replaced):
        cache.get(update)

    assert len(cache._evicted) <= max(4096, 4 * cache._capacity)
    assert len(cache._evicted) > INITIAL_CACHE_SIZE
