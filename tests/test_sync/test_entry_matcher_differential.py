"""The shared entry index answers exactly what the linear scans it replaced answered.

``old_ip_in_list`` and ``old_is_trusted_proxy`` are the pre-index implementations,
copied verbatim; every list and client below goes through both and the outcome,
a verdict or the ValueError an invalid entry raises, must be equal.
"""

import random
from collections.abc import Sequence
from ipaddress import IPv6Network, ip_address, ip_network
from types import SimpleNamespace
from typing import Any

import pytest

from guard_core.sync._utils.ip_extraction import (
    _canonicalize_ip,
    _is_trusted_proxy,
    _peer_address_for_matching,
)
from guard_core.sync._utils.nat64 import configure_nat64_prefixes
from guard_core.sync._utils.whitelist_match import (
    INITIAL_CACHE_SIZE,
    ContentCache,
    clear_entry_indexes,
    entry_index,
)
from guard_core.sync.utils import _ip_in_list

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


def old_ip_in_list(ip_addr: Any, ip: str, entries: Sequence[str] | None) -> bool:
    if not entries:
        return False
    canonical_ip = _canonicalize_ip(ip)
    for entry in entries:
        if "/" in entry:
            if ip_addr in ip_network(entry, strict=False):
                return True
        elif canonical_ip == _canonicalize_ip(entry):
            return True
    return False


def old_proxy_matches(peer_address: Any, proxy: str) -> bool:
    if "/" in proxy:
        return bool(peer_address in ip_network(proxy, strict=False))
    return bool(peer_address == _peer_address_for_matching(proxy))


def old_is_trusted_proxy(connecting_ip: str, trusted_proxies: Sequence[str]) -> bool:
    peer_address = _peer_address_for_matching(connecting_ip)
    if peer_address is None:
        return False
    try:
        return any(old_proxy_matches(peer_address, proxy) for proxy in trusted_proxies)
    except ValueError:
        return False


def outcome(call: Any, *args: Any) -> tuple[str, Any]:
    try:
        return "verdict", call(*args)
    except ValueError as error:
        return "error", type(error)


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
    try:
        configure_nat64_prefixes([prefix])
        for first in pool:
            for second in pool:
                for client in (translated, "8.8.8.8", "2001:db8:122:344::1"):
                    entries = [first, second]
                    addr = address_of(client)
                    assert outcome(_ip_in_list, addr, client, entries) == outcome(
                        old_ip_in_list, addr, client, entries
                    )
                    assert outcome(_is_trusted_proxy, client, entries) == outcome(
                        old_is_trusted_proxy, client, entries
                    )
    finally:
        configure_nat64_prefixes([])


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
    lists = INITIAL_CACHE_SIZE * 12

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

    for update in range(5, INITIAL_CACHE_SIZE * 10):
        for key in live:
            cache.get(key)
        cache.get(update)

    assert len(cache) <= INITIAL_CACHE_SIZE


def test_the_cache_is_cleared_when_nat64_prefixes_change() -> None:
    entry_index(("64:ff9b::808:808",), "proxy")

    configure_nat64_prefixes([])

    from guard_core.sync._utils import whitelist_match

    assert len(whitelist_match._index_cache) == 0


def test_an_invalid_cidr_reached_before_a_match_still_raises() -> None:
    addr = ip_address("1.2.3.4")

    with pytest.raises(ValueError):
        _ip_in_list(addr, "1.2.3.4", ["10.0.0.0/33", "1.2.3.4"])
    assert _ip_in_list(addr, "1.2.3.4", ["1.2.3.4", "10.0.0.0/33"]) is True


def test_the_trusted_proxy_networks_of_a_ban_are_parsed_once_per_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.sync._utils import whitelist_match
    from guard_core.sync.handlers.ipban_handler import IPBanManager

    clear_entry_indexes()
    parsed: list[str] = []
    original = whitelist_match.ip_network

    def counting(value: str, strict: bool = True) -> Any:
        parsed.append(value)
        return original(value, strict=strict)

    monkeypatch.setattr(whitelist_match, "ip_network", counting)
    IPBanManager._instance = None
    manager = IPBanManager()
    manager.config = SimpleNamespace(trusted_proxies=["10.0.0.0/8", "not-a-network"])

    first = manager._trusted_proxy_networks()
    second = manager._trusted_proxy_networks()

    assert first == second == [ip_network("10.0.0.0/8")]
    assert parsed == ["10.0.0.0/8", "not-a-network"]
    IPBanManager._instance = None
