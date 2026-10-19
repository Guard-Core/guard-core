"""One prefix-length index for every list of IP entries the engine matches.

The whitelist, blacklist, ``exempt_ips``, the route lists, emergency mode and the
trusted proxies are lists of exact addresses and CIDRs. Matching a client used to
parse every CIDR with ``ip_network`` on every call (4000 us at 1000 entries); the
index is built once per distinct list, keyed by its content, and a lookup is one
dict probe per distinct prefix length.

Three modes share the one index type and differ only in how an entry without a
slash is read: ``network`` (every entry a network, longest prefix first, for the
whitelist carve), ``list`` (an exact entry is compared by its canonical text, as
``_ip_in_list`` always did) and ``proxy`` (an exact entry is compared as the
address it normalizes to, as the trusted-proxy check always did). The first
invalid CIDR of a list raises ``ValueError`` when a lookup reaches it before a
match, exactly like the linear scan it replaces.
"""

import threading
from collections.abc import Callable, Hashable, Sequence
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network
from typing import Generic, NamedTuple, TypeVar

Address = IPv4Address | IPv6Address
Network = IPv4Network | IPv6Network
_Buckets = tuple[tuple[int, dict[int, tuple[int, str]]], ...]

_Key = TypeVar("_Key", bound=Hashable)
_Value = TypeVar("_Value")
INITIAL_CACHE_SIZE = 8


class _Slot(Generic[_Value]):
    __slots__ = ("value", "used")

    def __init__(self, value: _Value) -> None:
        self.value = value
        self.used = False


class ContentCache(Generic[_Key, _Value]):
    """A cache keyed by list content that grows to hold the lists in use.

    The engine holds five global lists (whitelist, blacklist, ``exempt_ips``,
    ``trusted_proxies``, the emergency whitelist) plus two per IP-restricted route,
    so no fixed size is right: a cache smaller than that working set re-parses a
    list on every use (300 us instead of 0.8 us). At capacity a miss evicts the
    oldest entry nothing has hit since the last sweep and remembers only the hash
    of its key, never the key (a 10,000 entry list is 1.6 MiB). A miss on a
    remembered hash means the working set is larger than the cache, so the capacity
    grows by one slot; a hash collision only grows it by one slot too. The cache
    starts at 8 slots and a list that dynamic rules replace is never asked for
    again, is evicted and forgotten, and never makes the cache grow, so the
    capacity tracks the lists held and not the number of updates.
    """

    def __init__(self, build: Callable[[_Key], _Value]) -> None:
        self._build = build
        self._slots: dict[_Key, _Slot[_Value]] = {}
        self._evicted: dict[int, None] = {}
        self._capacity = INITIAL_CACHE_SIZE
        self._lock = threading.Lock()

    def get(self, key: _Key) -> _Value:
        slot = self._slots.get(key)
        if slot is not None:
            slot.used = True
            return slot.value
        built = self._build(key)
        with self._lock:
            if hash(key) in self._evicted:
                del self._evicted[hash(key)]
                self._capacity = max(self._capacity, len(self._slots) + 1)
            if len(self._slots) >= self._capacity:
                self._evict_one()
            self._slots[key] = _Slot(built)
        return built

    def _evict_one(self) -> None:
        victim = next((k for k, slot in self._slots.items() if not slot.used), None)
        if victim is None:
            for slot in self._slots.values():
                slot.used = False
            victim = next(iter(self._slots))
        del self._slots[victim]
        self._evicted[hash(victim)] = None
        if len(self._evicted) > max(4096, 4 * self._capacity):
            del self._evicted[next(iter(self._evicted))]

    def clear(self) -> None:
        with self._lock:
            self._slots.clear()
            self._evicted.clear()
            self._capacity = INITIAL_CACHE_SIZE

    def __len__(self) -> int:
        return len(self._slots)


class EntryIndex(NamedTuple):
    buckets: dict[int, _Buckets]
    exact: dict[Hashable, int]
    invalid: tuple[int, str] | None


def _exact_key(mode: str, entry: str) -> Hashable | None:
    from guard_core.sync._utils.ip_extraction import (
        _canonicalize_ip,
        _peer_address_for_matching,
    )

    if mode == "list":
        return _canonicalize_ip(entry)
    return _peer_address_for_matching(entry)


def _longest_first(
    by_length: dict[tuple[int, int], dict[int, tuple[int, str]]],
) -> dict[int, _Buckets]:
    index: dict[int, _Buckets] = {}
    for version in (4, 6):
        members = sorted(
            (
                (prefixlen, entries)
                for (entry_version, prefixlen), entries in by_length.items()
                if entry_version == version
            ),
            key=lambda bucket: bucket[0],
            reverse=True,
        )
        index[version] = tuple(members)
    return index


def _build_entry_index(key: tuple[tuple[str, ...], str]) -> EntryIndex:
    entries, mode = key
    by_length: dict[tuple[int, int], dict[int, tuple[int, str]]] = {}
    exact: dict[Hashable, int] = {}
    invalid: tuple[int, str] | None = None
    for position, entry in enumerate(entries):
        if mode != "network" and "/" not in entry:
            exact_key = _exact_key(mode, entry)
            if exact_key is not None:
                exact.setdefault(exact_key, position)
            continue
        try:
            network = ip_network(entry, strict=False)
        except ValueError as error:
            if mode == "network":
                raise
            invalid = (position, str(error))
            break
        members = by_length.setdefault((network.version, network.prefixlen), {})
        members.setdefault(int(network.network_address), (position, str(network)))
    return EntryIndex(_longest_first(by_length), exact, invalid)


def _parse_networks(entries: tuple[str, ...]) -> tuple[Network, ...]:
    networks = []
    for entry in entries:
        try:
            networks.append(ip_network(entry, strict=False))
        except ValueError:
            continue
    return tuple(networks)


_index_cache: ContentCache[tuple[tuple[str, ...], str], EntryIndex] = ContentCache(
    _build_entry_index
)
_network_cache: ContentCache[tuple[str, ...], tuple[Network, ...]] = ContentCache(
    _parse_networks
)


def entry_index(entries: tuple[str, ...], mode: str) -> EntryIndex:
    return _index_cache.get((entries, mode))


def parsed_networks(entries: tuple[str, ...]) -> tuple[Network, ...]:
    return _network_cache.get(entries)


def clear_entry_indexes() -> None:
    _index_cache.clear()
    _network_cache.clear()


def _first_match(
    index: EntryIndex, address: Address, exact_lookup: Hashable
) -> tuple[int, str] | None:
    best: tuple[int, str] | None = None
    position = index.exact.get(exact_lookup)
    if position is not None:
        best = (position, "")
    value = int(address)
    bits = address.max_prefixlen
    for prefixlen, members in index.buckets[address.version]:
        shift = bits - prefixlen
        found = members.get(value >> shift << shift)
        if found is not None and (best is None or found[0] < best[0]):
            best = found
    return best


def is_listed(
    address: Address, exact_lookup: Hashable, entries: Sequence[str], mode: str
) -> bool:
    index = entry_index(tuple(entries), mode)
    match = _first_match(index, address, exact_lookup)
    if index.invalid is not None and (match is None or match[0] > index.invalid[0]):
        raise ValueError(index.invalid[1])
    return match is not None


def most_specific_whitelist_entry(
    address: Address, entries: Sequence[str]
) -> str | None:
    value = int(address)
    bits = address.max_prefixlen
    for prefixlen, members in entry_index(tuple(entries), "network").buckets[
        address.version
    ]:
        shift = bits - prefixlen
        found = members.get(value >> shift << shift)
        if found is not None:
            return found[1]
    return None
