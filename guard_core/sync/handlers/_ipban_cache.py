import heapq
import ipaddress
import time
from collections.abc import Callable, Iterator, MutableMapping
from typing import Any

from cachetools import TTLCache

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network

DEFAULT_MAX_LOCAL_BANS = 100_000


class _ObservableTTLCache(TTLCache):
    def __init__(
        self,
        maxsize: int,
        ttl: float,
        on_evict: Callable[[], None],
    ) -> None:
        super().__init__(maxsize=maxsize, ttl=ttl)
        self._on_evict = on_evict

    def popitem(self) -> tuple[Any, Any]:
        item = super().popitem()
        self._on_evict()
        return item


class _BanStore(MutableMapping[str, float]):
    """In-memory bans keyed by identity, each with its own expiry.

    At ``maxsize`` the ban closest to expiry is evicted first (a lazy-deletion heap
    keeps that O(log n)), and ``on_evict`` is told when the evicted ban had not
    expired yet.
    """

    def __init__(
        self,
        maxsize: int,
        on_evict: Callable[[str, float], None],
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.maxsize = maxsize
        self._on_evict = on_evict
        self._clock = clock
        self._expiries: dict[str, float] = {}
        self._heap: list[tuple[float, str]] = []

    def __getitem__(self, key: str) -> float:
        return self._expiries[key]

    def __len__(self) -> int:
        return len(self._expiries)

    def __iter__(self) -> Iterator[str]:
        return iter(self._expiries)

    def __setitem__(self, key: str, expiry: float) -> None:
        if key not in self._expiries and len(self._expiries) >= self.maxsize:
            self._evict_closest_to_expiry()
        self._expiries[key] = expiry
        heapq.heappush(self._heap, (expiry, key))
        if len(self._heap) > 2 * len(self._expiries) + 1024:
            self._heap = [(value, name) for name, value in self._expiries.items()]
            heapq.heapify(self._heap)

    def __delitem__(self, key: str) -> None:
        del self._expiries[key]

    def clear(self) -> None:
        self._expiries.clear()
        self._heap.clear()

    def resize(self, maxsize: int) -> None:
        self.maxsize = maxsize
        while len(self._expiries) > maxsize:
            self._evict_closest_to_expiry()

    def _evict_closest_to_expiry(self) -> None:
        while self._heap:
            expiry, key = heapq.heappop(self._heap)
            if self._expiries.get(key) != expiry:
                continue
            del self._expiries[key]
            if expiry > self._clock():
                self._on_evict(key, expiry)
            return


class _OperatorNetworks:
    """Operator CIDR bans read back from Redis, answered by prefix length.

    A lookup is one dict probe per distinct prefix length present, so a deployment
    with 100,000 banned networks costs microseconds per request instead of a scan.
    """

    def __init__(self, expiries: dict[_Network, float]) -> None:
        by_length: dict[tuple[int, int], dict[int, float]] = {}
        for network, expiry in expiries.items():
            key = (network.version, network.prefixlen)
            by_length.setdefault(key, {})[int(network.network_address)] = expiry
        self._buckets: dict[int, list[tuple[int, dict[int, float]]]] = {4: [], 6: []}
        for (version, prefixlen), members in by_length.items():
            self._buckets[version].append((prefixlen, members))

    def covers(
        self, address: ipaddress.IPv4Address | ipaddress.IPv6Address, now: float
    ) -> bool:
        value = int(address)
        bits = address.max_prefixlen
        for prefixlen, members in self._buckets[address.version]:
            shift = bits - prefixlen
            expiry = members.get(value >> shift << shift)
            if expiry is not None and expiry > now:
                return True
        return False
