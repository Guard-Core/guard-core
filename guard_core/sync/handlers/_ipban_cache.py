import heapq
import ipaddress
import time
from collections.abc import Callable, Iterator, MutableMapping
from typing import TypeVar, overload

from cachetools import TTLCache

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network

DEFAULT_MAX_LOCAL_BANS = 100_000

_Default = TypeVar("_Default")


class _ObservableTTLCache(TTLCache[str, float]):
    def __init__(
        self,
        maxsize: int,
        ttl: float,
        on_evict: Callable[[], None],
    ) -> None:
        super().__init__(maxsize=maxsize, ttl=ttl)
        self._on_evict = on_evict

    def popitem(self) -> tuple[str, float]:
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
        self._memory_only: set[str] = set()
        self._foreign_memory: dict[str, float] = {}

    def record_foreign_memory(self, key: str, expiry: float) -> None:
        """Keep the latest expiry of a ban whose Redis write failed: unlike the
        memory-only marker, a later write does not clear it."""
        self._foreign_memory[key] = max(expiry, self._foreign_memory.get(key, 0.0))

    def foreign_memory_expiry(self, key: str) -> float | None:
        return self._foreign_memory.get(key)

    def mark_memory_only(self, key: str) -> None:
        """Record that no Redis copy backs this ban, so an eviction loses it."""
        self._memory_only.add(key)

    def is_memory_only(self, key: str) -> bool:
        return key in self._memory_only

    def __getitem__(self, key: str) -> float:
        return self._expiries[key]

    @overload
    def get(self, key: str, default: None = None) -> float | None: ...

    @overload
    def get(self, key: str, default: float | _Default) -> float | _Default: ...

    def get(
        self, key: str, default: float | _Default | None = None
    ) -> float | _Default | None:
        return self._expiries.get(key, default)

    def __len__(self) -> int:
        return len(self._expiries)

    def __iter__(self) -> Iterator[str]:
        return iter(self._expiries)

    def __setitem__(self, key: str, expiry: float) -> None:
        if key not in self._expiries and len(self._expiries) >= self.maxsize:
            self._evict_closest_to_expiry()
        self._expiries[key] = expiry
        self._memory_only.discard(key)
        heapq.heappush(self._heap, (expiry, key))
        if len(self._heap) > 2 * len(self._expiries) + 1024:
            self._heap = [(value, name) for name, value in self._expiries.items()]
            heapq.heapify(self._heap)

    def __delitem__(self, key: str) -> None:
        self._foreign_memory.pop(key, None)
        del self._expiries[key]
        self._memory_only.discard(key)

    def clear(self) -> None:
        self._expiries.clear()
        self._heap.clear()
        self._memory_only.clear()
        self._foreign_memory.clear()

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
            self._foreign_memory.pop(key, None)
            if expiry > self._clock():
                self._on_evict(key, expiry)
            self._memory_only.discard(key)
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
        self.has_networks = bool(by_length)
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

    def covering(
        self, address: ipaddress.IPv4Address | ipaddress.IPv6Address, now: float
    ) -> tuple[_Network, float] | None:
        value = int(address)
        bits = address.max_prefixlen
        for prefixlen, members in self._buckets[address.version]:
            shift = bits - prefixlen
            base = value >> shift << shift
            expiry = members.get(base)
            if expiry is not None and expiry > now:
                network = ipaddress.ip_network((base, prefixlen))
                return network, expiry
        return None
