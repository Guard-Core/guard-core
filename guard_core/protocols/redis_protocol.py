from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from typing_extensions import AsyncContextManager

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig


@runtime_checkable
class RedisHandlerProtocol(Protocol):
    """Storage backend the engine uses for all shared, cross-worker state.

    WHAT: a namespaced async key-value store (rate-limit counters, IP bans,
    cloud-IP ranges, behavioral tallies) keyed by ``(namespace, key)``, plus the
    atomic multi-key operations the engine builds its bans, strikes and sliding
    windows on.
    WHEN: every handler that persists state resolves it through this protocol;
    ``initialize`` runs once at startup before any read/write, and startup
    names every member below that a handler lacks.
    HOW: subclass ``RedisHandlerBase`` and supply ``initialize`` and
    ``get_connection``, or implement every member below. ``get_connection``
    must yield a redis-py-compatible asyncio client: the engine runs pipelines,
    ``evalsha``, ``scan_iter``, ``zrange`` and ``execute_command`` on it. Reads
    return ``None`` on a miss (never raise for absent keys); keep calls
    non-blocking on the request hot path. All TTLs are expressed in seconds.
    """

    config: SecurityConfig

    async def get_key(self, namespace: str, key: str) -> Any:
        """Return the value stored at ``namespace:key``, or ``None`` if absent."""
        ...

    async def get_many(self, pairs: Sequence[tuple[str, str]]) -> list[Any]:
        """Return the values of every ``(namespace, key)`` pair in one round trip.

        The list matches ``pairs`` in order, with ``None`` for each absent key.
        """
        ...

    async def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool | None:
        """Store ``value`` at ``namespace:key``, expiring after ``ttl`` seconds.

        ``ttl=None`` persists with no expiry. Returns the backend's set result
        (truthy on success) or ``None`` when the backend reports nothing.
        """
        ...

    async def set_key_if_absent(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool:
        """Store ``value`` at ``namespace:key`` only when absent (a lock claim).

        Returns ``True`` when this call stored it, ``False`` when the key held a
        value already.
        """
        ...

    async def incr(
        self, namespace: str, key: str, ttl: int | None = None
    ) -> int | None:
        """Increment the counter at ``namespace:key`` and return the new value.

        ``ttl`` (seconds) is applied when given; ``None`` leaves any expiry alone.
        """
        ...

    async def write_atomically(
        self,
        *,
        sets: Sequence[tuple[str, str, Any, int | None]] = (),
        deletes: Sequence[tuple[str, str]] = (),
        increment: tuple[str, str] | None = None,
    ) -> None:
        """Apply sets, deletes and one counter increment in one transaction.

        ``sets`` holds ``(namespace, key, value, ttl)``, ``deletes`` holds
        ``(namespace, key)``. Either all of it lands or none of it does.
        """
        ...

    async def delete(self, namespace: str, key: str) -> int | None:
        """Delete ``namespace:key``; return the number of keys removed (0 if none)."""
        ...

    async def delete_pattern(self, pattern: str) -> int | None:
        """Delete every key matching ``pattern`` (prefix added), without ``KEYS``.

        Returns the number of keys removed.
        """
        ...

    async def keys(self, pattern: str) -> list[str] | None:
        """Return keys matching ``pattern``, or ``None`` when none can be listed."""
        ...

    async def write_ban_extending_only(
        self,
        namespace: str,
        key: str,
        expiry: str,
        duration: int,
        *,
        version: tuple[str, str],
        advance_version: bool = False,
        rule_owned: bool = False,
    ) -> float:
        """Write a ban only when it outlasts the live one, in one atomic call.

        ``expiry`` is the expiry text the caller formatted once and ``duration``
        the ban's seconds. ``advance_version`` increments the ``version`` counter
        in the same call when the ban was written; ``rule_owned`` records the ban
        in the owned set. Returns the expiry the ban key holds afterwards.
        """
        ...

    async def owned_ban_members(self) -> list[str]:
        """Return the full ban keys the dynamic rules own, as the owned set has them."""
        ...

    async def owned_ban_state(
        self, namespace: str, key: str
    ) -> tuple[float | None, float | None]:
        """Return the owned-set expiry of one ban and the expiry the ban holds now.

        Each is ``None`` when absent. Both are read in one round trip.
        """
        ...

    async def purge_owned_ban(self, member: str) -> int:
        """Lift one owned ban down to its floor, or off, in one atomic call.

        ``member`` is the full ban key. Returns 0 (already gone), 1 (deleted),
        2 (rewritten to its floor) or 3 (a longer ban replaced it, left alone).
        """
        ...

    async def disown_ban(self, namespace: str, key: str) -> None:
        """Remove the ban from the set of bans a dynamic rule owns."""
        ...

    async def record_sliding_window_hit(
        self,
        namespace: str,
        key: str,
        timestamp: float,
        window_start: float,
        ttl: int,
        *,
        index: tuple[str, int] | None = None,
        index_refused: list[bool] | None = None,
    ) -> int:
        """Record one hit and return the key's count inside the window.

        ``index`` (index key, max members) also adds the key to that set of the
        namespace in the same round trip; at the cap the key is not indexed but
        the hit still counts, and ``True`` is appended to ``index_refused`` when
        given.
        """
        ...

    async def count_sliding_window_hits(
        self, namespace: str, key: str, window_start: float
    ) -> int:
        """Return the key's hits at or after ``window_start``, recording none."""
        ...

    async def sum_indexed_window_hits(
        self, namespace: str, index_key: str, window_start: float
    ) -> int:
        """Sum the hits since ``window_start`` over every key of the index set.

        Members whose key has expired are dropped. One round trip.
        """
        ...

    def detection_correlation_keys(self, client_ip: str) -> list[str]:
        """Return the full keys that tell whether ``client_ip`` has strikes.

        They are the category index and the shared rate-limit violations key.
        """
        ...

    async def record_detection_strikes(
        self,
        client_ip: str,
        categories: Sequence[str],
        timestamp: float,
        window_start: float,
        ttl: int,
        cap: int,
    ) -> tuple[int, int, dict[str, int]]:
        """Record one detection strike under every category in one round trip.

        Returns the IP's total over all categories, its shared rate-limit
        violations in the window, and the count of each category of this strike.
        Every key is bounded to ``cap`` members.
        """
        ...

    async def read_detection_categories(
        self, client_ip: str, window_start: float
    ) -> list[str]:
        """Return the categories ``client_ip`` has strikes in since ``window_start``.

        Shared rate-limit violations appear as ``"rate_limit"``. One round trip.
        """
        ...

    async def forget_detection_strikes(self, client_ip: str) -> None:
        """Delete every detection strike counter of ``client_ip`` in one round trip."""
        ...

    async def initialize(self) -> None:
        """Open the connection/pool. Called once at startup before any access."""
        ...

    async def initialize_agent(self, agent_handler: Any) -> None:
        """Receive the telemetry agent handler so Redis events can be reported."""
        ...

    def get_connection(self) -> AsyncContextManager[Any]:
        """Yield a redis-py-compatible asyncio client for one operation."""
        ...
