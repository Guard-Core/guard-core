import threading
import time
import weakref
from collections import OrderedDict
from typing import Generic, Protocol, TypeVar

from guard_core.sync._utils.app_managers import (
    _HELD_ATTRIBUTE,
    held_for_app,
    hold_for_app,
)


class _Clearable(Protocol):
    def clear(self) -> None: ...


_T = TypeVar("_T", bound=_Clearable)

_PRUNE_FLOOR = 64


class SampledKeys:
    """The keys one app last sampled, for ``observe_sampled_key``."""

    def __init__(self) -> None:
        self.entries: OrderedDict[str, float] = OrderedDict()
        self.lock = threading.Lock()

    def clear(self) -> None:
        self.entries.clear()


class CountedKeys:
    """The keys one app last sampled and what each suppressed since, for
    ``observe_counted_key``, plus the pending counts of evicted keys."""

    def __init__(self) -> None:
        self.entries: OrderedDict[str, tuple[float, int]] = OrderedDict()
        self.lock = threading.Lock()
        self.evicted_pending = 0
        self.evicted_lock = threading.Lock()

    def clear(self) -> None:
        self.entries.clear()
        self.evicted_pending = 0

    def take_evicted_pending(self) -> int:
        with self.evicted_lock:
            taken, self.evicted_pending = self.evicted_pending, 0
        return taken


class RefusalReports(dict[str, float]):
    """The reasons one app last reported, with the time of each."""


class WarnedKeys(set[str]):
    """The warnings one app already logged, for log-once warnings."""


class PerApp(Generic[_T]):
    """One sampling table per app, found by the app's config.

    The config holds its table and a copy of the config gets a table of its own (it
    is another app), so with N apps the process holds at most N tables, each
    bounded by the caller's own cap. No config, or one that cannot hold a table,
    uses a process-wide table of its own.
    """

    def __init__(self, kind: str, table_type: type[_T]) -> None:
        self._kind = f"sampling:{kind}"
        self._table_type = table_type
        self._lock = threading.Lock()
        self._unheld = table_type()
        self._tables: list[weakref.ReferenceType[_T]] = []
        self._prune_at = _PRUNE_FLOOR

    def clear(self) -> None:
        """Forget the process-wide table. The table of an app goes with its config."""
        self._unheld.clear()

    def tables(self) -> list[_T]:
        """Every table alive now: the process-wide one and each app's."""
        with self._lock:
            alive = [table for ref in self._tables if (table := ref()) is not None]
            return [self._unheld, *alive]

    def _drop_dead_tables(self) -> None:
        self._tables = [ref for ref in self._tables if ref() is not None]
        self._prune_at = max(_PRUNE_FLOOR, 2 * len(self._tables))

    def for_app(self, config: object) -> _T:
        try:
            # Indexing, not .get(): this runs on the response path of every request.
            record = config.__dict__[_HELD_ATTRIBUTE]
            held = record[self._kind] if record.owner() is config else None
        except (AttributeError, KeyError):
            held = None
        if held is not None and isinstance(held, self._table_type):
            return held
        with self._lock:
            held = held_for_app(config, self._kind)
            if isinstance(held, self._table_type):
                return held
            fresh = self._table_type()
            if not hold_for_app(config, self._kind, fresh):
                return self._unheld
            self._tables.append(weakref.ref(fresh))
            if len(self._tables) >= self._prune_at:
                self._drop_dead_tables()
            return fresh


def _evict_oldest_when_full(table: "OrderedDict[str, float]", max_tracked: int) -> None:
    if len(table) >= max_tracked:
        table.popitem(last=False)


def _is_due(last_sampled: float | None, cutoff: float) -> bool:
    return last_sampled is None or last_sampled <= cutoff


def observe_sampled_key(
    table: "OrderedDict[str, float]",
    lock: threading.Lock,
    key: str,
    *,
    window: float,
    max_tracked: int,
) -> bool:
    """Return true at most once per key per ``window`` seconds.

    ``table`` maps each key to the time it last returned true. At most
    ``max_tracked`` keys are kept and the oldest is evicted.
    """
    now = time.monotonic()
    with lock:
        last_sampled = table.pop(key, None)
        if last_sampled is None:
            _evict_oldest_when_full(table, max_tracked)
        sampled = _is_due(last_sampled, now - window)
        table[key] = now if sampled else last_sampled or now
    return sampled


def observe_counted_key(
    table: "OrderedDict[str, tuple[float, int]]",
    lock: threading.Lock,
    key: str,
    *,
    window: float,
    max_tracked: int,
) -> tuple[bool, int, int]:
    """Like ``observe_sampled_key``, and count what it did not sample.

    ``table`` maps each key to the time it last returned true and how many
    observations returned false since. Returns ``(sampled, suppressed,
    evicted_pending)``: ``suppressed`` is that count when ``sampled`` is true (0 for
    a key seen first), and ``evicted_pending`` is the pending count of the oldest
    key evicted to make room (0 when none or when it had none), so the caller can
    keep it instead of losing it.
    """
    now = time.monotonic()
    with lock:
        entry = table.pop(key, None)
        if entry is None:
            evicted_pending = 0
            if len(table) >= max_tracked:
                evicted_pending = table.popitem(last=False)[1][1]
            table[key] = (now, 0)
            return True, 0, evicted_pending
        last_sampled, pending = entry
        if last_sampled <= now - window:
            table[key] = (now, 0)
            return True, pending, 0
        table[key] = (last_sampled, pending + 1)
        return False, 0, 0
