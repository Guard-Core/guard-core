import threading
import time
from collections import OrderedDict


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
