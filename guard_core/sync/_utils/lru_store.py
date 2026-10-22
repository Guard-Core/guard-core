from collections.abc import Callable, MutableMapping
from typing import Any, TypeVar

_V = TypeVar("_V")

DEFAULT_MAX_TRACKED_KEYS = 10_000


def _lru_pop_or_create(
    store: MutableMapping[str, _V],
    key: str,
    max_size: int,
    default: Callable[[], _V],
    evicted: list[tuple[str, Any]] | None = None,
    kind: str = "",
) -> _V:
    value = store.pop(key, None)
    if value is not None:
        return value
    if len(store) >= max_size:
        oldest_key = next(iter(store))
        dropped = store.pop(oldest_key)
        if evicted is not None:
            evicted.append((kind, dropped))
    return default()
