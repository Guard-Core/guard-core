from __future__ import annotations

import threading
import weakref
from collections.abc import Hashable
from typing import Any


class _ProcessScope:
    pass


_PROCESS_SCOPE = _ProcessScope()


def current_scope() -> object:
    return _PROCESS_SCOPE


class _Entry:
    __slots__ = ("client", "owners", "scope")

    def __init__(self, client: Any, scope: object, owner: object) -> None:
        self.client = client
        self.scope = weakref.ref(scope)
        self.owners: weakref.WeakSet[Any] = weakref.WeakSet([owner])


_entries: dict[Hashable, _Entry] = {}
_entries_lock = threading.Lock()


def _freeze(value: Any) -> Hashable:
    if isinstance(value, dict):
        return tuple(
            sorted(((k, _freeze(v)) for k, v in value.items()), key=lambda kv: kv[0])
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    if value is None or isinstance(value, (str, int, float, bool, type)):
        return value
    if hasattr(value, "__dict__"):
        return (type(value).__qualname__, _freeze(vars(value)))
    return (type(value).__qualname__, repr(value))


def pool_key(
    url: str,
    max_connections: int,
    pool_timeout: float,
    connection_kwargs: dict[str, Any],
    scope: object,
) -> Hashable:
    """Every connection setting by value plus the running scope, never the prefix."""
    return (
        url,
        max_connections,
        pool_timeout,
        _freeze(connection_kwargs),
        id(scope),
    )


def _live_entry(key: Hashable, scope: object) -> _Entry | None:
    entry = _entries.get(key)
    if entry is None:
        return None
    if entry.scope() is not scope or not entry.owners:
        del _entries[key]
        return None
    return entry


def acquire(key: Hashable, scope: object, owner: object) -> Any | None:
    """The shared client for key with owner added, or None when none is live."""
    with _entries_lock:
        entry = _live_entry(key, scope)
        if entry is None:
            return None
        entry.owners.add(owner)
        return entry.client


def publish(key: Hashable, scope: object, client: Any, owner: object) -> Any:
    """Make client the shared one for key; a client published first wins."""
    with _entries_lock:
        entry = _live_entry(key, scope)
        if entry is None:
            _entries[key] = _Entry(client, scope, owner)
            return client
        entry.owners.add(owner)
        return entry.client


def release(key: Hashable, client: Any, owner: object) -> bool:
    """Drop owner's reference; True when the caller must close the client."""
    with _entries_lock:
        entry = _entries.get(key)
        if entry is None or entry.client is not client:
            return True
        entry.owners.discard(owner)
        if entry.owners:
            return False
        del _entries[key]
        return True
