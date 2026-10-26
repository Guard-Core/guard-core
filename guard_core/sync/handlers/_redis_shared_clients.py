from __future__ import annotations

import threading
import weakref
from collections.abc import Hashable
from typing import Any

from guard_core._redis_enablement import configured_redis_url
from guard_core._redis_exceptions import RedisConnectionError, RedisTimeoutError
from guard_core.sync._utils.config_registry import ConfigHandlerRegistry

DEFAULT_POOL_SIZE = 100


class _ProcessScope:
    pass


_PROCESS_SCOPE = _ProcessScope()


def current_scope() -> object:
    return _PROCESS_SCOPE


def current_scope_or_none() -> object | None:
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


def pool_key_of_settings(
    url: str,
    config: Any,
    connection_kwargs: dict[str, Any],
    default_pool_size: int,
    scope: object,
) -> Hashable:
    """The pool key a config's connection settings give, the one place it is built."""
    return pool_key(
        url,
        config.redis_max_connections or default_pool_size,
        config.redis_pool_timeout,
        connection_kwargs,
        scope,
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


_MANAGERS: ConfigHandlerRegistry[object] = ConfigHandlerRegistry()


def _manager_kind(manager_class: type) -> str:
    return f"{manager_class.__module__}.{manager_class.__qualname__}"


def existing_manager(config: Any, manager_class: type) -> Any | None:
    """The manager built for this config object, held weakly, or None."""
    return _MANAGERS.lookup(config, _manager_kind(manager_class))


def register_manager(config: Any, manager: Any, manager_class: type) -> None:
    _MANAGERS.register(config, manager, _manager_kind(manager_class))


def open_client(
    owner: Any, url: str, config: Any, build: Any, default_pool_size: int
) -> tuple[Any | None, Hashable, object, bool]:
    """The shared client for these settings, else a new one from build; the last
    item says whether it was shared."""
    connection_kwargs = owner._connection_kwargs(config)
    scope = current_scope()
    key = pool_key_of_settings(url, config, connection_kwargs, default_pool_size, scope)
    shared = acquire(key, scope, owner)
    if shared is not None:
        return shared, key, scope, True
    client = build(
        url,
        config.redis_max_connections or default_pool_size,
        config.redis_pool_timeout,
        **connection_kwargs,
    )
    return client, key, scope, False


def register_client(owner: Any, client: Any, key: Hashable, scope: object) -> Any:
    published = publish(key, scope, client, owner)
    if published is not client:
        owner._safe_aclose(client)
    return published


def connection_kwargs_of(cfg: Any) -> dict[str, Any]:
    """Connection tuning passed to ``Redis.from_url``.

    Without bounded timeouts a partitioned Redis blocks every request that
    touches it indefinitely, so these default to non-None. Any value already
    encoded in ``redis_url`` query params still wins (redis-py applies URL
    params last), so this only sets a floor.
    """
    kwargs: dict[str, Any] = {
        "socket_connect_timeout": cfg.redis_socket_connect_timeout,
        "socket_timeout": cfg.redis_socket_timeout,
        "health_check_interval": cfg.redis_health_check_interval,
    }
    if cfg.redis_retries > 0:
        from redis.backoff import ExponentialBackoff
        from redis.retry import Retry

        kwargs["retry"] = Retry(ExponentialBackoff(), cfg.redis_retries)
        kwargs["retry_on_error"] = [RedisConnectionError, RedisTimeoutError]
    return kwargs


def connection_key_of(config: Any) -> Hashable | None:
    """The key ``RedisManager.initialize`` pools this config's client under, or
    None without a configured Redis; the running event loop is part of it."""
    url = configured_redis_url(config)
    if url is None:
        return None
    return pool_key_of_settings(
        url,
        config,
        connection_kwargs_of(config),
        DEFAULT_POOL_SIZE,
        current_scope_or_none(),
    )
