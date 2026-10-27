from __future__ import annotations

import threading
import weakref
from collections.abc import Hashable
from typing import TYPE_CHECKING, Protocol

from guard_core._redis_enablement import configured_redis_url
from guard_core._redis_exceptions import RedisConnectionError, RedisTimeoutError
from guard_core._utils.config_registry import ConfigHandlerRegistry

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from guard_core.handlers.redis_handler import RedisManager
    from guard_core.models import SecurityConfig

DEFAULT_POOL_SIZE = 100


class RedisClientCloser(Protocol):
    async def _safe_aclose(self, client: Redis) -> None: ...


class RedisClientOwner(RedisClientCloser, Protocol):
    def _connection_kwargs(
        self, config: SecurityConfig | None = None
    ) -> dict[str, object]: ...


class RedisClientBuilder(Protocol):
    def __call__(
        self,
        url: str,
        max_connections: int,
        pool_timeout: float,
        **connection_kwargs: object,
    ) -> Redis: ...


def current_scope() -> object:
    import asyncio

    return asyncio.get_running_loop()


def current_scope_or_none() -> object | None:
    import asyncio

    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


class _Entry:
    __slots__ = ("client", "owners", "scope")

    def __init__(self, client: Redis, scope: object, owner: object) -> None:
        self.client = client
        self.scope = weakref.ref(scope)
        self.owners: weakref.WeakSet[object] = weakref.WeakSet([owner])


_entries: dict[Hashable, _Entry] = {}
_entries_lock = threading.Lock()


def _freeze(value: object) -> Hashable:
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
    connection_kwargs: dict[str, object],
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
    config: SecurityConfig,
    connection_kwargs: dict[str, object],
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


def acquire(key: Hashable, scope: object, owner: object) -> Redis | None:
    """The shared client for key with owner added, or None when none is live."""
    with _entries_lock:
        entry = _live_entry(key, scope)
        if entry is None:
            return None
        entry.owners.add(owner)
        return entry.client


def publish(key: Hashable, scope: object, client: Redis, owner: object) -> Redis:
    """Make client the shared one for key; a client published first wins."""
    with _entries_lock:
        entry = _live_entry(key, scope)
        if entry is None:
            _entries[key] = _Entry(client, scope, owner)
            return client
        entry.owners.add(owner)
        return entry.client


def release(key: Hashable, client: Redis, owner: object) -> bool:
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


_MANAGERS: ConfigHandlerRegistry[RedisManager] = ConfigHandlerRegistry()


def _manager_kind(manager_class: type[RedisManager]) -> str:
    return f"{manager_class.__module__}.{manager_class.__qualname__}"


def existing_manager(
    config: SecurityConfig, manager_class: type[RedisManager]
) -> RedisManager | None:
    """The manager built for this config object, held weakly, or None."""
    return _MANAGERS.lookup(config, _manager_kind(manager_class))


def register_manager(
    config: SecurityConfig, manager: RedisManager, manager_class: type[RedisManager]
) -> None:
    _MANAGERS.register(config, manager, _manager_kind(manager_class))


def open_client(
    owner: RedisClientOwner,
    url: str,
    config: SecurityConfig,
    build: RedisClientBuilder,
    default_pool_size: int,
) -> tuple[Redis, Hashable, object, bool]:
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


async def register_client(
    owner: RedisClientCloser, client: Redis, key: Hashable, scope: object
) -> Redis:
    published = publish(key, scope, client, owner)
    if published is not client:
        await owner._safe_aclose(client)
    return published


def connection_kwargs_of(cfg: SecurityConfig) -> dict[str, object]:
    """Connection tuning passed to ``Redis.from_url``.

    Without bounded timeouts a partitioned Redis blocks every request that
    touches it indefinitely, so these default to non-None. Any value already
    encoded in ``redis_url`` query params still wins (redis-py applies URL
    params last), so this only sets a floor.
    """
    kwargs: dict[str, object] = {
        "socket_connect_timeout": cfg.redis_socket_connect_timeout,
        "socket_timeout": cfg.redis_socket_timeout,
        "health_check_interval": cfg.redis_health_check_interval,
    }
    if cfg.redis_retries > 0:
        from redis.asyncio.retry import Retry
        from redis.backoff import ExponentialBackoff

        kwargs["retry"] = Retry(ExponentialBackoff(), cfg.redis_retries)
        kwargs["retry_on_error"] = [RedisConnectionError, RedisTimeoutError]
    return kwargs


def connection_key_of(config: SecurityConfig) -> Hashable | None:
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
