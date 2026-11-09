import logging
import weakref
from collections.abc import Callable
from collections.abc import Hashable as Hashable
from typing import TYPE_CHECKING, Generic, Protocol, TypeVar

from guard_core._parked_records import APP_MANAGERS_RECORD
from guard_core._redis_enablement import (
    RedisFieldsConfig,
    configured_redis_url,
    redis_is_configured,
)
from guard_core.sync._utils.app_scope import (
    SHARED_BY_APPS,
    forget_handlers_of_the_gone_app,
    remember_state_before_the_first_app,
)
from guard_core.sync._utils.config_registry import ConfigHandlerRegistry

if TYPE_CHECKING:
    from guard_core._security_config_fields import RequestT
    from guard_core.models import SecurityConfig
    from guard_core.sync.handlers._redis_shared_clients import PoolKey

_HELD_ATTRIBUTE = APP_MANAGERS_RECORD

_M = TypeVar("_M")


class _PrefixedRedisConfig(RedisFieldsConfig, Protocol):
    @property
    def redis_prefix(self) -> str: ...


class _Held(dict[str, object]):
    """The per-app managers a config keeps alive, valid only for its owner."""

    # A weak reference, not the owner (a strong one makes a cycle that waits for the
    # garbage collector) and not id(owner), whose call costs about twice as much on
    # the response path, where every request asks.
    __slots__ = ("owner",)

    def __init__(self, owner: object) -> None:
        super().__init__()
        self.owner = weakref.ref(owner)

    def __copy__(self) -> "_Held":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_Held":
        return self


def redis_prefixes_differ(
    first: _PrefixedRedisConfig | None, second: _PrefixedRedisConfig
) -> bool:
    return (
        first is not None
        and first is not second
        and redis_is_configured(first)
        and redis_is_configured(second)
        and first.redis_prefix != second.redis_prefix
    )


def share_redis_prefix(
    first: _PrefixedRedisConfig, second: _PrefixedRedisConfig
) -> bool:
    return (
        redis_is_configured(first)
        and redis_is_configured(second)
        and not redis_prefixes_differ(first, second)
    )


def _connection_key_of(config: "SecurityConfig[RequestT]") -> "PoolKey | None":
    if configured_redis_url(config) is None:
        return None
    from guard_core.sync.handlers._redis_shared_clients import connection_key_of

    return connection_key_of(config)


# Only these connection settings print their values: numbers, never a credential.
_NUMERIC_CONNECTION_SETTINGS = frozenset(
    {"socket_connect_timeout", "socket_timeout", "health_check_interval"}
)


def _is_number_or_none(value: object) -> bool:
    return value is None or isinstance(value, (int, float))


def _setting_difference(name: str, first: object, second: object) -> tuple[str, str]:
    if (
        name in _NUMERIC_CONNECTION_SETTINGS
        and _is_number_or_none(first)
        and _is_number_or_none(second)
    ):
        return f"{name}={first}", f"{name}={second}"
    return f"a different {name}", f"a different {name}"


def _differing_connection_settings(
    first: "PoolKey", second: "PoolKey"
) -> list[tuple[str, str]]:
    first_settings = dict(first.connection_kwargs)
    second_settings = dict(second.connection_kwargs)
    return [
        _setting_difference(name, first_settings.get(name), second_settings.get(name))
        for name in sorted(first_settings.keys() | second_settings.keys())
        if first_settings.get(name) != second_settings.get(name)
    ]


def _connection_differences(
    first: "PoolKey | None", second: "PoolKey | None"
) -> list[tuple[str, str]]:
    """What differs between two connections besides the URL, as one text per side:
    the two values of a pool setting, the name of any other setting (a value only
    for a numeric one) and the event loop, never a secret."""
    if first is None or second is None:
        return []
    differences = []
    if first.max_connections != second.max_connections:
        differences.append(
            (
                f"redis_max_connections={first.max_connections}",
                f"redis_max_connections={second.max_connections}",
            )
        )
    if first.pool_timeout != second.pool_timeout:
        differences.append(
            (
                f"redis_pool_timeout={first.pool_timeout}",
                f"redis_pool_timeout={second.pool_timeout}",
            )
        )
    differences.extend(_differing_connection_settings(first, second))
    if first.scope_id != second.scope_id:
        differences.append(("on one event loop", "on another event loop"))
    return differences


def _describe_connection(url: str | None, differences: list[str]) -> str | None:
    if not differences:
        return url
    return f"{url} ({', '.join(differences)})"


def _warn_split_connection(
    first: _PrefixedRedisConfig,
    second: _PrefixedRedisConfig,
    first_key: "PoolKey | None",
    second_key: "PoolKey | None",
) -> None:
    from guard_core.sync.handlers.redis_handler import _redact_redis_url

    differences = _connection_differences(first_key, second_key)
    logging.getLogger("guard_core.sync.handlers.app_managers").warning(
        "Two apps use the Redis prefix %r on different Redis connections (%s and "
        "%s): each keeps its own in-process managers and they share state only "
        "through Redis.",
        first.redis_prefix,
        _describe_connection(
            _redact_redis_url(first.redis_url), [pair[0] for pair in differences]
        ),
        _describe_connection(
            _redact_redis_url(second.redis_url), [pair[1] for pair in differences]
        ),
    )


def mark_shared_by_apps(manager: object, *configs: object) -> None:
    """Record the configs of the apps that share this manager, held weakly."""
    sharing = manager.__dict__.get(SHARED_BY_APPS)
    if sharing is None:
        sharing = weakref.WeakValueDictionary()
        manager.__dict__[SHARED_BY_APPS] = sharing
    for config in configs:
        sharing[id(config)] = config


def unmark_shared_by_apps(manager: object) -> None:
    manager.__dict__.pop(SHARED_BY_APPS, None)


def held_record_of(config: object) -> _Held | None:
    """The record parked on this config, only when this config is its owner."""
    held: _Held | None = config.__dict__.get(_HELD_ATTRIBUTE)
    return held if held is not None and held.owner() is config else None


def hold_for_app(config: object, kind: str, manager: object) -> bool:
    """Keep a per-app manager alive as long as the config of its app.

    The registries below hold managers weakly. The manager references its
    config and the config references the manager, so the pair is freed together
    when the app goes away, whether or not the app uses Redis.
    """
    try:
        held = held_record_of(config)
        if held is None:
            held = _Held(config)
            object.__setattr__(config, _HELD_ATTRIBUTE, held)
        held[kind] = manager
    except (AttributeError, TypeError):
        return False
    return True


def held_for_app(config: object, kind: str) -> object | None:
    """What ``hold_for_app`` kept under ``kind`` for this config, if anything."""
    try:
        held: _Held | None = config.__dict__.get(_HELD_ATTRIBUTE)
    except AttributeError:
        return None
    if held is None or held.owner() is not config:
        return None
    return held.get(kind)


class AppManagers(Generic[_M]):
    """Resolves the manager of one handler kind for the app built from a config.

    State held in Redis is keyed by the prefix string, settings held in config
    by the config object. The module-level default manager serves the first app
    and every app that uses Redis under the same prefix. Any other app, with
    Redis under another prefix or without Redis, gets a manager of its own, found
    by config identity, and it never moves the prefix the default serves.
    """

    def __init__(
        self,
        kind: str,
        warns_on_split_connection: bool = False,
        shares_default_between_apps: bool = True,
    ) -> None:
        self.kind = kind
        self._shares_default = shares_default_between_apps
        self._shared_default: weakref.ref[object] | None = None
        self._warns = warns_on_split_connection
        self._served_key: PoolKey | None = None
        self._own: ConfigHandlerRegistry[_M] = ConfigHandlerRegistry()
        self._default_apps: ConfigHandlerRegistry[_M] = ConfigHandlerRegistry()
        self._served: weakref.ref[_PrefixedRedisConfig] | None = None

    def _default_serves(self) -> _PrefixedRedisConfig | None:
        served = self._served() if self._served is not None else None
        if served is None or self._default_apps.lookup(served, self.kind) is None:
            return None
        return served

    def own(self, config: object) -> _M | None:
        found: _M | None = self._own.lookup(config, self.kind)
        return found

    def uses_default(self, config: object) -> bool:
        return self._default_apps.lookup(config, self.kind) is not None

    def resolve(self, config: object) -> _M | None:
        """The manager serving the app of this config, ``None`` when none does."""
        own = self.own(config)
        return own if own is not None else self._default_apps.lookup(config, self.kind)

    def find(self, config: object, default: _M) -> _M:
        own = self.own(config)
        return own if own is not None else default

    def _serve_from_default(
        self, config: "SecurityConfig[RequestT]", default: _M
    ) -> _M:
        if self._served is None:
            remember_state_before_the_first_app(default)
        elif self._served() is None:
            forget_handlers_of_the_gone_app(default)
        self._default_apps.register(config, default, self.kind)
        self._served = weakref.ref[_PrefixedRedisConfig](config)
        self._served_key = _connection_key_of(config)
        return default

    def bind(
        self, config: "SecurityConfig[RequestT]", default: _M, fresh: Callable[[], _M]
    ) -> _M:
        own = self.own(config)
        if own is not None:
            return own
        served = self._default_serves()
        if served is None or served is config:
            return self._serve_from_default(config, default)
        if self.uses_default(config):
            self._default_apps.register(config, default, self.kind)
            return default
        if share_redis_prefix(served, config):
            key = _connection_key_of(config)
            if self._shares_default and key == self._served_key:
                self._default_apps.register(config, default, self.kind)
                mark_shared_by_apps(default, served, config)
                self._shared_default = weakref.ref(default)
                return default
            if self._warns and key != self._served_key:
                _warn_split_connection(served, config, self._served_key, key)
        manager = fresh()
        self._own.register(config, manager, self.kind)
        hold_for_app(config, self.kind, manager)
        return manager

    def forget_default(self) -> None:
        shared = self._shared_default() if self._shared_default is not None else None
        if shared is not None:
            unmark_shared_by_apps(shared)
        self._shared_default = None
        self._served = None
        self._served_key = None
