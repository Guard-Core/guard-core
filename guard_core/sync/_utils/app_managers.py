import logging
import weakref
from collections.abc import Callable, Hashable
from typing import Any, Generic, TypeVar

from guard_core._redis_enablement import redis_is_configured
from guard_core.sync._utils.app_scope import SHARED_BY_APPS
from guard_core.sync._utils.config_registry import ConfigHandlerRegistry

_HELD_ATTRIBUTE = "_guard_app_managers"

_M = TypeVar("_M")


class _Held(dict[str, Any]):
    """The per-app managers a config keeps alive. A copy of the config shares it."""

    def __copy__(self) -> "_Held":
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> "_Held":
        return self


def redis_prefixes_differ(first: Any, second: Any) -> bool:
    return (
        first is not None
        and first is not second
        and redis_is_configured(first)
        and redis_is_configured(second)
        and first.redis_prefix != second.redis_prefix
    )


def share_redis_prefix(first: Any, second: Any) -> bool:
    return (
        redis_is_configured(first)
        and redis_is_configured(second)
        and not redis_prefixes_differ(first, second)
    )


def _connection_key_of(config: Any) -> Hashable | None:
    from guard_core.sync.handlers._redis_shared_clients import connection_key_of

    return connection_key_of(config)


def _warn_split_connection(first: Any, second: Any) -> None:
    from guard_core.sync.handlers.redis_handler import _redact_redis_url

    logging.getLogger("guard_core.sync.handlers.app_managers").warning(
        "Two apps use the Redis prefix %r on different Redis connections (%s and "
        "%s): each keeps its own in-process managers and they share state only "
        "through Redis.",
        first.redis_prefix,
        _redact_redis_url(first.redis_url),
        _redact_redis_url(second.redis_url),
    )


def mark_shared_by_apps(manager: Any, *configs: Any) -> None:
    """Record the configs of the apps that share this manager, held weakly."""
    sharing = manager.__dict__.get(SHARED_BY_APPS)
    if sharing is None:
        sharing = weakref.WeakValueDictionary()
        manager.__dict__[SHARED_BY_APPS] = sharing
    for config in configs:
        sharing[id(config)] = config


def unmark_shared_by_apps(manager: Any) -> None:
    manager.__dict__.pop(SHARED_BY_APPS, None)


def hold_for_app(config: Any, kind: str, manager: Any) -> None:
    """Keep a per-app manager alive as long as the config of its app.

    The registries below hold managers weakly. The manager references its
    config and the config references the manager, so the pair is freed together
    when the app goes away, whether or not the app uses Redis.
    """
    try:
        held = config.__dict__.get(_HELD_ATTRIBUTE)
        if held is None:
            held = _Held()
            object.__setattr__(config, _HELD_ATTRIBUTE, held)
        held[kind] = manager
    except (AttributeError, TypeError):
        return


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
        self._shared_default: weakref.ref[Any] | None = None
        self._warns = warns_on_split_connection
        self._served_key: Hashable | None = None
        self._own = ConfigHandlerRegistry()
        self._default_apps = ConfigHandlerRegistry()
        self._served: weakref.ref[Any] | None = None

    def _default_serves(self) -> Any | None:
        served = self._served() if self._served is not None else None
        if served is None or self._default_apps.lookup(served, self.kind) is None:
            return None
        return served

    def own(self, config: Any) -> _M | None:
        found: _M | None = self._own.lookup(config, self.kind)
        return found

    def uses_default(self, config: Any) -> bool:
        return self._default_apps.lookup(config, self.kind) is not None

    def find(self, config: Any, default: _M) -> _M:
        own = self.own(config)
        return own if own is not None else default

    def bind(self, config: Any, default: _M, fresh: Callable[[], _M]) -> _M:
        own = self.own(config)
        if own is not None:
            return own
        served = self._default_serves()
        if served is None or served is config:
            self._default_apps.register(config, default, self.kind)
            self._served = weakref.ref(config)
            self._served_key = _connection_key_of(config)
            return default
        if self.uses_default(config):
            self._default_apps.register(config, default, self.kind)
            return default
        if share_redis_prefix(served, config):
            if self._shares_default and _connection_key_of(config) == self._served_key:
                self._default_apps.register(config, default, self.kind)
                mark_shared_by_apps(default, served, config)
                self._shared_default = weakref.ref(default)
                return default
            if self._warns and _connection_key_of(config) != self._served_key:
                _warn_split_connection(served, config)
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
