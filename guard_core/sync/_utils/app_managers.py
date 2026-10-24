import weakref
from collections.abc import Callable
from typing import Any, Generic, TypeVar

from guard_core._redis_enablement import redis_is_configured
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

    def __init__(self, kind: str) -> None:
        self.kind = kind
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
            return default
        if self.uses_default(config) or share_redis_prefix(served, config):
            self._default_apps.register(config, default, self.kind)
            return default
        manager = fresh()
        self._own.register(config, manager, self.kind)
        hold_for_app(config, self.kind, manager)
        return manager

    def forget_default(self) -> None:
        self._served = None
