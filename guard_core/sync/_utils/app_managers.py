import weakref
from collections.abc import Callable
from typing import Any, Generic, TypeVar

from guard_core._redis_enablement import redis_is_configured
from guard_core.sync._utils.config_registry import REDIS_HANDLERS, ConfigHandlerRegistry

_HELD_ATTRIBUTE = "_guard_app_managers"

_M = TypeVar("_M")


def redis_prefixes_differ(first: Any, second: Any) -> bool:
    return (
        first is not None
        and first is not second
        and redis_is_configured(first)
        and redis_is_configured(second)
        and first.redis_prefix != second.redis_prefix
    )


def hold_for_app(config: Any, kind: str, manager: Any) -> None:
    """Keep a per-app manager alive as long as the app's Redis handler.

    The registries below hold managers weakly, so without an owner a manager
    would be collected once a later app replaced the default's ``_instance``.
    The handler and the manager reference each other, so the pair is freed
    together when the app goes away.
    """
    handler = REDIS_HANDLERS.lookup(config)
    held = getattr(handler, "__dict__", None)
    if held is not None:
        held.setdefault(_HELD_ATTRIBUTE, {})[kind] = manager


class AppManagers(Generic[_M]):
    """Resolves the manager of one handler kind for the app built from a config.

    The module-level default manager serves the first app, and every app that
    shares its Redis prefix or has no Redis, exactly as before. An app that uses
    Redis under another prefix than the app the default serves gets a manager of
    its own, found by config identity, so two apps never share per-app state.
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

    def find(self, config: Any, default: _M) -> _M:
        own = self.own(config)
        return own if own is not None else default

    def bind(self, config: Any, default: _M, fresh: Callable[[], _M]) -> _M:
        own = self.own(config)
        if own is not None:
            return own
        if redis_prefixes_differ(self._default_serves(), config):
            manager = fresh()
            self._own.register(config, manager, self.kind)
            hold_for_app(config, self.kind, manager)
            return manager
        self._default_apps.register(config, default, self.kind)
        self._served = weakref.ref(config)
        return default

    def forget_default(self) -> None:
        self._served = None
