from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

_RECORD_ATTRIBUTE = "_guard_app_scope"


class AppScope:
    """The config, agent and Redis handler of one app, as its init bound them.

    Two apps on one Redis prefix and connection share their managers, and each
    app's init used to rebind the shared manager's handlers, so the last app
    initialized served every app's events, writes and config. The managers now
    read these three from the scope of the request in flight, so each app routes
    its own. The pipeline sets it where a request's checks start; an app's init
    sets it around its own non-request work.
    """

    __slots__ = ("agent_handler", "config", "redis_handler")

    def __init__(self, config: Any) -> None:
        self.config = config
        self.agent_handler: Any = None
        self.redis_handler: Any = None

    def __copy__(self) -> "AppScope":
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> "AppScope":
        return self


_current_app_scope: ContextVar[AppScope | None] = ContextVar(
    "guard_core_app_scope", default=None
)


class ScopedToApp:
    """A manager attribute served by the app scope in force, else by what was set.

    The value set last (the app that initialized last) answers only outside any
    scope: a call from code that never went through an app's pipeline or init.
    """

    def __set_name__(self, owner: type, name: str) -> None:
        self._name = name

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self
        scope = _current_app_scope.get()
        if scope is None:
            return instance.__dict__.get(self._name)
        return getattr(scope, self._name)

    def __set__(self, instance: Any, value: Any) -> None:
        instance.__dict__[self._name] = value


def app_scope_of(config: Any) -> AppScope:
    """The scope record parked on the config, created on first use."""
    scope: AppScope | None = config.__dict__.get(_RECORD_ATTRIBUTE)
    if scope is None:
        scope = AppScope(config)
        object.__setattr__(config, _RECORD_ATTRIBUTE, scope)
    return scope


def existing_app_scope_of(config: Any) -> AppScope | None:
    found: AppScope | None = config.__dict__.get(_RECORD_ATTRIBUTE)
    return found


@contextmanager
def in_app_scope(scope: AppScope | None) -> Iterator[None]:
    token = _current_app_scope.set(scope)
    try:
        yield
    finally:
        _current_app_scope.reset(token)
