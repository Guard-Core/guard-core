from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING, Generic, TypeVar, overload

from guard_core._parked_records import APP_SCOPE_RECORD
from guard_core._utils.scan_config_scope import _scan_config_scope

if TYPE_CHECKING:
    from guard_core.handlers._ipban_cache import _Network
    from guard_core.models import SecurityConfig
    from guard_core.protocols.agent_protocol import AgentHandlerProtocol
    from guard_core.protocols.redis_protocol import RedisHandlerProtocol

_RECORD_ATTRIBUTE = APP_SCOPE_RECORD
SHARED_BY_APPS = "_guard_shared_by_apps"


class AppScope:
    """The config, agent and Redis handler of one app, as its init bound them.

    Two apps on one Redis prefix and connection share their managers, and each
    app's init used to rebind the shared manager's handlers, so the last app
    initialized served every app's events, writes and config. The managers now
    read these three from the scope of the request in flight, so each app routes
    its own. The pipeline sets it where a request's checks start; an app's init
    sets it around its own non-request work.
    """

    __slots__ = ("agent_handler", "config", "redis_handler", "rule_exempt_networks")

    def __init__(self, config: "SecurityConfig") -> None:
        self.config = config
        self.agent_handler: AgentHandlerProtocol | None = None
        self.redis_handler: RedisHandlerProtocol | None = None
        self.rule_exempt_networks: tuple[_Network, ...] = ()

    def __copy__(self) -> "AppScope":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "AppScope":
        return self


_current_app_scope: ContextVar[AppScope | None] = ContextVar(
    "guard_core_app_scope", default=None
)


_V = TypeVar("_V")


class ScopedToApp(Generic[_V]):
    """A manager attribute served by the app scope in force, else by what was set.

    Outside a pipeline or init, a scan that was handed a config reads that app's
    scope. With no scope at all, the value set last answers only for a manager one
    app owns; a manager several apps share answers the default for the agent and
    the Redis handler, never another app's.
    """

    def __init__(self, default: _V, writes_to_scope: bool = False) -> None:
        self._default = default
        self._writes_to_scope = writes_to_scope

    def __set_name__(self, owner: type, name: str) -> None:
        self._name = name

    @overload
    def __get__(
        self, instance: None, owner: type | None = None
    ) -> "ScopedToApp[_V]": ...

    @overload
    def __get__(self, instance: object, owner: type | None = None) -> _V: ...

    def __get__(
        self, instance: object | None, owner: type | None = None
    ) -> "ScopedToApp[_V] | _V":
        if instance is None:
            return self
        scope = _current_app_scope.get()
        if scope is None:
            scan = _scan_config_scope.get()
            if scan is not None and scan.manager is instance:
                scope = existing_app_scope_of(scan.config)
        if scope is not None:
            served: _V = getattr(scope, self._name)
            return served
        stored = instance.__dict__
        if self._name != "config" and stored.get(SHARED_BY_APPS):
            return self._default
        value: _V = stored.get(self._name, self._default)
        return value

    def __set__(self, instance: object, value: _V) -> None:
        scope = _current_app_scope.get() if self._writes_to_scope else None
        if scope is not None:
            setattr(scope, self._name, value)
        else:
            instance.__dict__[self._name] = value


class ScopedConfig(ScopedToApp["SecurityConfig | None"]):
    def __init__(self) -> None:
        super().__init__(None)


class ScopedAgentHandler(ScopedToApp["AgentHandlerProtocol | None"]):
    def __init__(self) -> None:
        super().__init__(None)


class ScopedRedisHandler(ScopedToApp["RedisHandlerProtocol | None"]):
    def __init__(self) -> None:
        super().__init__(None)


class ScopedRuleExemptNetworks(ScopedToApp["tuple[_Network, ...]"]):
    def __init__(self) -> None:
        super().__init__((), writes_to_scope=True)


def app_scope_of(config: "SecurityConfig") -> AppScope:
    """The scope record parked on the config, created on first use."""
    scope = existing_app_scope_of(config)
    if scope is None:
        scope = AppScope(config)
        object.__setattr__(config, _RECORD_ATTRIBUTE, scope)
    return scope


def existing_app_scope_of(config: "SecurityConfig") -> AppScope | None:
    found: AppScope | None = config.__dict__.get(_RECORD_ATTRIBUTE)
    return found if found is not None and found.config is config else None


def hold_app_scope(config: "SecurityConfig") -> "Token[AppScope | None] | None":
    """Make this app's scope the one in force until ``release_app_scope``.

    The entry point an adapter calls where a request's checks start, so the scope
    also covers the route handler. Returns the token to release with, or None when
    the app has no scope (nothing is set, so an outer app's scope is never
    replaced by None).
    """
    scope = existing_app_scope_of(config)
    return None if scope is None else _current_app_scope.set(scope)


def release_app_scope(token: "Token[AppScope | None] | None") -> None:
    """Restore the scope that was in force before ``hold_app_scope``.

    A sync adapter calls this from a hook that always runs (Flask
    ``teardown_request``, a ``finally`` around Django's ``get_response``).
    """
    if token is not None:
        _current_app_scope.reset(token)


@contextmanager
def in_app_scope(scope: AppScope | None) -> Iterator[None]:
    token = _current_app_scope.set(scope)
    try:
        yield
    finally:
        _current_app_scope.reset(token)
