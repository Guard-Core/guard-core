import inspect
import weakref
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING, Generic, TypeVar, overload

from guard_core._parked_records import APP_SCOPE_RECORD
from guard_core.sync._utils.scan_config_scope import _scan_config_scope

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.handlers._ipban_cache import _Network
    from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
    from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol

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

    # The config is held weakly: the scope is parked on the config's __dict__, so a
    # strong reference is a cycle that frees a dropped config only at a gc pass.
    __slots__ = (
        "config_ref",
        "agent_handler",
        "redis_handler",
        "rule_exempt_networks",
    )

    def __init__(self, config: "SyncSecurityConfig") -> None:
        self.config_ref = weakref.ref(config)
        self.agent_handler: SyncAgentHandlerProtocol | None = None
        self.redis_handler: SyncRedisHandlerProtocol | None = None
        self.rule_exempt_networks: tuple[_Network, ...] = ()

    @property
    def config(self) -> "SyncSecurityConfig | None":
        """The app's config, ``None`` once the app that owned it is gone."""
        return self.config_ref()

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

    _weak_key: str | None = None

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
        if self._weak_key is not None:
            return self._or_weakly_held(stored, value)
        return value

    def _or_weakly_held(self, stored: Mapping[str, object], value: _V) -> _V:
        if value is not None or self._weak_key is None:
            return value
        held = stored.get(self._weak_key)
        resolved = held() if isinstance(held, weakref.ref) else None
        return value if resolved is None else resolved

    def __set__(self, instance: object, value: _V) -> None:
        scope = _current_app_scope.get() if self._writes_to_scope else None
        if scope is not None:
            setattr(scope, self._name, value)
        else:
            instance.__dict__[self._name] = value


class ScopedConfig(ScopedToApp["SyncSecurityConfig | None"]):
    _config_weak_key: str

    def __init__(self) -> None:
        super().__init__(None)

    def __set_name__(self, owner: type, name: str) -> None:
        super().__set_name__(owner, name)
        self._weak_key = self._config_weak_key = _weak_key(name)

    @overload
    def __get__(self, instance: None, owner: type | None = None) -> "ScopedConfig": ...

    @overload
    def __get__(
        self, instance: object, owner: type | None = None
    ) -> "SyncSecurityConfig | None": ...

    def __get__(
        self, instance: object | None, owner: type | None = None
    ) -> "ScopedConfig | SyncSecurityConfig | None":
        # Hot path: no scope in force, so the config set last (strongly, else the
        # weakly held one) answers; anything else takes the general rule.
        if (
            instance is not None
            and _current_app_scope.get() is None
            and _scan_config_scope.get() is None
        ):
            stored = instance.__dict__
            value: SyncSecurityConfig | None = stored.get(self._name)
            if value is None:
                weak = stored.get(self._config_weak_key)
                if weak is not None:
                    value = weak()
            if value is not None:
                return value
        return super().__get__(instance, owner)

    def __set__(self, instance: object, value: "SyncSecurityConfig | None") -> None:
        instance.__dict__.pop(_weak_key(self._name), None)
        super().__set__(instance, value)


class WeakableConfig:
    """A config attribute a module singleton can serve without owning the app.

    ``manager.attribute = value`` keeps the value strongly, as a plain attribute
    does. ``hold_config_weakly`` serves it until the app that owns it is gone.
    Read on the class it returns the descriptor itself.
    """

    def __set_name__(self, owner: type, name: str) -> None:
        self._name = name
        self._weak_key = _weak_key(name)
        self._held_key = _held_key(name)

    @overload
    def __get__(
        self, instance: None, owner: type | None = None
    ) -> "WeakableConfig": ...

    @overload
    def __get__(
        self, instance: object, owner: type | None = None
    ) -> "SyncSecurityConfig | None": ...

    def __get__(
        self, instance: object | None, owner: type | None = None
    ) -> "WeakableConfig | SyncSecurityConfig | None":
        if instance is None:
            return self
        stored = instance.__dict__
        value: SyncSecurityConfig | None = stored.get(self._name)
        if value is not None:
            return value
        kept: SyncSecurityConfig | None = stored.get(self._held_key)
        if kept is not None:
            return kept
        held: weakref.ref[SyncSecurityConfig] | None = stored.get(self._weak_key)
        return None if held is None else held()

    def __set__(self, instance: object, value: "SyncSecurityConfig | None") -> None:
        instance.__dict__.pop(_weak_key(self._name), None)
        instance.__dict__[self._name] = value


class ScopedAgentHandler(ScopedToApp["SyncAgentHandlerProtocol | None"]):
    def __init__(self) -> None:
        super().__init__(None)


class ScopedRedisHandler(ScopedToApp["SyncRedisHandlerProtocol | None"]):
    def __init__(self) -> None:
        super().__init__(None)


class ScopedRuleExemptNetworks(ScopedToApp["tuple[_Network, ...]"]):
    def __init__(self) -> None:
        super().__init__((), writes_to_scope=True)


def _weak_key(attribute: str) -> str:
    return f"_guard_weak_{attribute}"


def _held_key(attribute: str) -> str:
    return f"_guard_held_{attribute}"


def _reclaim_displaced_slot(manager: object, attribute: str) -> None:
    """Put the config descriptor back when a plain value replaced it on the class.

    v4.4.0 code resets the default manager with ``Manager._config = None``, which
    replaces the descriptor; the instance's held and weak entries would then be
    invisible and a hand-built manager would read no config at all.
    """
    owner = type(manager)
    if hasattr(inspect.getattr_static(owner, attribute, None), "__set__"):
        return
    slot = WeakableConfig()
    slot.__set_name__(owner, attribute)
    setattr(owner, attribute, slot)


def weakly_held_config(manager: object, attribute: str) -> "SyncSecurityConfig | None":
    held: weakref.ref[SyncSecurityConfig] | None = manager.__dict__.get(
        _weak_key(attribute)
    )
    return None if held is None else held()


def hold_config_weakly(
    manager: object, config: object, attribute: str = "config"
) -> None:
    """Serve this config from a manager attribute without keeping its app alive.

    A module singleton manager holds the config of the first app, so a strong
    reference keeps that app's config, scope and handlers for the life of the
    process, and every later app on another prefix is told the first is still
    running. A plain assignment to the attribute stays strong. A config that
    cannot be weakly referenced stays held strongly.
    """
    _reclaim_displaced_slot(manager, attribute)
    manager.__dict__.pop(attribute, None)
    manager.__dict__.pop(_held_key(attribute), None)
    manager.__dict__.pop(_weak_key(attribute), None)
    try:
        manager.__dict__[_weak_key(attribute)] = weakref.ref(config)
    except TypeError:
        manager.__dict__[_held_key(attribute)] = config


def hold_config_until_adopted(
    manager: object, config: object, attribute: str = "config"
) -> None:
    """Keep the config strongly, as v4.4.0 did, without marking the manager as
    one that owns an app of its own; ``release_config_to_app`` lets it go."""
    _reclaim_displaced_slot(manager, attribute)
    manager.__dict__[_held_key(attribute)] = config


def release_config_to_app(
    manager: object, config: object, attribute: str = "config"
) -> None:
    """Once an app adopts a manager built with its config, the app owns the config
    and the manager serves it weakly. A manager nobody adopted keeps it strong."""
    stored = manager.__dict__
    if stored.get(attribute) is config or stored.get(_held_key(attribute)) is config:
        hold_config_weakly(manager, config, attribute)


def serve_config_of_the_live_app(
    manager: object, config: "SyncSecurityConfig", attribute: str = "config"
) -> None:
    """Point a singleton whose app is gone at the app now using it, never away
    from an app still alive."""
    if (
        attribute not in manager.__dict__
        and _held_key(attribute) not in manager.__dict__
        and weakly_held_config(manager, attribute) is None
    ):
        hold_config_weakly(manager, config, attribute)


def forget_config(manager: object, attribute: str) -> None:
    manager.__dict__.pop(attribute, None)
    manager.__dict__.pop(_held_key(attribute), None)
    manager.__dict__.pop(_weak_key(attribute), None)


def forget_handlers_of_the_gone_app(manager: object) -> None:
    """Drop the Redis and agent handlers a default manager kept for an app that is
    gone, so the next app is not served a handler built for the previous one, and
    whatever else the manager keeps per app (it says so in
    ``forget_state_of_the_gone_app``)."""
    for name in ("redis_handler", "agent_handler"):
        if isinstance(inspect.getattr_static(type(manager), name, None), ScopedToApp):
            manager.__dict__.pop(name, None)
    forget_other_state = getattr(manager, "forget_state_of_the_gone_app", None)
    if forget_other_state is not None:
        forget_other_state()


def remember_state_before_the_first_app(manager: object) -> None:
    """Let a default manager record what it holds before the first app binds, so a
    takeover from a gone app can restore it."""
    remember = getattr(manager, "remember_state_before_the_first_app", None)
    if remember is not None:
        remember()


def app_scope_of(config: "SyncSecurityConfig") -> AppScope:
    """The scope record parked on the config, created on first use."""
    scope = existing_app_scope_of(config)
    if scope is None:
        scope = AppScope(config)
        object.__setattr__(config, _RECORD_ATTRIBUTE, scope)
    return scope


def existing_app_scope_of(config: "SyncSecurityConfig") -> AppScope | None:
    found: AppScope | None = config.__dict__.get(_RECORD_ATTRIBUTE)
    return found if found is not None and found.config_ref() is config else None


def hold_app_scope(config: "SyncSecurityConfig") -> "Token[AppScope | None] | None":
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
