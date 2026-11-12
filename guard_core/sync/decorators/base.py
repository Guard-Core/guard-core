import logging
from collections.abc import Callable, Sequence
from typing import (
    ParamSpec,
    Protocol,
    TypeAlias,
    TypeVar,
    runtime_checkable,
)

from guard_core._misconfiguration import (
    report_misconfiguration,
    report_misconfigurations,
)
from guard_core.models import SyncSecurityConfig
from guard_core.sync.decorators.route_config import (
    _REVISION_EXEMPT_ATTRS,
    _TRACKED_DICT_FIELDS,
    _TRACKED_LIST_FIELDS,
    _TRACKED_SET_FIELDS,
    AuthVerifier,
    Principal,
    RouteConfig,
    RouteConfigRevision,
    _RevisionTrackedContainer,
    _TrackedDict,
    _TrackedList,
    _TrackedSet,
)
from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

__all__ = [
    "AuthVerifier",
    "BaseSecurityDecorator",
    "BaseSecurityMixin",
    "DecoratedFunction",
    "GuardedCallable",
    "GuardedParams",
    "GuardedReturn",
    "Principal",
    "RouteConfig",
    "RouteConfigRevision",
    "get_route_decorator_config",
    "get_route_id",
    "_REVISION_EXEMPT_ATTRS",
    "_RevisionTrackedContainer",
    "_TRACKED_DICT_FIELDS",
    "_TRACKED_LIST_FIELDS",
    "_TRACKED_SET_FIELDS",
    "_TrackedDict",
    "_TrackedList",
    "_TrackedSet",
]


_ROUTE_ID_ATTR = "_guard_route_id"


@runtime_checkable
class DecoratedFunction(Protocol):
    _guard_route_id: str

    def __call__(self, *args: object, **kwargs: object) -> object: ...


class _GeoCountryLookup(Protocol):
    def get_country(self, ip: str) -> str | None: ...


GuardedParams = ParamSpec("GuardedParams")
GuardedReturn = TypeVar("GuardedReturn")
GuardedCallable: TypeAlias = Callable[GuardedParams, GuardedReturn]


def get_route_id(func: object) -> str:
    route_id = getattr(func, "_guard_route_id", None)
    if not isinstance(route_id, str):
        raise AttributeError(f"{func!r} is not decorated by a guard route decorator")
    return route_id


class BaseSecurityMixin:
    _report_misconfiguration: Callable[[str], None]
    _report_misconfigurations: Callable[[Sequence[str]], None]
    _require_geo_source: Callable[[str], None]

    def _ensure_route_config(self, func: object) -> RouteConfig:
        raise NotImplementedError("This mixin must be used with BaseSecurityDecorator")

    def _apply_route_config(
        self, func: Callable[GuardedParams, GuardedReturn]
    ) -> Callable[GuardedParams, GuardedReturn]:
        raise NotImplementedError("This mixin must be used with BaseSecurityDecorator")


class BaseSecurityDecorator:
    def __init__(self, config: SyncSecurityConfig) -> None:
        from guard_core.sync.handlers.behavior_handler import BehaviorTracker

        self.config = config
        self._route_configs: dict[str, RouteConfig] = {}
        # id -> id(func) of the function the id was derived from. A stamped
        # _guard_route_id is only reused when THIS instance assigned it to
        # THIS function; otherwise a cross-instance collision would select
        # another route's config.
        self._route_id_owner: dict[str, int] = {}
        self._route_config_revision = RouteConfigRevision()
        self.behavior_tracker = BehaviorTracker(config)
        self.agent_handler: SyncAgentHandlerProtocol | None = None
        self.geo_ip_handler: _GeoCountryLookup | None = None

    def _report_misconfiguration(self, problem: str) -> None:
        report_misconfiguration(
            self.config,
            problem,
            logger=logging.getLogger("guard_core.sync.decorators"),
            stacklevel=4,
        )

    def _report_misconfigurations(self, problems: Sequence[str]) -> None:
        report_misconfigurations(
            self.config,
            problems,
            logger=logging.getLogger("guard_core.sync.decorators"),
            stacklevel=4,
        )

    def _require_geo_source(self, rule: str) -> None:
        if not self.config.fail_on_misconfiguration:
            return
        from guard_core._geo_source import geo_source_problem
        from guard_core.sync.handlers._downloader import TREE_DOWNLOADER

        problem = geo_source_problem(
            rule,
            self.config.geo_ip_handler,
            self.config.ipinfo_token,
            TREE_DOWNLOADER,
        )
        if problem is not None:
            self._report_misconfiguration(problem)

    @property
    def route_config_revision(self) -> int:
        return self._route_config_revision.value

    def get_route_config(self, route_id: str) -> RouteConfig | None:
        return self._route_configs.get(route_id)

    def _get_route_id(self, func: object) -> str:
        route_id = getattr(func, "_guard_route_id", None)
        owner_chain: list[int] = []
        current: object = func
        while current is not None and id(current) not in owner_chain:
            owner_chain.append(id(current))
            current = getattr(current, "__wrapped__", None)
        if (
            isinstance(route_id, str)
            and route_id in self._route_configs
            and self._route_id_owner.get(route_id) in owner_chain
        ):
            # Same instance, same function: stacked decorators intentionally
            # share this config. An id assigned to a DIFFERENT function (in
            # this or another instance) must not select its config.
            return route_id
        # a callable object has no __qualname__ of its own; its class names it
        qualname = getattr(func, "__qualname__", None) or type(func).__qualname__
        route_id = base_id = f"{func.__module__}.{qualname}"
        suffix = 1
        while route_id in self._route_configs:
            suffix += 1
            route_id = f"{base_id}#{suffix}"
        return route_id

    def _ensure_route_config(self, func: object) -> RouteConfig:
        route_id = self._get_route_id(func)
        if route_id not in self._route_configs:
            config = RouteConfig(self._route_config_revision)
            config._inherit_suspicious_detection(
                self.config.enable_penetration_detection
            )
            self._route_configs[route_id] = config
            self._route_config_revision.bump()
        self._route_id_owner.setdefault(route_id, id(func))
        setattr(func, _ROUTE_ID_ATTR, route_id)
        return self._route_configs[route_id]

    def _apply_route_config(
        self, func: Callable[GuardedParams, GuardedReturn]
    ) -> Callable[GuardedParams, GuardedReturn]:
        route_id = self._get_route_id(func)
        setattr(func, _ROUTE_ID_ATTR, route_id)
        return func

    def initialize_behavior_tracking(
        self, redis_handler: SyncRedisHandlerProtocol | None = None
    ) -> None:
        if redis_handler:
            self.behavior_tracker.initialize_redis(redis_handler)

    def initialize_agent(
        self,
        agent_handler: SyncAgentHandlerProtocol,
        geo_ip_handler: _GeoCountryLookup | None = None,
    ) -> None:
        self.agent_handler = agent_handler
        self.geo_ip_handler = geo_ip_handler
        self.behavior_tracker.initialize_agent(agent_handler)

    def send_decorator_event(
        self,
        event_type: str,
        request: SyncGuardRequest,
        action_taken: str,
        reason: str,
        decorator_type: str,
        **kwargs: object,
    ) -> None:
        if not self.agent_handler:
            return

        from guard_core.sync.core.events.middleware_events import SecurityEventBus

        event_bus = SecurityEventBus(
            agent_handler=self.agent_handler,
            config=self.config,
            geo_ip_handler=self.geo_ip_handler,
        )
        event_bus.send_middleware_event(
            event_type=event_type,
            request=request,
            action_taken=action_taken,
            reason=reason,
            decorator_type=decorator_type,
            **kwargs,
        )

    def send_access_denied_event(
        self,
        request: SyncGuardRequest,
        reason: str,
        decorator_type: str,
        action_taken: str = "blocked",
        **metadata: object,
    ) -> None:
        from guard_core.sync.core.events.event_types import EVENT_ACCESS_DENIED

        self.send_decorator_event(
            event_type=EVENT_ACCESS_DENIED,
            request=request,
            action_taken=action_taken,
            reason=reason,
            decorator_type=decorator_type,
            **metadata,
        )

    def send_authentication_failed_event(
        self,
        request: SyncGuardRequest,
        reason: str,
        auth_type: str,
        action_taken: str = "blocked",
        **metadata: object,
    ) -> None:
        from guard_core.sync.core.events.event_types import EVENT_AUTHENTICATION_FAILED

        self.send_decorator_event(
            event_type=EVENT_AUTHENTICATION_FAILED,
            request=request,
            action_taken=action_taken,
            reason=reason,
            decorator_type="authentication",
            auth_type=auth_type,
            **metadata,
        )

    def send_rate_limit_event(
        self,
        request: SyncGuardRequest,
        limit: int,
        window: int,
        action_taken: str = "blocked",
        **metadata: object,
    ) -> None:
        from guard_core.sync.core.events.event_types import EVENT_RATE_LIMITED

        self.send_decorator_event(
            event_type=EVENT_RATE_LIMITED,
            request=request,
            action_taken=action_taken,
            reason=f"Rate limit exceeded: {limit} requests per {window}s",
            decorator_type="rate_limiting",
            limit=limit,
            window=window,
            **metadata,
        )

    def send_decorator_violation_event(
        self,
        request: SyncGuardRequest,
        violation_type: str,
        reason: str,
        **metadata: object,
    ) -> None:
        from guard_core.sync.core.events.event_types import EVENT_DECORATOR_VIOLATION

        self.send_decorator_event(
            event_type=EVENT_DECORATOR_VIOLATION,
            request=request,
            action_taken="blocked",
            reason=reason,
            decorator_type=violation_type,
            **metadata,
        )


def get_route_decorator_config(
    request: SyncGuardRequest, decorator_handler: BaseSecurityDecorator
) -> RouteConfig | None:
    route_id = getattr(request.state, "guard_route_id", None)
    if route_id:
        return decorator_handler.get_route_config(route_id)
    return None
