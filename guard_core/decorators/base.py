from collections.abc import Callable
from typing import (
    Any,
    Protocol,
    cast,
    runtime_checkable,
)

from guard_core.decorators.route_config import (
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
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest

__all__ = [
    "AuthVerifier",
    "BaseSecurityDecorator",
    "BaseSecurityMixin",
    "DecoratedFunction",
    "Principal",
    "RouteConfig",
    "RouteConfigRevision",
    "get_route_decorator_config",
    "_REVISION_EXEMPT_ATTRS",
    "_RevisionTrackedContainer",
    "_TRACKED_DICT_FIELDS",
    "_TRACKED_LIST_FIELDS",
    "_TRACKED_SET_FIELDS",
    "_TrackedDict",
    "_TrackedList",
    "_TrackedSet",
]


@runtime_checkable
class DecoratedFunction(Protocol):
    _guard_route_id: str

    def __call__(self, *args: Any, **kwargs: Any) -> Any: ...


class BaseSecurityMixin:
    def _ensure_route_config(self, func: Callable[..., Any]) -> RouteConfig:
        raise NotImplementedError("This mixin must be used with BaseSecurityDecorator")

    def _apply_route_config(self, func: Callable[..., Any]) -> "DecoratedFunction":
        raise NotImplementedError("This mixin must be used with BaseSecurityDecorator")


class BaseSecurityDecorator:
    def __init__(self, config: SecurityConfig) -> None:
        from guard_core.handlers.behavior_handler import BehaviorTracker

        self.config = config
        self._route_configs: dict[str, RouteConfig] = {}
        self._route_config_revision = RouteConfigRevision()
        self.behavior_tracker = BehaviorTracker(config)
        self.agent_handler: Any = None
        self.geo_ip_handler: Any = None

    @property
    def route_config_revision(self) -> int:
        return self._route_config_revision.value

    def get_route_config(self, route_id: str) -> RouteConfig | None:
        return self._route_configs.get(route_id)

    def _get_route_id(self, func: Callable[..., Any]) -> str:
        route_id = getattr(func, "_guard_route_id", None)
        if isinstance(route_id, str):
            return route_id
        route_id = base_id = f"{func.__module__}.{func.__qualname__}"
        suffix = 1
        while route_id in self._route_configs:
            suffix += 1
            route_id = f"{base_id}#{suffix}"
        return route_id

    def _ensure_route_config(self, func: Callable[..., Any]) -> RouteConfig:
        route_id = self._get_route_id(func)
        if route_id not in self._route_configs:
            config = RouteConfig(self._route_config_revision)
            config.enable_suspicious_detection = (
                self.config.enable_penetration_detection
            )
            self._route_configs[route_id] = config
            self._route_config_revision.bump()
        cast(Any, func)._guard_route_id = route_id
        return self._route_configs[route_id]

    def _apply_route_config(self, func: Callable[..., Any]) -> DecoratedFunction:
        route_id = self._get_route_id(func)
        cast(Any, func)._guard_route_id = route_id
        return cast(DecoratedFunction, func)

    async def initialize_behavior_tracking(self, redis_handler: Any = None) -> None:
        if redis_handler:
            await self.behavior_tracker.initialize_redis(redis_handler)

    async def initialize_agent(
        self, agent_handler: Any, geo_ip_handler: Any = None
    ) -> None:
        self.agent_handler = agent_handler
        self.geo_ip_handler = geo_ip_handler
        await self.behavior_tracker.initialize_agent(agent_handler)

    async def send_decorator_event(
        self,
        event_type: str,
        request: GuardRequest,
        action_taken: str,
        reason: str,
        decorator_type: str,
        **kwargs: Any,
    ) -> None:
        if not self.agent_handler:
            return

        from guard_core.core.events.middleware_events import SecurityEventBus

        event_bus = SecurityEventBus(
            agent_handler=self.agent_handler,
            config=self.config,
            geo_ip_handler=self.geo_ip_handler,
        )
        await event_bus.send_middleware_event(
            event_type=event_type,
            request=request,
            action_taken=action_taken,
            reason=reason,
            decorator_type=decorator_type,
            **kwargs,
        )

    async def send_access_denied_event(
        self,
        request: GuardRequest,
        reason: str,
        decorator_type: str,
        **metadata: Any,
    ) -> None:
        from guard_core.core.events.event_types import EVENT_ACCESS_DENIED

        await self.send_decorator_event(
            event_type=EVENT_ACCESS_DENIED,
            request=request,
            action_taken="blocked",
            reason=reason,
            decorator_type=decorator_type,
            **metadata,
        )

    async def send_authentication_failed_event(
        self,
        request: GuardRequest,
        reason: str,
        auth_type: str,
        **metadata: Any,
    ) -> None:
        from guard_core.core.events.event_types import EVENT_AUTHENTICATION_FAILED

        await self.send_decorator_event(
            event_type=EVENT_AUTHENTICATION_FAILED,
            request=request,
            action_taken="blocked",
            reason=reason,
            decorator_type="authentication",
            auth_type=auth_type,
            **metadata,
        )

    async def send_rate_limit_event(
        self,
        request: GuardRequest,
        limit: int,
        window: int,
        **metadata: Any,
    ) -> None:
        from guard_core.core.events.event_types import EVENT_RATE_LIMITED

        await self.send_decorator_event(
            event_type=EVENT_RATE_LIMITED,
            request=request,
            action_taken="blocked",
            reason=f"Rate limit exceeded: {limit} requests per {window}s",
            decorator_type="rate_limiting",
            limit=limit,
            window=window,
            **metadata,
        )

    async def send_decorator_violation_event(
        self,
        request: GuardRequest,
        violation_type: str,
        reason: str,
        **metadata: Any,
    ) -> None:
        from guard_core.core.events.event_types import EVENT_DECORATOR_VIOLATION

        await self.send_decorator_event(
            event_type=EVENT_DECORATOR_VIOLATION,
            request=request,
            action_taken="blocked",
            reason=reason,
            decorator_type=violation_type,
            **metadata,
        )


def get_route_decorator_config(
    request: GuardRequest, decorator_handler: BaseSecurityDecorator
) -> RouteConfig | None:
    route_id = getattr(request.state, "guard_route_id", None)
    if route_id:
        return decorator_handler.get_route_config(route_id)
    return None
