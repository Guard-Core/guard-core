from guard_core._misconfiguration_kinds import (
    K_ROUTE_UNKNOWN_TO_DECORATOR,
    kinds_log_extra,
)
from guard_core.sync.core.routing.context import RoutingContext
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers._cloud_provider_registry import merge_cloud_selectors
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class RouteConfigResolver:
    def __init__(self, context: RoutingContext):
        self.context = context
        self._warned_foreign_route_ids: set[str] = set()

    def _flag_route_unknown_to_decorator(
        self, request: SyncGuardRequest, route_id: str
    ) -> None:
        request.state.guard_route_unresolved = True
        if route_id in self._warned_foreign_route_ids:
            return
        self._warned_foreign_route_ids.add(route_id)
        self.context.logger.warning(
            "Route %r carries a route id that this SecurityDecorator does not "
            "know: it was decorated by a different SecurityDecorator instance "
            "than the one the middleware uses, so none of its decorators apply.",
            route_id,
            extra=kinds_log_extra(K_ROUTE_UNKNOWN_TO_DECORATOR, route_id),
        )

    def get_route_config(self, request: SyncGuardRequest) -> RouteConfig | None:
        state = request.state
        guard_decorator = self.context.guard_decorator
        if not guard_decorator:
            guard_decorator = getattr(state, "guard_decorator", None)
        if not guard_decorator:
            return None

        route_id = getattr(state, "guard_route_id", None)
        if not route_id:
            return None

        route_config = guard_decorator.get_route_config(route_id)
        if route_config is None:
            self._flag_route_unknown_to_decorator(request, route_id)
        return route_config

    def should_bypass_check(
        self, check_name: str, route_config: RouteConfig | None
    ) -> bool:
        if not route_config:
            return False
        return (
            check_name in route_config.bypassed_checks
            or "all" in route_config.bypassed_checks
        )

    def get_cloud_providers_to_check(
        self, route_config: RouteConfig | None
    ) -> list[str] | None:
        providers = set(self.context.config.block_cloud_providers or ())
        if route_config and route_config.block_cloud_providers:
            providers = merge_cloud_selectors(
                providers, route_config.block_cloud_providers
            )
        return list(providers) if providers else None
