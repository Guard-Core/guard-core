from guard_core.core.routing.context import RoutingContext
from guard_core.decorators.base import RouteConfig
from guard_core.handlers._cloud_provider_registry import merge_cloud_selectors
from guard_core.protocols.request_protocol import GuardRequest


class RouteConfigResolver:
    def __init__(self, context: RoutingContext):
        self.context = context
        self._warned_foreign_route_ids: set[str] = set()

    def _flag_route_unknown_to_decorator(
        self, request: GuardRequest, route_id: str
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
        )

    def get_route_config(self, request: GuardRequest) -> RouteConfig | None:
        guard_decorator = self.context.guard_decorator
        if not guard_decorator:
            guard_decorator = getattr(request.state, "guard_decorator", None)
        if not guard_decorator:
            return None

        route_id = getattr(request.state, "guard_route_id", None)
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
        providers = merge_cloud_selectors(
            self.context.config.block_cloud_providers,
            route_config.block_cloud_providers if route_config else None,
        )
        return list(providers) if providers else None
