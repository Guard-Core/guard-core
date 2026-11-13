from guard_core._misconfiguration import report_declared_path_param_problems
from guard_core._utils.route_gate import route_unknown_to_decorator_problem
from guard_core.core.routing.context import RoutingContext
from guard_core.decorators.base import RouteConfig
from guard_core.handlers._cloud_provider_registry import merge_cloud_selectors
from guard_core.protocols.request_protocol import GuardRequest


class RouteConfigResolver:
    def __init__(self, context: RoutingContext):
        self.context = context

    def _flag_route_unknown_to_decorator(
        self, request: GuardRequest, route_id: str
    ) -> None:
        request.state.guard_route_unresolved = True
        report_declared_path_param_problems(
            self.context.config,
            [route_unknown_to_decorator_problem(route_id)],
            logger=self.context.logger,
            stacklevel=2,
        )

    def get_route_config(self, request: GuardRequest) -> RouteConfig | None:
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
