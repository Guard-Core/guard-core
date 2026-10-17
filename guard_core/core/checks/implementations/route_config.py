from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.route_prefixes import warn_unmatched_exclude_paths
from guard_core.core.events.event_types import EVENT_ROUTE_UNRESOLVED
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import extract_client_ip, log_activity

UNRESOLVED_ROUTE_REASON = (
    "Route resolution failed; per-route decorator config could not be applied"
)


class RouteConfigCheck(SecurityCheck):
    enforced_on_excluded_paths = True

    @property
    def check_name(self) -> str:
        return "route_config"

    async def _handle_unresolved_route(
        self, request: GuardRequest
    ) -> GuardResponse | None:
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=UNRESOLVED_ROUTE_REASON,
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            on_block=self.config.on_block,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )
        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_ROUTE_UNRESOLVED,
            request=request,
            action_taken=(
                "request_blocked" if not self.config.passive_mode else "logged_only"
            ),
            reason=UNRESOLVED_ROUTE_REASON,
        )
        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=500,
                default_message="Route resolution failed",
            )
        return None

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        warn_unmatched_exclude_paths(self.middleware, self.config)
        route_config = self.middleware.route_resolver.get_route_config(request)
        request.state.route_config = route_config
        request.state.client_ip = await extract_client_ip(
            request, self.config, self.middleware.agent_handler
        )
        if self.config.route_resolution_strict and getattr(
            request.state, "guard_route_unresolved", False
        ):
            return await self._handle_unresolved_route(request)
        return None
