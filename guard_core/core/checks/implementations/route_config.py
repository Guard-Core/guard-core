from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.route_prefixes import warn_unmatched_exclude_paths
from guard_core.core.events.event_types import EVENT_ROUTE_UNRESOLVED
from guard_core.handlers.cors_handler import is_preflight
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
        if self.config.passive_mode:
            return None
        status = self._unresolved_status(request)
        response: GuardResponse = await self.middleware.create_error_response(
            status_code=status, default_message="Route resolution failed"
        )
        if status == 405 and (allow := self._allow_header(request)):
            response.headers["Allow"] = allow
        return response

    def _allow_header(self, request: GuardRequest) -> str:
        allowed_methods = getattr(self.middleware, "allowed_methods", None)
        if not callable(allowed_methods):
            return ""
        try:
            return ", ".join(sorted(set(allowed_methods(str(request.url_path)))))
        except Exception:
            self.logger.error("allowed_methods failed; omitting Allow")
            return ""

    def _unresolved_status(self, request: GuardRequest) -> int:
        if getattr(request.state, "guard_route_id", None):
            return 500
        resolve_route = getattr(self.middleware, "resolve_route", None)
        if callable(resolve_route):
            try:
                if any(True for _ in resolve_route(str(request.url_path))):
                    return 405
            except Exception:
                self.logger.error("resolve_route failed; answering 500")
                return 500
        return 404

    def _is_cors_preflight(self, request: GuardRequest) -> bool:
        return self.config.enable_cors and is_preflight(request.method, request.headers)

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        warn_unmatched_exclude_paths(self.middleware, self.config)
        route_config = self.middleware.route_resolver.get_route_config(request)
        state = request.state
        state.route_config = route_config
        state.client_ip = await extract_client_ip(
            request, self.config, self.middleware.agent_handler
        )
        if (
            self.config.route_resolution_strict
            and getattr(state, "guard_route_unresolved", False)
            and not self._is_cors_preflight(request)
        ):
            return await self._handle_unresolved_route(request)
        return None
