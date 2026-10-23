from collections.abc import Collection

from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.cors_handler import CorsHandler, is_preflight
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig, SyncSecurityConfig
from guard_core.sync.protocols.middleware_protocol import SyncGuardMiddlewareProtocol
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class CorsPreflightCheck(SecurityCheck):
    """Answers a CORS preflight for an app built without CORS that a flagged
    ``configure(..., enable_cors=True, override_apps=True)`` turned it on for, and
    sends the refusal event of a refused CORS override on every preflight (an app
    built with CORS answers its preflights in its adapter, whose CorsHandler cannot
    the agent).

    It runs after the ban, IP, cloud and user agent checks and before rate limiting,
    so no later check (authentication, API key, required headers) refuses the
    preflight. An app built with CORS on answers its preflights in its adapter.
    """

    def __init__(self, middleware: SyncGuardMiddlewareProtocol) -> None:
        super().__init__(middleware)
        self._cors: CorsHandler | None = None

    @property
    def check_name(self) -> str:
        return "cors_preflight"

    @classmethod
    def applies_to(
        cls,
        config: SyncSecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return True

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        if request.method.upper() != "OPTIONS":
            return None
        manager = self.middleware.response_factory.security_headers_manager
        if isinstance(manager, SecurityHeadersManager):
            manager.send_cors_override_event(self.config)
        if self.config.enable_cors:
            return None
        if self._cors is None:
            self._cors = CorsHandler(self.config)
        if not self._cors.is_enabled():
            return None
        if not is_preflight(request.method, request.headers):
            return None
        preflight = self._cors.build_preflight_response(request.headers)
        response: GuardResponse = self.middleware.create_error_response(
            status_code=preflight.status_code, default_message=preflight.body
        )
        for name, value in preflight.headers.items():
            response.headers[name] = value
        return response
