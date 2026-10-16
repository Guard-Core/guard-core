from collections.abc import Collection

from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.ip_extraction import _is_trusted_proxy
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.helpers import route_config_applies
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class HttpsEnforcementCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "https_enforcement"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return config.enforce_https or route_config_applies(
            route_configs, lambda rc: rc.require_https
        )

    def _is_request_https(self, request: SyncGuardRequest) -> bool:
        is_https = request.url_scheme == "https"

        if (
            self.config.trust_x_forwarded_proto
            and self.config.trusted_proxies
            and request.client_host
        ):
            if self._is_trusted_proxy(request.client_host):
                forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
                is_https = is_https or forwarded_proto.lower() == "https"

        return is_https

    def _is_trusted_proxy(self, connecting_ip: str) -> bool:
        return _is_trusted_proxy(connecting_ip, self.config.trusted_proxies)

    def _create_https_redirect(self, request: SyncGuardRequest) -> GuardResponse:
        result: GuardResponse = self.middleware.response_factory.create_https_redirect(
            request
        )
        return result

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)

        https_required = (
            route_config.require_https if route_config else self.config.enforce_https
        )
        if not https_required:
            return None

        if self._is_request_https(request):
            return None

        self.middleware.event_bus.send_https_violation_event(request, route_config)

        if not self.config.passive_mode:
            return self._create_https_redirect(request)

        return None
