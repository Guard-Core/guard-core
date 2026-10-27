from collections.abc import Collection

from guard_core._utils.forwarded_proto import request_is_https
from guard_core._utils.ip_extraction import _is_trusted_proxy
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.helpers import route_config_applies
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

_NO_FACTORY = "'NoneType' object has no attribute '{}'"


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

    def _is_request_https(self, request: GuardRequest) -> bool:
        return request_is_https(request, self.config)

    def _is_trusted_proxy(self, connecting_ip: str) -> bool:
        return _is_trusted_proxy(connecting_ip, self.config.trusted_proxies)

    async def _create_https_redirect(self, request: GuardRequest) -> GuardResponse:
        response_factory = self.middleware.response_factory
        if response_factory is None:
            raise AttributeError(_NO_FACTORY.format("create_https_redirect"))
        result: GuardResponse = await response_factory.create_https_redirect(request)
        return result

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)

        https_required = self.config.enforce_https or bool(
            route_config and route_config.require_https
        )
        if not https_required:
            return None

        if self._is_request_https(request):
            return None

        await self.middleware.event_bus.send_https_violation_event(
            request, route_config
        )

        if not self.config.passive_mode:
            return await self._create_https_redirect(request)

        return None
