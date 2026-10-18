import time
from collections.abc import Collection
from typing import TYPE_CHECKING, ClassVar

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.helpers import route_config_applies
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig, cloud_blocking_enabled
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

if TYPE_CHECKING:
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol


class CloudIpRefreshCheck(SecurityCheck):
    requires: ClassVar[tuple[str, ...]] = ("cloud",)
    container_fields: ClassVar[tuple[str, ...]] = ("block_cloud_providers",)

    def __init__(self, middleware: "GuardMiddlewareProtocol") -> None:
        super().__init__(middleware)
        from guard_core.handlers.cloud_handler import cloud_handler

        self.cloud_handler = cloud_handler

    @property
    def check_name(self) -> str:
        return "cloud_ip_refresh"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return cloud_blocking_enabled(config) or route_config_applies(
            route_configs, lambda rc: bool(rc.block_cloud_providers)
        )

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)
        cloud_providers_to_check = (
            self.middleware.route_resolver.get_cloud_providers_to_check(route_config)
        )
        if not cloud_providers_to_check:
            return None

        if (
            time.time() - self.middleware.last_cloud_ip_refresh
            > self.config.cloud_ip_refresh_interval
        ):
            previous_refresh = self.middleware.last_cloud_ip_refresh
            self.middleware.last_cloud_ip_refresh = int(time.time())
            providers = set(cloud_providers_to_check)
            adapter_covers_providers = providers <= set(
                self.config.block_cloud_providers or ()
            )
            scheduled = await self.cloud_handler.schedule_refresh(
                providers,
                ttl=self.config.cloud_ip_refresh_interval,
                refresh=self.middleware.refresh_cloud_ip_ranges
                if adapter_covers_providers
                else None,
            )
            if not scheduled:
                self.middleware.last_cloud_ip_refresh = previous_refresh
        return None
