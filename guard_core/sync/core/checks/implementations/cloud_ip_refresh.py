import time
from collections.abc import Collection
from typing import TYPE_CHECKING, ClassVar

from guard_core.models import SyncSecurityConfig, cloud_blocking_enabled
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.helpers import route_config_applies
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

if TYPE_CHECKING:
    from guard_core.sync.protocols.middleware_protocol import (
        SyncGuardMiddlewareProtocol,
    )


class CloudIpRefreshCheck(SecurityCheck):
    requires: ClassVar[tuple[str, ...]] = ("cloud",)
    container_fields: ClassVar[tuple[str, ...]] = ("block_cloud_providers",)

    def __init__(self, middleware: "SyncGuardMiddlewareProtocol") -> None:
        super().__init__(middleware)
        from guard_core.sync.handlers.cloud_handler import cloud_handler_for

        self.cloud_handler = cloud_handler_for(middleware.config)

    @property
    def check_name(self) -> str:
        return "cloud_ip_refresh"

    @classmethod
    def applies_to(
        cls,
        config: SyncSecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return cloud_blocking_enabled(config) or route_config_applies(
            route_configs, lambda rc: bool(rc.block_cloud_providers)
        )

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
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
            from guard_core.sync.handlers.cloud_handler import cloud_handler

            # An adapter's refresh runs on the module-level manager, so an app with
            # a manager of its own (another prefix) refreshes through that manager.
            adapter_refreshes = (
                adapter_covers_providers and self.cloud_handler is cloud_handler
            )
            scheduled = self.cloud_handler.schedule_refresh(
                providers,
                ttl=self.config.cloud_ip_refresh_interval,
                refresh=self.middleware.refresh_cloud_ip_ranges
                if adapter_refreshes
                else None,
            )
            if not scheduled:
                self.middleware.last_cloud_ip_refresh = previous_refresh
        return None
