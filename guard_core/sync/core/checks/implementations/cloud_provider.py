from collections.abc import Collection
from typing import TYPE_CHECKING, ClassVar

from guard_core.models import SecurityConfig, cloud_blocking_enabled
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.helpers import (
    emit_access_denied_event,
    report_hostile_signal,
    route_config_applies,
)
from guard_core.sync.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity

if TYPE_CHECKING:
    from guard_core.sync.protocols.middleware_protocol import (
        SyncGuardMiddlewareProtocol,
    )


class CloudProviderCheck(SecurityCheck):
    requires: ClassVar[tuple[str, ...]] = ("cloud",)
    container_fields: ClassVar[tuple[str, ...]] = ("block_cloud_providers",)

    def __init__(self, middleware: "SyncGuardMiddlewareProtocol") -> None:
        super().__init__(middleware)
        from guard_core.sync.handlers.cloud_handler import cloud_handler

        self.cloud_handler = cloud_handler

    @property
    def check_name(self) -> str:
        return "cloud_provider"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return cloud_blocking_enabled(config) or route_config_applies(
            route_configs, lambda rc: bool(rc.block_cloud_providers)
        )

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        if (
            getattr(request.state, "is_whitelisted", False)
            or getattr(request.state, "is_exempt", False) is True
        ):
            return None

        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)
        if not client_ip:
            return None

        if self.middleware.route_resolver.should_bypass_check("clouds", route_config):
            return None

        cloud_providers_to_check = (
            self.middleware.route_resolver.get_cloud_providers_to_check(route_config)
        )
        if not cloud_providers_to_check:
            return None

        if not self.cloud_handler.is_cloud_ip(client_ip, set(cloud_providers_to_check)):
            return None

        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Blocked cloud provider IP: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            on_block=self.config.on_block,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )

        self._emit_cloud_block_events(
            request, client_ip, cloud_providers_to_check, route_config
        )

        route_blocks_clouds = bool(route_config and route_config.block_cloud_providers)
        report_hostile_signal(
            self,
            request,
            "cloud",
            f"Blocked cloud provider IP: {client_ip}",
            None if route_blocks_clouds else "ip_blocked",
        )

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=403,
                default_message="Cloud provider IP not allowed",
            )

        return None

    def _emit_cloud_block_events(
        self,
        request: SyncGuardRequest,
        client_ip: str,
        cloud_providers_to_check: list[str],
        route_config: RouteConfig | None,
    ) -> None:
        route_blocks_clouds = bool(route_config and route_config.block_cloud_providers)

        self.middleware.event_bus.send_cloud_detection_events(
            request,
            client_ip,
            cloud_providers_to_check,
            None if route_blocks_clouds else route_config,
            self.cloud_handler,
            self.config.passive_mode,
        )

        if not route_blocks_clouds:
            return

        emit_access_denied_event(
            self.middleware,
            request,
            event_type=EVENT_DECORATOR_VIOLATION,
            reason=f"Cloud provider IP {client_ip} blocked",
            decorator_type="block_clouds",
            passive_mode=self.config.passive_mode,
            violation_type="cloud_provider",
            blocked_providers=list(cloud_providers_to_check),
        )
