from collections.abc import Collection
from typing import TYPE_CHECKING, ClassVar

from guard_core._utils.agent_events import agent_receives_events
from guard_core._utils.rule_attribution import cloud_provider_attribution
from guard_core.core.checks._pending_ban import resolve_pending_ban
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.helpers import (
    emit_access_denied_event,
    report_hostile_signal,
    route_config_applies,
)
from guard_core.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_IP_BLOCKED,
)
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig, cloud_blocking_enabled
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity

if TYPE_CHECKING:
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol


def _cloud_block_reason(client_ip: str, cloud_details: tuple[str, str] | None) -> str:
    reason = f"Blocked cloud provider IP: {client_ip}"
    if cloud_details is None:
        return reason
    provider, network = cloud_details
    return f"{reason} - IP belongs to blocked cloud provider: {provider} ({network})"


class CloudProviderCheck(SecurityCheck):
    requires: ClassVar[tuple[str, ...]] = ("cloud",)
    defers_ban_read = True
    leaves_ban_pending = True
    container_fields: ClassVar[tuple[str, ...]] = ("block_cloud_providers",)

    def __init__(self, middleware: "GuardMiddlewareProtocol") -> None:
        super().__init__(middleware)
        from guard_core.handlers.cloud_handler import cloud_handler_for

        self.cloud_handler = cloud_handler_for(middleware.config)

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

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        if (
            getattr(request.state, "is_whitelisted", False)
            or getattr(request.state, "is_exempt", False) is True
        ):
            return None

        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)
        if not client_ip:
            return None

        cloud_providers_to_check = self._providers_the_client_is_in(
            client_ip, route_config
        )
        if not cloud_providers_to_check:
            return None

        cloud_details = self.cloud_handler.get_cloud_provider_details(
            client_ip, set(cloud_providers_to_check)
        )
        banned = await resolve_pending_ban(request, "cloud")
        if banned is not None:
            return banned
        reason = _cloud_block_reason(client_ip, cloud_details)
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=reason,
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            on_block=self.config.on_block,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )

        await self._emit_cloud_block_events(
            request, client_ip, cloud_providers_to_check, route_config, cloud_details
        )

        route_blocks_clouds = bool(route_config and route_config.block_cloud_providers)
        await report_hostile_signal(
            self,
            request,
            "cloud",
            reason,
            None if route_blocks_clouds else "ip_blocked",
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=403,
                default_message="Cloud provider IP not allowed",
            )

        return None

    def _providers_the_client_is_in(
        self, client_ip: str, route_config: RouteConfig | None
    ) -> list[str]:
        resolver = self.middleware.route_resolver
        if resolver.should_bypass_check("clouds", route_config):
            return []
        providers = resolver.get_cloud_providers_to_check(route_config)
        if providers and self.cloud_handler.is_cloud_ip(client_ip, set(providers)):
            return list(providers)
        return []

    async def _emit_cloud_block_events(
        self,
        request: GuardRequest,
        client_ip: str,
        cloud_providers_to_check: list[str],
        route_config: RouteConfig | None,
        cloud_details: tuple[str, str] | None,
    ) -> None:
        route_blocks_clouds = bool(route_config and route_config.block_cloud_providers)
        attribution = (
            {}
            if route_blocks_clouds
            or not agent_receives_events(self.middleware.event_bus, self.config)
            else self._cloud_attribution(cloud_details)
        )

        await self.middleware.event_bus.send_cloud_detection_events(
            request,
            client_ip,
            cloud_providers_to_check,
            None if route_blocks_clouds else route_config,
            self.cloud_handler,
            self.config.passive_mode,
            cloud_details=cloud_details,
            attribution=attribution,
        )

        if not route_blocks_clouds:
            await self._emit_global_cloud_ip_blocked_event(
                request, client_ip, cloud_details, attribution
            )
            return

        await emit_access_denied_event(
            self.middleware,
            request,
            event_type=EVENT_DECORATOR_VIOLATION,
            reason=f"Cloud provider IP {client_ip} blocked",
            decorator_type="block_clouds",
            passive_mode=self.config.passive_mode,
            violation_type="cloud_provider",
            blocked_providers=list(cloud_providers_to_check),
        )

    def _cloud_attribution(
        self, cloud_details: tuple[str, str] | None
    ) -> dict[str, object]:
        if cloud_details is None:
            return {}
        provider, network = cloud_details
        region = self.cloud_handler.network_regions.get(provider, {}).get(network)
        return cloud_provider_attribution(provider, region)

    async def _emit_global_cloud_ip_blocked_event(
        self,
        request: GuardRequest,
        client_ip: str,
        cloud_details: tuple[str, str] | None,
        attribution: dict[str, object],
    ) -> None:
        reason = f"Blocked cloud provider IP: {client_ip}"
        provider_fields: dict[str, str] = {}
        if cloud_details is not None:
            provider, network = cloud_details
            reason = f"IP belongs to blocked cloud provider: {provider}"
            provider_fields = {"cloud_provider": provider, "network": network}

        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_IP_BLOCKED,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=reason,
            ip_address=client_ip,
            filter_type="global",
            **provider_fields,
            **attribution,
        )
