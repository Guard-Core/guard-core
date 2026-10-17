from collections.abc import Collection, Sequence
from ipaddress import ip_address

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.events.event_types import EVENT_EMERGENCY_MODE_BLOCK
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import _ip_in_list, extract_client_ip, log_activity


class EmergencyModeCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "emergency_mode"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return config.emergency_mode or config.enable_dynamic_rules

    def _admitted_lists(self) -> tuple[Sequence[str] | None, ...]:
        if self.config.emergency_whitelist_only:
            return (self.config.emergency_whitelist,)
        return (
            self.config.emergency_whitelist,
            self.config.whitelist,
            self.config.exempt_ips,
        )

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        if not self.config.emergency_mode:
            return None

        client_ip = getattr(request.state, "client_ip", None)
        if not client_ip:
            client_ip = await extract_client_ip(
                request, self.config, self.middleware.agent_handler
            )

        try:
            client_ip_addr = ip_address(client_ip)
        except ValueError:
            client_ip_addr = None

        is_whitelisted = client_ip_addr is not None and any(
            _ip_in_list(client_ip_addr, client_ip, entries)
            for entries in self._admitted_lists()
        )

        if not is_whitelisted:
            await log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"[EMERGENCY MODE] Access denied for IP {client_ip}",
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
                event_type=EVENT_EMERGENCY_MODE_BLOCK,
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason=f"[EMERGENCY MODE] IP {client_ip} not in whitelist",
                emergency_whitelist_count=len(self.config.emergency_whitelist),
                emergency_active=True,
            )

            if not self.config.passive_mode:
                return await self.middleware.create_error_response(
                    status_code=503,
                    default_message="Service temporarily unavailable",
                )
        else:
            await log_activity(
                request,
                self.logger,
                log_type="info",
                reason=(
                    f"[EMERGENCY MODE] Allowed access for whitelisted IP {client_ip}"
                ),
                level="INFO",
                check_name=self.check_name,
                muted_check_logs=self.config.muted_check_logs,
                sensitive_headers=self.config.log_sensitive_headers,
                sensitive_params=self.config.log_sensitive_params,
                sensitive_body_fields=self.config.log_sensitive_body_fields,
            )

        return None
