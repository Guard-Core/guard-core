from collections.abc import Collection, Sequence
from ipaddress import ip_address

from guard_core._utils.agent_events import agent_receives_events
from guard_core._utils.nat64 import nat64_table_of
from guard_core._utils.rule_attribution import emergency_attribution
from guard_core._utils.sampling import PerApp, SampledKeys, observe_sampled_key
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.events.event_types import EVENT_EMERGENCY_MODE_BLOCK
from guard_core.core.validation.path_matching import path_is_excluded
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import _ip_in_list, extract_client_ip, log_activity

EMERGENCY_RETRY_AFTER = 60
_EMERGENCY_SAMPLE_WINDOW_SECONDS = 60
_MAX_TRACKED_EMERGENCY_CLIENTS = 10_000
_emergency_samples: PerApp[SampledKeys] = PerApp("emergency", SampledKeys)


def _sample_emergency_line(config: object, kind: str, client_ip: str) -> bool:
    samples = _emergency_samples.for_app(config)
    return observe_sampled_key(
        samples.entries,
        samples.lock,
        f"{kind}|{client_ip}",
        window=_EMERGENCY_SAMPLE_WINDOW_SECONDS,
        max_tracked=_MAX_TRACKED_EMERGENCY_CLIENTS,
    )


class EmergencyModeCheck(SecurityCheck):
    enforced_on_excluded_paths = True

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
            _ip_in_list(client_ip_addr, client_ip, entries, nat64_table_of(self.config))
            for entries in self._admitted_lists()
        )

        if not is_whitelisted:
            exempt_paths = self.config.emergency_exempt_paths
            if exempt_paths and path_is_excluded(request.url_path, exempt_paths):
                return None
            return await self._deny(request, client_ip)
        await self._log_allowed(request, client_ip)
        return None

    async def _deny(
        self, request: GuardRequest, client_ip: str
    ) -> GuardResponse | None:
        sampled = _sample_emergency_line(self.config, "block", client_ip)
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"[EMERGENCY MODE] Access denied for IP {client_ip}",
            level=self.config.log_suspicious_level if sampled else None,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            on_block=self.config.on_block,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )

        if sampled:
            await self.middleware.event_bus.send_middleware_event(
                event_type=EVENT_EMERGENCY_MODE_BLOCK,
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason=f"[EMERGENCY MODE] IP {client_ip} not in whitelist",
                emergency_whitelist_count=len(self.config.emergency_whitelist),
                emergency_active=True,
                **(
                    emergency_attribution(self.config)
                    if agent_receives_events(self.middleware.event_bus, self.config)
                    else {}
                ),
            )

        if self.config.passive_mode:
            return None
        response: GuardResponse = await self.middleware.create_error_response(
            status_code=503,
            default_message="Service temporarily unavailable",
        )
        response.headers["Retry-After"] = str(EMERGENCY_RETRY_AFTER)
        return response

    async def _log_allowed(self, request: GuardRequest, client_ip: str) -> None:
        if not _sample_emergency_line(self.config, "allow", client_ip):
            return
        await log_activity(
            request,
            self.logger,
            log_type="info",
            reason=f"[EMERGENCY MODE] Allowed access for whitelisted IP {client_ip}",
            level="INFO",
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )
