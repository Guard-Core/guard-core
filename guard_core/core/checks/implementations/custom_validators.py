from collections.abc import Collection
from typing import TYPE_CHECKING

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.helpers import (
    _increment_suspicious_counts,
    _try_threshold_ban,
    emit_decorator_event,
    route_config_applies,
)
from guard_core.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig, ThreatBanConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity

if TYPE_CHECKING:
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol


class CustomValidatorsCheck(SecurityCheck):
    def __init__(self, middleware: "GuardMiddlewareProtocol") -> None:
        super().__init__(middleware)
        from guard_core.handlers.ipban_handler import ip_ban_manager

        self.ip_ban_manager = ip_ban_manager

    @property
    def check_name(self) -> str:
        return "custom_validators"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return route_config_applies(
            route_configs, lambda rc: bool(rc.custom_validators)
        )

    async def _ban_honeypot_hit(self, request: GuardRequest) -> None:
        client_ip = getattr(request.state, "client_ip", None)
        if not client_ip:
            return
        _increment_suspicious_counts(self.middleware, client_ip, "honeypot")
        await _try_threshold_ban(
            request,
            self.config,
            self.ip_ban_manager,
            self.middleware,
            client_ip,
            "honeypot field filled",
            self.logger,
            self.check_name,
            self.config.muted_check_logs,
            ("honeypot",),
            reason="honeypot_triggered",
            default_entries={
                "honeypot": ThreatBanConfig(
                    threshold=1, duration=self.config.auto_ban_duration
                )
            },
        )

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)
        if not route_config or not route_config.custom_validators:
            return None

        for validator in route_config.custom_validators:
            validation_response = await validator(request)
            if validation_response:
                await log_activity(
                    request,
                    self.logger,
                    log_type="suspicious",
                    reason="Custom validation failed",
                    level=self.config.log_suspicious_level,
                    passive_mode=self.config.passive_mode,
                    check_name=self.check_name,
                    muted_check_logs=self.config.muted_check_logs,
                    on_block=self.config.on_block,
                    sensitive_headers=self.config.log_sensitive_headers,
                    sensitive_params=self.config.log_sensitive_params,
                    sensitive_body_fields=self.config.log_sensitive_body_fields,
                )

                await emit_decorator_event(
                    self.middleware,
                    request,
                    event_type=EVENT_DECORATOR_VIOLATION,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason="Custom validation failed",
                    decorator_type="content_filtering",
                    violation_type="custom_validation",
                    validator_name=getattr(validator, "__name__", "anonymous"),
                )
                if (
                    not self.config.passive_mode
                    and validator in route_config.honeypot_validators
                ):
                    await self._ban_honeypot_hit(request)
                if not self.config.passive_mode and isinstance(
                    validation_response, GuardResponse
                ):
                    return validation_response
        return None
