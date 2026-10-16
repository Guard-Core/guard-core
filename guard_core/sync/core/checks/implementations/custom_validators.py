from collections.abc import Collection
from typing import TYPE_CHECKING

from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.helpers import (
    count_hostile_signal_and_maybe_ban,
    emit_decorator_event,
    route_config_applies,
)
from guard_core.sync.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity

if TYPE_CHECKING:
    pass


class CustomValidatorsCheck(SecurityCheck):
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

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)
        if not route_config or not route_config.custom_validators:
            return None

        for validator in route_config.custom_validators:
            validation_response = validator(request)
            if validation_response:
                log_activity(
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

                emit_decorator_event(
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
                    count_hostile_signal_and_maybe_ban(
                        self, request, "honeypot", "honeypot field filled", 1
                    )
                if not self.config.passive_mode and isinstance(
                    validation_response, GuardResponse
                ):
                    return validation_response
        return None
