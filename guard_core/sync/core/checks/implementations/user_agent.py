from collections.abc import Collection
from typing import TYPE_CHECKING, ClassVar

from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.request_logging import redact_header_value_for_display
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.helpers import (
    check_user_agent_allowed,
    emit_decorator_event,
    report_hostile_signal,
    route_config_applies,
)
from guard_core.sync.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_USER_AGENT_BLOCKED,
)
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity

if TYPE_CHECKING:
    pass


class UserAgentCheck(SecurityCheck):
    container_fields: ClassVar[tuple[str, ...]] = ("blocked_user_agents",)

    @property
    def check_name(self) -> str:
        return "user_agent"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return (
            bool(config.blocked_user_agents)
            or route_config_applies(
                route_configs, lambda rc: bool(rc.blocked_user_agents)
            )
            or config.enable_dynamic_rules
        )

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        if (
            getattr(request.state, "is_whitelisted", False)
            or getattr(request.state, "is_exempt", False) is True
        ):
            return None

        route_config = getattr(request.state, "route_config", None)
        user_agent = request.headers.get("User-Agent", "")

        if not check_user_agent_allowed(user_agent, route_config, self.config):
            redacted_user_agent = redact_header_value_for_display(
                user_agent,
                self.config.log_sensitive_params,
                self.config.log_sensitive_body_fields,
                self.config.log_sensitive_headers,
            )
            log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"Blocked user agent: {redacted_user_agent}",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
                check_name=self.check_name,
                muted_check_logs=self.config.muted_check_logs,
                on_block=self.config.on_block,
                sensitive_headers=self.config.log_sensitive_headers,
                sensitive_params=self.config.log_sensitive_params,
                sensitive_body_fields=self.config.log_sensitive_body_fields,
            )

            if route_config and route_config.blocked_user_agents:
                emit_decorator_event(
                    self.middleware,
                    request,
                    event_type=EVENT_DECORATOR_VIOLATION,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"User agent '{redacted_user_agent}' blocked",
                    decorator_type="access_control",
                    violation_type="user_agent",
                    blocked_user_agent=redacted_user_agent,
                )
            else:
                self.middleware.event_bus.send_middleware_event(
                    event_type=EVENT_USER_AGENT_BLOCKED,
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"User agent '{redacted_user_agent}' in global blocklist",
                    user_agent=redacted_user_agent,
                    filter_type="global",
                )

            if not self.config.passive_mode:
                report_hostile_signal(
                    self,
                    request,
                    "user_agent",
                    f"Blocked user agent: {redacted_user_agent}",
                    "user_agent",
                )
                return self.middleware.create_error_response(
                    status_code=403,
                    default_message="User-Agent not allowed",
                )
        return None
