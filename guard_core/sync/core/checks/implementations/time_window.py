from collections.abc import Collection
from datetime import datetime

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.time_window import time_window_allows
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.helpers import (
    emit_access_denied_event,
    route_config_applies,
)
from guard_core.sync.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity


class TimeWindowCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "time_window"

    @classmethod
    def applies_to(
        cls,
        config: SyncSecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return route_config_applies(
            route_configs, lambda rc: bool(rc.time_restrictions)
        )

    def _check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        return time_window_allows(time_restrictions, self.logger, datetime.now)

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)
        if not route_config or not route_config.time_restrictions:
            return None

        time_allowed = self._check_time_window(route_config.time_restrictions)
        if not time_allowed:
            log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason="Access outside allowed time window",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
                check_name=self.check_name,
                muted_check_logs=self.config.muted_check_logs,
                on_block=self.config.on_block,
                sensitive_headers=self.config.log_sensitive_headers,
                sensitive_params=self.config.log_sensitive_params,
                sensitive_body_fields=self.config.log_sensitive_body_fields,
            )
            emit_access_denied_event(
                self.middleware,
                request,
                event_type=EVENT_DECORATOR_VIOLATION,
                reason="Access outside allowed time window",
                decorator_type="advanced",
                passive_mode=self.config.passive_mode,
                violation_type="time_restriction",
            )
            if not self.config.passive_mode:
                return self.middleware.create_error_response(
                    status_code=403,
                    default_message="Access not allowed at this time",
                )
        return None
