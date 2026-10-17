import hmac
from collections.abc import Collection

from guard_core.models import SecurityConfig
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


def _classify_header_violation(header_name: str) -> tuple[str, str]:
    header_lower = header_name.lower()

    if header_lower == "x-api-key":
        return "authentication", "api_key_required"
    if header_lower == "authorization":
        return "authentication", "required_header"
    return "advanced", "required_header"


class RequiredHeadersCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "required_headers"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return route_config_applies(route_configs, lambda rc: bool(rc.required_headers))

    def _report_header_violation(
        self,
        request: SyncGuardRequest,
        header: str,
        reason: str,
        *,
        header_field: str,
    ) -> GuardResponse | None:
        log_activity(
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

        decorator_type, violation_type = _classify_header_violation(header)

        emit_access_denied_event(
            self.middleware,
            request,
            event_type=EVENT_DECORATOR_VIOLATION,
            reason=reason,
            decorator_type=decorator_type,
            passive_mode=self.config.passive_mode,
            violation_type=violation_type,
            **{header_field: header},
        )

        report_hostile_signal(self, request, "required_header", reason)

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=400,
                default_message="Bad request",
            )
        return None

    def _handle_missing_header(
        self, request: SyncGuardRequest, header: str
    ) -> GuardResponse | None:
        reason = f"Missing required header: {header}"
        return self._report_header_violation(
            request, header, reason, header_field="missing_header"
        )

    def _handle_mismatched_header(
        self, request: SyncGuardRequest, header: str
    ) -> GuardResponse | None:
        reason = f"Header '{header}' does not match the required value"
        return self._report_header_violation(
            request, header, reason, header_field="mismatched_header"
        )

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)

        if not route_config or not route_config.required_headers:
            return None

        for header, expected in route_config.required_headers.items():
            actual = request.headers.get(header)
            if not actual:
                return self._handle_missing_header(request, header)
            if expected != "required" and not hmac.compare_digest(
                actual.encode(), expected.encode()
            ):
                return self._handle_mismatched_header(request, header)

        return None
