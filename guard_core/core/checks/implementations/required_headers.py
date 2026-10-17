import hmac
from collections.abc import Collection

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.helpers import (
    emit_access_denied_event,
    report_hostile_signal,
    route_config_applies,
)
from guard_core.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity


def _classify_header_violation(header_name: str) -> tuple[str, str]:
    header_lower = header_name.lower()

    if header_lower == "x-api-key":
        return "authentication", "api_key_required"
    if header_lower == "authorization":
        return "authentication", "required_header"
    return "advanced", "required_header"


def _is_presence_only_api_key_header(
    route_config: RouteConfig, header: str, expected: str
) -> bool:
    return (
        route_config.api_key_required
        and header == route_config.api_key_header
        and expected == "required"
    )


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

    async def _report_header_violation(
        self,
        request: GuardRequest,
        header: str,
        reason: str,
        *,
        header_field: str,
    ) -> GuardResponse | None:
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

        decorator_type, violation_type = _classify_header_violation(header)

        await emit_access_denied_event(
            self.middleware,
            request,
            event_type=EVENT_DECORATOR_VIOLATION,
            reason=reason,
            decorator_type=decorator_type,
            passive_mode=self.config.passive_mode,
            violation_type=violation_type,
            **{header_field: header},
        )

        await report_hostile_signal(self, request, "required_header", reason)

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=400,
                default_message="Bad request",
            )
        return None

    async def _handle_missing_header(
        self, request: GuardRequest, header: str
    ) -> GuardResponse | None:
        reason = f"Missing required header: {header}"
        return await self._report_header_violation(
            request, header, reason, header_field="missing_header"
        )

    async def _handle_mismatched_header(
        self, request: GuardRequest, header: str
    ) -> GuardResponse | None:
        reason = f"Header '{header}' does not match the required value"
        return await self._report_header_violation(
            request, header, reason, header_field="mismatched_header"
        )

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)

        if not route_config or not route_config.required_headers:
            return None

        for header, expected in route_config.required_headers.items():
            if _is_presence_only_api_key_header(route_config, header, expected):
                continue
            actual = request.headers.get(header)
            if not actual:
                return await self._handle_missing_header(request, header)
            if expected != "required" and not hmac.compare_digest(
                actual.encode(), expected.encode()
            ):
                return await self._handle_mismatched_header(request, header)

        return None
