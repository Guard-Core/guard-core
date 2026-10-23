from collections.abc import Collection

from guard_core.sync._utils.request_logging import redact_url_for_display
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.helpers import (
    emit_access_denied_event,
    is_referrer_domain_allowed,
    report_hostile_signal,
    route_config_applies,
)
from guard_core.sync.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.sync.decorators.base import RouteConfig
from guard_core.models import SecurityConfig, SyncSecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.utils import log_activity


class ReferrerCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "referrer"

    @classmethod
    def applies_to(
        cls,
        config: SyncSecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return route_config_applies(route_configs, lambda rc: bool(rc.require_referrer))

    def _handle_missing_referrer(
        self, request: SyncGuardRequest, route_config: RouteConfig
    ) -> GuardResponse | None:
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason="Missing referrer header",
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
            reason="Missing referrer header",
            decorator_type="content_filtering",
            passive_mode=self.config.passive_mode,
            violation_type="require_referrer",
            allowed_domains=route_config.require_referrer,
        )

        report_hostile_signal(
            self, request, "referrer", "Missing referrer header"
        )

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=403,
                default_message="Referrer required",
            )

        return None

    def _handle_invalid_referrer(
        self, request: SyncGuardRequest, referrer: str, route_config: RouteConfig
    ) -> GuardResponse | None:
        redacted_referrer = redact_url_for_display(
            referrer,
            self.config.log_sensitive_params,
            self.config.log_sensitive_body_fields,
            self.config.log_sensitive_headers,
        )
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Invalid referrer: {redacted_referrer}",
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
            reason=f"Referrer '{redacted_referrer}' not in allowed domains",
            decorator_type="content_filtering",
            passive_mode=self.config.passive_mode,
            violation_type="require_referrer",
            referrer=redacted_referrer,
            allowed_domains=route_config.require_referrer,
        )

        report_hostile_signal(
            self, request, "referrer", f"Invalid referrer: {redacted_referrer}"
        )

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=403,
                default_message="Invalid referrer",
            )

        return None

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)
        if not route_config or not route_config.require_referrer:
            return None

        referrer = request.headers.get("referer", "")

        if not referrer:
            return self._handle_missing_referrer(request, route_config)

        if not is_referrer_domain_allowed(referrer, route_config.require_referrer):
            return self._handle_invalid_referrer(request, referrer, route_config)

        return None
