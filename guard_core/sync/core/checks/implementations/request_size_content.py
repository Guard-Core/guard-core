from collections.abc import Collection

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.request_logging import redact_header_value_for_display
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.helpers import (
    emit_decorator_event,
    route_config_applies,
)
from guard_core.sync.core.events.event_types import EVENT_CONTENT_FILTERED
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity


class RequestSizeContentCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "request_size_content"

    @classmethod
    def applies_to(
        cls,
        config: SyncSecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return route_config_applies(
            route_configs,
            lambda rc: (
                rc.max_request_size is not None or bool(rc.allowed_content_types)
            ),
        )

    def _check_request_size_limit(
        self, request: SyncGuardRequest, route_config: RouteConfig
    ) -> GuardResponse | None:
        if not route_config.max_request_size:
            return None

        content_length = request.headers.get("content-length")
        if not content_length or int(content_length) <= route_config.max_request_size:
            return None

        message = f"Request size {content_length} exceeds limit"

        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"{message}: {route_config.max_request_size}",
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
            event_type=EVENT_CONTENT_FILTERED,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"{message}: {route_config.max_request_size}",
            decorator_type="content_filtering",
            violation_type="max_request_size",
        )

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=413,
                default_message="Request too large",
            )

        return None

    def _check_content_type_allowed(
        self, request: SyncGuardRequest, route_config: RouteConfig
    ) -> GuardResponse | None:
        if not route_config.allowed_content_types:
            return None

        content_type = request.headers.get("content-type", "").split(";")[0]
        if content_type in route_config.allowed_content_types:
            return None

        redacted_content_type = redact_header_value_for_display(
            content_type,
            self.config.log_sensitive_params,
            self.config.log_sensitive_body_fields,
            self.config.log_sensitive_headers,
        )
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Invalid content type: {redacted_content_type}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            on_block=self.config.on_block,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )

        allowed_types = route_config.allowed_content_types
        emit_decorator_event(
            self.middleware,
            request,
            event_type=EVENT_CONTENT_FILTERED,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"Content type not in allowed types: {allowed_types}",
            decorator_type="content_filtering",
            violation_type="content_type",
        )

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=415,
                default_message="Unsupported content type",
            )

        return None

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)

        if not route_config:
            return None

        size_response = self._check_request_size_limit(request, route_config)
        if size_response:
            return size_response

        return self._check_content_type_allowed(request, route_config)
