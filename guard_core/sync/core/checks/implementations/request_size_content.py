from collections.abc import Collection

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.body_reader import (
    parse_declared_length,
    read_prefix_beyond_limit,
    request_declares_body,
)
from guard_core.sync._utils.honeypot_fields import media_type_of
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
        limit = route_config.max_request_size
        if not limit:
            return None

        content_length = request.headers.get("content-length")
        if content_length is None or request.headers.get("transfer-encoding"):
            if not self._streamed_body_exceeds(request, limit):
                return None
            return self._oversize_response(
                request, limit, f"Request body exceeds {limit} bytes"
            )

        declared = parse_declared_length(content_length)
        if declared is None:
            return self._invalid_length_response(request, content_length)
        if declared <= limit:
            return None
        return self._oversize_response(
            request, limit, f"Request size {content_length} exceeds limit"
        )

    def _streamed_body_exceeds(self, request: SyncGuardRequest, limit: int) -> bool:
        body = read_prefix_beyond_limit(request, self.config, limit)
        return body is not None and len(body) > limit

    def _invalid_length_response(
        self, request: SyncGuardRequest, content_length: str
    ) -> GuardResponse | None:
        shown = redact_header_value_for_display(
            content_length,
            self.config.log_sensitive_params,
            self.config.log_sensitive_body_fields,
            self.config.log_sensitive_headers,
        )
        self._log_suspicious(request, f"Invalid Content-Length: {shown}")
        if self.config.passive_mode:
            return None
        return self.middleware.create_error_response(
            status_code=400,
            default_message="Invalid Content-Length",
        )

    def _log_suspicious(self, request: SyncGuardRequest, reason: str) -> None:
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

    def _oversize_response(
        self, request: SyncGuardRequest, limit: int, message: str
    ) -> GuardResponse | None:
        self._log_suspicious(request, f"{message}: {limit}")

        emit_decorator_event(
            self.middleware,
            request,
            event_type=EVENT_CONTENT_FILTERED,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"{message}: {limit}",
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

        if not request_declares_body(request.headers):
            return None

        content_type = media_type_of(request.headers.get("content-type", ""))
        if content_type in {
            media_type_of(t) for t in route_config.allowed_content_types
        }:
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
