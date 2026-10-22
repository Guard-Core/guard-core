from collections.abc import Collection

from guard_core._utils.body_reader import (
    parse_declared_length,
    read_prefix_beyond_limit,
    request_declares_body,
)
from guard_core._utils.honeypot_fields import media_type_of
from guard_core._utils.request_logging import redact_header_value_for_display
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.helpers import emit_decorator_event, route_config_applies
from guard_core.core.events.event_types import EVENT_CONTENT_FILTERED
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity


class RequestSizeContentCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "request_size_content"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return route_config_applies(
            route_configs,
            lambda rc: (
                rc.max_request_size is not None or bool(rc.allowed_content_types)
            ),
        )

    async def _check_request_size_limit(
        self, request: GuardRequest, route_config: RouteConfig
    ) -> GuardResponse | None:
        limit = route_config.max_request_size
        if limit is None:
            return None

        content_length = request.headers.get("content-length")
        if content_length is None or request.headers.get("transfer-encoding"):
            if not await self._streamed_body_exceeds(request, limit):
                return None
            return await self._oversize_response(
                request, limit, f"Request body exceeds {limit} bytes"
            )

        declared = parse_declared_length(content_length)
        if declared is None:
            return await self._invalid_length_response(request, content_length)
        if declared <= limit:
            return None
        return await self._oversize_response(
            request, limit, f"Request size {content_length} exceeds limit"
        )

    async def _streamed_body_exceeds(self, request: GuardRequest, limit: int) -> bool:
        body = await read_prefix_beyond_limit(request, self.config, limit)
        return body is not None and len(body) > limit

    async def _invalid_length_response(
        self, request: GuardRequest, content_length: str
    ) -> GuardResponse | None:
        shown = redact_header_value_for_display(
            content_length,
            self.config.log_sensitive_params,
            self.config.log_sensitive_body_fields,
            self.config.log_sensitive_headers,
        )
        await self._log_suspicious(request, f"Invalid Content-Length: {shown}")
        if self.config.passive_mode:
            return None
        return await self.middleware.create_error_response(
            status_code=400,
            default_message="Invalid Content-Length",
        )

    async def _log_suspicious(self, request: GuardRequest, reason: str) -> None:
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

    async def _oversize_response(
        self, request: GuardRequest, limit: int, message: str
    ) -> GuardResponse | None:
        await self._log_suspicious(request, f"{message}: {limit}")

        await emit_decorator_event(
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
            return await self.middleware.create_error_response(
                status_code=413,
                default_message="Request too large",
            )

        return None

    async def _check_content_type_allowed(
        self, request: GuardRequest, route_config: RouteConfig
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
        await log_activity(
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
        await emit_decorator_event(
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
            return await self.middleware.create_error_response(
                status_code=415,
                default_message="Unsupported content type",
            )

        return None

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)

        if not route_config:
            return None

        size_response = await self._check_request_size_limit(request, route_config)
        if size_response:
            return size_response

        return await self._check_content_type_allowed(request, route_config)
