import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Protocol

from guard_core._utils.request_logging import (
    redact_endpoint_for_display,
    redact_header_value_for_display,
)
from guard_core._utils.route_gate import route_template_event_fields
from guard_core.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_HTTPS_ENFORCED,
    EventFilter,
)
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import AgentHandlerProtocol
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.utils import (
    extract_client_ip,
    get_pipeline_response_time,
    invoke_error_hook,
)

if TYPE_CHECKING:
    from guard_core.handlers.cloud_handler import CloudManager

_MIDDLEWARE_HANDLER_NAME = "middleware"


class _CountryLookup(Protocol):
    def get_country(self, ip: str) -> str | None: ...


class SecurityEventBus:
    def __init__(
        self,
        agent_handler: AgentHandlerProtocol | None,
        config: SecurityConfig,
        geo_ip_handler: _CountryLookup | None = None,
        event_filter: EventFilter | None = None,
    ):
        self.agent_handler = agent_handler
        self.config = config
        self.geo_ip_handler = geo_ip_handler
        self.event_filter = event_filter or EventFilter()
        self.logger = logging.getLogger(__name__)

    def _lookup_country(self, client_ip: str) -> str | None:
        if not self.geo_ip_handler:
            return None
        try:
            country: str | None = self.geo_ip_handler.get_country(client_ip)
            return country
        except Exception as e:
            self.logger.warning(f"GeoIP lookup failed for {client_ip}: {e}")
            invoke_error_hook(
                getattr(self.config, "on_error", None),
                "geoip",
                e,
                {"client_ip": client_ip},
            )
            return None

    @staticmethod
    def _forward_trace_headers(
        request: GuardRequest, kwargs: dict[str, object]
    ) -> dict[str, object]:
        forwarded = kwargs
        for header in ("traceparent", "tracestate"):
            value = request.headers.get(header)
            if value and header not in forwarded:
                forwarded = {**forwarded, header: value}
        return forwarded

    def _build_event(
        self,
        event_type: str,
        request: GuardRequest,
        client_ip: str,
        country: str | None,
        action_taken: str,
        reason: str,
        metadata: dict[str, object],
    ) -> object:
        from guard_core._pydantic_plugin_mute import get_telemetry_model

        SecurityEvent = get_telemetry_model("SecurityEvent")

        raw_user_agent = request.headers.get("User-Agent")
        return SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            ip_address=client_ip,
            country=country,
            user_agent=redact_header_value_for_display(
                raw_user_agent,
                self.config.log_sensitive_params,
                self.config.log_sensitive_body_fields,
                self.config.log_sensitive_headers,
            )
            if raw_user_agent
            else raw_user_agent,
            action_taken=action_taken,
            reason=reason,
            endpoint=redact_endpoint_for_display(
                str(request.url_path),
                self.config.log_sensitive_params,
                self.config.log_sensitive_body_fields,
                self.config.log_sensitive_headers,
            ),
            method=request.method,
            response_time=get_pipeline_response_time(request),
            decorator_type=metadata.get("decorator_type"),
            rule_type=metadata.get("rule_type"),
            handler_name=_MIDDLEWARE_HANDLER_NAME,
            metadata=metadata,
            **route_template_event_fields(request.state),
        )

    async def send_middleware_event(
        self,
        event_type: str,
        request: GuardRequest,
        action_taken: str,
        reason: str,
        **kwargs: object,
    ) -> None:
        if not self.agent_handler or not self.config.agent_enable_events:
            return
        if not self.event_filter.is_event_allowed(event_type):
            return

        try:
            client_ip = await extract_client_ip(
                request, self.config, self.agent_handler
            )
            country = self._lookup_country(client_ip)
            metadata = self._forward_trace_headers(request, kwargs)
            event = self._build_event(
                event_type, request, client_ip, country, action_taken, reason, metadata
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send security event to agent: {e}")

    async def send_https_violation_event(
        self, request: GuardRequest, route_config: RouteConfig | None
    ) -> None:
        https_url = redact_endpoint_for_display(
            request.url_replace_scheme("https"),
            self.config.log_sensitive_params,
            self.config.log_sensitive_body_fields,
            self.config.log_sensitive_headers,
        )

        if route_config and route_config.require_https:
            await self.send_middleware_event(
                event_type=EVENT_DECORATOR_VIOLATION,
                request=request,
                action_taken="https_redirect",
                reason="Route requires HTTPS but request was HTTP",
                decorator_type="authentication",
                violation_type="require_https",
                original_scheme=request.url_scheme,
                redirect_url=https_url,
            )
        else:
            await self.send_middleware_event(
                event_type=EVENT_HTTPS_ENFORCED,
                request=request,
                action_taken="https_redirect",
                reason="HTTP request redirected to HTTPS for security",
                original_scheme=request.url_scheme,
                redirect_url=https_url,
            )

    async def send_cloud_detection_events(
        self,
        request: GuardRequest,
        client_ip: str,
        cloud_providers_to_check: list[str],
        route_config: RouteConfig | None,
        cloud_handler: "CloudManager",
        passive_mode: bool,
        cloud_details: tuple[str, str] | None = None,
        attribution: dict[str, object] | None = None,
    ) -> None:
        if cloud_details is None:
            cloud_details = cloud_handler.get_cloud_provider_details(
                client_ip, set(cloud_providers_to_check)
            )
        if cloud_details and cloud_handler.agent_handler:
            provider, network = cloud_details
            await cloud_handler.send_cloud_detection_event(
                client_ip,
                provider,
                network,
                "request_blocked" if not passive_mode else "logged_only",
                **(attribution or {}),
            )

        if route_config and route_config.block_cloud_providers:
            await self.send_middleware_event(
                event_type=EVENT_DECORATOR_VIOLATION,
                request=request,
                action_taken="request_blocked" if not passive_mode else "logged_only",
                reason=f"Cloud provider IP {client_ip} blocked",
                decorator_type="access_control",
                violation_type="cloud_provider",
                blocked_providers=list(cloud_providers_to_check),
            )
