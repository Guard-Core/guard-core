import logging
from collections.abc import Mapping
from datetime import datetime, timezone

from guard_core._utils.request_logging import (
    redact_endpoint_for_display,
    redact_header_value_for_display,
)
from guard_core.protocols.agent_protocol import AgentHandlerProtocol

_SECURITY_HEADERS_HANDLER_NAME = "security_headers"


def _safe_csp_uri(value: object) -> str:
    return redact_endpoint_for_display(str(value), None, None)


def _safe_csp_directive(value: object) -> str:
    return redact_header_value_for_display(str(value), None, None)


def _safe_csp_line_number(value: object) -> int | None:
    if not isinstance(value, (str, int, float)):
        return None
    try:
        return int(value)
    except ValueError:
        return None


class SecurityHeadersEventsMixin:
    agent_handler: AgentHandlerProtocol | None
    logger: logging.Logger

    async def initialize_agent(self, agent_handler: AgentHandlerProtocol) -> None:
        self.agent_handler = agent_handler

    async def _send_headers_applied_event(
        self, path: str, headers: dict[str, str]
    ) -> None:
        from guard_core.core.events.event_types import EVENT_SECURITY_HEADERS_APPLIED

        agent_handler = self.agent_handler
        if agent_handler is None:
            return
        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_SECURITY_HEADERS_APPLIED,
                action_taken="headers_added",
                handler_name=_SECURITY_HEADERS_HANDLER_NAME,
                metadata={
                    "path": redact_endpoint_for_display(path, None, None),
                    "headers_count": len(headers),
                    "has_csp": "Content-Security-Policy" in headers,
                    "has_hsts": "Strict-Transport-Security" in headers,
                },
            )
            await agent_handler.send_event(event)
        except Exception as e:
            self.logger.debug(f"Failed to send headers event to agent: {e}")

    async def validate_csp_report(self, report: Mapping[str, object]) -> bool:
        required_fields = ["document-uri", "violated-directive", "blocked-uri"]

        csp_report = report.get("csp-report", {})
        if not isinstance(csp_report, dict) or not all(
            field in csp_report for field in required_fields
        ):
            return False

        safe_directive = _safe_csp_directive(csp_report.get("violated-directive"))
        safe_blocked_uri = _safe_csp_uri(csp_report.get("blocked-uri"))
        safe_document_uri = _safe_csp_uri(csp_report.get("document-uri"))
        self.logger.warning(
            f"CSP Violation: {safe_directive} "
            f"blocked {safe_blocked_uri} "
            f"on {safe_document_uri}"
        )

        if self.agent_handler:
            await self._send_csp_violation_event(csp_report)

        return True

    async def _send_csp_violation_event(self, report: Mapping[str, object]) -> None:
        from guard_core.core.events.event_types import EVENT_CSP_VIOLATION

        agent_handler = self.agent_handler
        if agent_handler is None:
            return
        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_CSP_VIOLATION,
                action_taken="logged",
                handler_name=_SECURITY_HEADERS_HANDLER_NAME,
                metadata={
                    "document_uri": _safe_csp_uri(report.get("document-uri")),
                    "violated_directive": _safe_csp_directive(
                        report.get("violated-directive")
                    ),
                    "blocked_uri": _safe_csp_uri(report.get("blocked-uri")),
                    "source_file": _safe_csp_uri(report.get("source-file")),
                    "line_number": _safe_csp_line_number(report.get("line-number")),
                },
            )
            await agent_handler.send_event(event)
        except Exception as e:
            safe_error = redact_header_value_for_display(str(e), None, None)
            self.logger.debug(
                f"Failed to send CSP violation event to agent: {safe_error}"
            )
