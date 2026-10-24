import logging
from datetime import datetime, timezone
from typing import Any

from guard_core.sync._utils.request_logging import (
    redact_endpoint_for_display,
    redact_header_value_for_display,
)

_SECURITY_HEADERS_HANDLER_NAME = "security_headers"


def _safe_csp_uri(value: Any) -> str:
    return redact_endpoint_for_display(str(value), None, None)


def _safe_csp_directive(value: Any) -> str:
    return redact_header_value_for_display(str(value), None, None)


def _safe_csp_line_number(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class SecurityHeadersEventsMixin:
    agent_handler: Any
    logger: logging.Logger

    def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    def _send_headers_applied_event(self, path: str, headers: dict[str, str]) -> None:
        from guard_core.sync.core.events.event_types import (
            EVENT_SECURITY_HEADERS_APPLIED,
        )

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
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.debug(f"Failed to send headers event to agent: {e}")

    def validate_csp_report(self, report: dict[str, Any]) -> bool:
        required_fields = ["document-uri", "violated-directive", "blocked-uri"]

        csp_report = report.get("csp-report", {})
        if not all(field in csp_report for field in required_fields):
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
            self._send_csp_violation_event(csp_report)

        return True

    def _send_csp_violation_event(self, report: dict[str, Any]) -> None:
        from guard_core.sync.core.events.event_types import EVENT_CSP_VIOLATION

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
            self.agent_handler.send_event(event)
        except Exception as e:
            safe_error = redact_header_value_for_display(str(e), None, None)
            self.logger.debug(
                f"Failed to send CSP violation event to agent: {safe_error}"
            )
