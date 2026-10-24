import logging
from datetime import datetime, timezone
from typing import Any

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.request_logging import redact_endpoint_for_display
from guard_core.sync.core.events.event_types import (
    METRIC_ERROR_RATE,
    METRIC_REQUEST_COUNT,
    METRIC_RESPONSE_TIME,
    EventFilter,
)
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class MetricsCollector:
    def __init__(
        self,
        agent_handler: Any,
        config: SyncSecurityConfig,
        event_filter: EventFilter | None = None,
    ):
        self.agent_handler = agent_handler
        self.config = config
        self.event_filter = event_filter or EventFilter()
        self.logger = logging.getLogger(__name__)

    def send_metric(
        self, metric_type: str, value: float, tags: dict[str, str] | None = None
    ) -> None:
        if self.agent_handler and self.config.agent_enable_metrics:
            if not self.event_filter.is_metric_allowed(metric_type):
                return
            try:
                from guard_core._pydantic_plugin_mute import get_telemetry_model

                SecurityMetric = get_telemetry_model("SecurityMetric")

                metric = SecurityMetric(
                    timestamp=datetime.now(timezone.utc),
                    metric_type=metric_type,
                    value=value,
                    tags=tags or {},
                )
                self.agent_handler.send_metric(metric)
            except Exception as e:
                self.logger.error(f"Failed to send metric to agent: {e}")

    def collect_request_metrics(
        self, request: SyncGuardRequest, response_time: float, status_code: int
    ) -> None:
        if not self.agent_handler or not self.config.agent_enable_metrics:
            return

        endpoint = redact_endpoint_for_display(
            str(request.url_path),
            self.config.log_sensitive_params,
            self.config.log_sensitive_body_fields,
            self.config.log_sensitive_headers,
        )
        method = request.method

        self.send_metric(
            METRIC_RESPONSE_TIME,
            response_time,
            {"endpoint": endpoint, "method": method, "status": str(status_code)},
        )

        self.send_metric(
            METRIC_REQUEST_COUNT, 1.0, {"endpoint": endpoint, "method": method}
        )

        if status_code >= 400:
            self.send_metric(
                METRIC_ERROR_RATE,
                1.0,
                {"endpoint": endpoint, "method": method, "status": str(status_code)},
            )
