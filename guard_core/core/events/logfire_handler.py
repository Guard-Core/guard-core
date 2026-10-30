from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.models import DynamicRules, SecurityConfig
    from guard_core.protocols.agent_protocol import JsonValue
    from guard_core.protocols.redis_protocol import RedisHandlerProtocol

logger = logging.getLogger("guard_core")

try:
    import logfire

    _logfire_available = True
except ImportError:
    logfire = None
    _logfire_available = False


_configure_lock = threading.Lock()


class LogfireHandler:
    def __init__(self, config: SecurityConfig) -> None:
        self._config = config
        self._started = False
        self._configured_by_guard = False

    async def start(self) -> None:
        if not _logfire_available:
            logger.warning("logfire not installed, Logfire handler disabled")
            return
        with _configure_lock:
            if self._started:
                return
            if logfire.DEFAULT_LOGFIRE_INSTANCE.config._initialized:
                self._started = True
                logger.warning(
                    "logfire is already configured for this process (by a host "
                    "application or an earlier guard_core instance); guard_core "
                    "will not apply its logfire_service_name %s",
                    self._config.logfire_service_name,
                )
                return
            logfire.configure(service_name=self._config.logfire_service_name)
            self._configured_by_guard = True
            self._started = True

    async def stop(self) -> None:
        if not _logfire_available:
            return
        with _configure_lock:
            if self._configured_by_guard:
                logfire.shutdown()
                self._configured_by_guard = False
            self._started = False

    async def send_event(self, event: object) -> None:
        if not _logfire_available:
            return
        event_type = getattr(event, "event_type", "unknown")
        metadata = getattr(event, "metadata", None)
        enrichment: dict[str, object] = {}
        if isinstance(metadata, dict):
            for key, value in metadata.items():
                if (
                    key.startswith("guard.")
                    and key not in ("traceparent", "tracestate")
                    and value is not None
                ):
                    enrichment[key] = value
        with logfire.span(
            f"guard.event.{event_type}",
            event_type=event_type,
            ip_address=getattr(event, "ip_address", ""),
            action_taken=getattr(event, "action_taken", ""),
            reason=getattr(event, "reason", ""),
            endpoint=getattr(event, "endpoint", ""),
            method=getattr(event, "method", ""),
            status_code=getattr(event, "status_code", 0),
            **enrichment,
        ):
            pass

    async def send_metric(self, metric: object) -> None:
        if not _logfire_available:
            return
        metric_type = getattr(metric, "metric_type", "unknown")
        value = getattr(metric, "value", 0)
        tags = getattr(metric, "tags", {}) or {}
        # the path lives in tags["endpoint"] (the model's own field is None); the tag
        # wins here as it does in the OTEL handler
        endpoint = tags.get("endpoint", getattr(metric, "endpoint", ""))
        safe_tags = {k: v for k, v in tags.items() if k not in ("value", "endpoint")}
        logfire.info(
            f"guard.metric.{metric_type}",
            value=value,
            endpoint=endpoint,
            **safe_tags,
        )

    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        pass

    async def flush_buffer(self) -> None:
        pass

    async def get_dynamic_rules(self) -> DynamicRules | None:
        return None

    def get_stats(self) -> dict[str, JsonValue]:
        return {}

    async def health_check(self) -> bool:
        return _logfire_available
