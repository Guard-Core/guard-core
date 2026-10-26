from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from opentelemetry.context import Context
    from opentelemetry.metrics import Counter, Histogram, Meter
    from opentelemetry.trace import Span, Tracer

    from guard_core.models import DynamicRules, SecurityConfig
    from guard_core.protocols.redis_protocol import RedisHandlerProtocol

logger = logging.getLogger("guard_core")

try:
    from opentelemetry import metrics, trace
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
        OTLPMetricExporter,
    )
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter,
    )
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.trace.propagation.tracecontext import (
        TraceContextTextMapPropagator,
    )

    _otel_available = True
except ImportError:
    metrics = None
    trace = None
    OTLPMetricExporter = None
    OTLPSpanExporter = None
    MeterProvider = None
    PeriodicExportingMetricReader = None
    Resource = None
    TracerProvider = None
    BatchSpanProcessor = None
    TraceContextTextMapPropagator = None
    _otel_available = False


_EVENT_SPAN_ATTRS: tuple[tuple[str, str], ...] = (
    ("guard.ip_address", "ip_address"),
    ("guard.action_taken", "action_taken"),
    ("guard.reason", "reason"),
    ("guard.endpoint", "endpoint"),
    ("guard.method", "method"),
)


class OtelHandler:
    def __init__(self, config: SecurityConfig) -> None:
        self._config = config
        self._tracer: Tracer | None = None
        self._meter: Meter | None = None
        self._rt_histogram: Histogram | None = None
        self._request_counter: Counter | None = None
        self._error_counter: Counter | None = None
        self._owned_tracer_provider: TracerProvider | None = None
        self._owned_meter_provider: MeterProvider | None = None
        self._lock = threading.Lock()

    async def start(self) -> None:
        if not _otel_available:
            logger.warning("opentelemetry-sdk not installed, OTEL handler disabled")
            return
        with self._lock:
            if self._tracer is not None:
                return
            attrs: dict[str, object] = {"service.name": self._config.otel_service_name}
            extra = getattr(self._config, "otel_resource_attributes", {}) or {}
            attrs.update(extra)
            resource = Resource.create(attrs)
            endpoint = self._config.otel_exporter_endpoint
            traces_endpoint = self._otlp_signal_endpoint(endpoint, "/v1/traces")
            metrics_endpoint = self._otlp_signal_endpoint(endpoint, "/v1/metrics")
            self._owned_tracer_provider = self._claim_tracer_provider(
                resource, traces_endpoint
            )
            self._tracer = trace.get_tracer("guard_core.otel")
            self._owned_meter_provider = self._claim_meter_provider(
                resource, metrics_endpoint
            )
            self._meter = metrics.get_meter("guard_core.otel")
            self._rt_histogram = self._meter.create_histogram(
                "guard.request.duration", unit="s"
            )
            self._request_counter = self._meter.create_counter("guard.request.count")
            self._error_counter = self._meter.create_counter("guard.error.count")

    @staticmethod
    def _claim_tracer_provider(
        resource: Resource, traces_endpoint: str | None
    ) -> TracerProvider | None:
        tp = TracerProvider(resource=resource)
        tp.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=traces_endpoint))
        )
        trace.set_tracer_provider(tp)
        if trace.get_tracer_provider() is tp:
            return tp
        tp.shutdown()
        logger.warning(
            "a tracer provider is already active for this process (installed "
            "by a host application or an earlier guard_core instance); "
            "guard_core will not export traces to %s",
            traces_endpoint,
        )
        return None

    @staticmethod
    def _claim_meter_provider(
        resource: Resource, metrics_endpoint: str | None
    ) -> MeterProvider | None:
        reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=metrics_endpoint)
        )
        mp = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(mp)
        if metrics.get_meter_provider() is mp:
            return mp
        mp.shutdown()
        logger.warning(
            "a meter provider is already active for this process (installed "
            "by a host application or an earlier guard_core instance); "
            "guard_core will not export metrics to %s",
            metrics_endpoint,
        )
        return None

    async def stop(self) -> None:
        if not _otel_available:
            return
        with self._lock:
            if self._owned_tracer_provider is not None and hasattr(
                self._owned_tracer_provider, "shutdown"
            ):
                self._owned_tracer_provider.shutdown()
            self._owned_tracer_provider = None
            self._tracer = None
            if self._owned_meter_provider is not None and hasattr(
                self._owned_meter_provider, "shutdown"
            ):
                self._owned_meter_provider.shutdown()
            self._owned_meter_provider = None
            self._meter = None

    async def send_event(self, event: object) -> None:
        if not _otel_available or not self._tracer:
            return
        event_type = getattr(event, "event_type", "unknown")
        metadata = getattr(event, "metadata", {}) or {}
        parent_ctx = self._extract_parent_context(metadata)

        with self._tracer.start_as_current_span(
            f"guard.event.{event_type}", context=parent_ctx
        ) as span:
            self._apply_event_attributes(span, event, event_type)
            self._forward_enrichment_metadata(span, metadata)

    @staticmethod
    def _otlp_signal_endpoint(endpoint: str | None, signal_path: str) -> str | None:
        if not endpoint:
            return None
        base = endpoint.rstrip("/")
        for known_signal in ("/v1/traces", "/v1/metrics", "/v1/logs"):
            if base.endswith(known_signal):
                base = base[: -len(known_signal)]
                break
        return base + signal_path

    def _extract_parent_context(self, metadata: object) -> Context | None:
        if not isinstance(metadata, dict):
            return None
        traceparent = metadata.get("traceparent")
        if not traceparent:
            return None
        carrier: dict[str, str] = {"traceparent": traceparent}
        tracestate = metadata.get("tracestate")
        if tracestate:
            carrier["tracestate"] = tracestate
        try:
            return TraceContextTextMapPropagator().extract(carrier=carrier)
        except Exception:
            return None

    def _apply_event_attributes(
        self, span: Span, event: object, event_type: str
    ) -> None:
        span.set_attribute("guard.event_type", event_type)
        for attr_key, event_attr in _EVENT_SPAN_ATTRS:
            span.set_attribute(attr_key, getattr(event, event_attr, ""))
        status_code = getattr(event, "status_code", 0)
        if status_code:
            span.set_attribute("guard.status_code", status_code)

    def _forward_enrichment_metadata(self, span: Span, metadata: object) -> None:
        if not isinstance(metadata, dict):
            return
        for key, value in metadata.items():
            if (
                key.startswith("guard.")
                and key not in ("traceparent", "tracestate")
                and value is not None
            ):
                span.set_attribute(key, value)

    async def send_metric(self, metric: object) -> None:
        if not _otel_available or not self._meter:
            return
        metric_type = getattr(metric, "metric_type", "unknown")
        value = getattr(metric, "value", 0)
        endpoint = getattr(metric, "endpoint", "")
        tags = getattr(metric, "tags", {}) or {}
        attrs = {"endpoint": endpoint, **tags}
        if metric_type == "response_time" and self._rt_histogram:
            self._rt_histogram.record(value, attributes=attrs)
        elif metric_type == "request_count" and self._request_counter:
            self._request_counter.add(value, attributes=attrs)
        elif metric_type == "error_rate" and self._error_counter:
            self._error_counter.add(value, attributes=attrs)
        else:
            logger.warning(
                "Unknown OTEL metric type %s - no instrument recorded", metric_type
            )

    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        pass

    async def flush_buffer(self) -> None:
        pass

    async def get_dynamic_rules(self) -> DynamicRules | None:
        return None

    async def health_check(self) -> bool:
        return _otel_available
