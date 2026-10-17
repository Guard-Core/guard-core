from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, cast
from unittest.mock import MagicMock

import pytest
from pytest import MonkeyPatch

pytest.importorskip("opentelemetry.sdk")

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from guard_core.core.events.composite_handler import CompositeAgentHandler
from guard_core.core.events.enricher import EnrichmentContext, EventEnricher
from guard_core.core.events.event_types import EventFilter
from guard_core.core.events.otel_handler import OtelHandler
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers.behavior_handler import BehaviorTracker
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.models import DynamicRules, SecurityConfig


def _build_request() -> MagicMock:
    request = MagicMock()
    request.client_host = "1.2.3.4"
    request.headers = {}
    request.url_path = "/api"
    request.method = "GET"
    request.state = type("S", (), {})()
    return request


def _otel_handler_with_exporter(
    config: SecurityConfig, exporter: InMemorySpanExporter
) -> OtelHandler:
    handler = OtelHandler(config)
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    handler._tracer = provider.get_tracer("guard_core.otel")
    handler._meter = None
    handler._rt_histogram = None
    handler._request_counter = None
    handler._error_counter = None

    async def _noop_start() -> None:
        return None

    cast(Any, handler).start = _noop_start
    return handler


def _prewired_composite_factory(
    exporter: InMemorySpanExporter,
    config: SecurityConfig,
    enricher: EventEnricher | None,
) -> Callable[[], CompositeAgentHandler]:
    def _factory() -> CompositeAgentHandler:
        otel = _otel_handler_with_exporter(config, exporter)
        event_filter = EventFilter(
            muted_event_types=frozenset(config.muted_event_types),
            muted_metric_types=frozenset(config.muted_metric_types),
        )
        return CompositeAgentHandler(
            [otel], event_filter=event_filter, enricher=enricher
        )

    return _factory


@pytest.mark.asyncio
async def test_enrichment_fields_land_on_otel_span(monkeypatch: MonkeyPatch) -> None:
    DynamicRuleManager._instance = None
    exporter = InMemorySpanExporter()
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="a" * 10,
        agent_project_id="proj-e2e",
        enable_enrichment=True,
        enable_otel=True,
        otel_service_name="api-e2e",
        otel_resource_attributes={"deployment.environment": "prod"},
        agent_enable_events=True,
    )

    rule_handler = DynamicRuleManager(config)
    rule_handler.current_rules = DynamicRules(
        rule_id="rule-xyz",
        version=5,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=["1.2.3.4"],
    )
    tracker = BehaviorTracker(config)
    tracker.usage_counts["/api"]["1.2.3.4"].append(9999999999.0)

    enricher = EventEnricher(
        EnrichmentContext(
            config=config,
            dynamic_rule_handler=rule_handler,
            behavior_tracker=tracker,
        )
    )

    fake_event_cls = MagicMock(side_effect=lambda **kw: type("E", (), kw)())
    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.SecurityEvent",
        fake_event_cls,
        raising=False,
    )

    async def fake_extract(*_a: object, **_kw: object) -> str:
        return "1.2.3.4"

    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.extract_client_ip",
        fake_extract,
    )
    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.get_pipeline_response_time",
        lambda _r: 0.0,
    )

    initializer = HandlerInitializer(config=config, agent_handler=None)
    monkeypatch.setattr(
        initializer,
        "build_composite_handler",
        _prewired_composite_factory(exporter, config, enricher),
    )

    await initializer.initialize_agent_integrations()
    bus = initializer.build_event_bus()

    await bus.send_middleware_event(
        event_type="ip_blocked",
        request=_build_request(),
        action_taken="blocked",
        reason="IP on blacklist",
    )

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    attrs = dict(spans[0].attributes or {})

    assert attrs.get("guard.project_id") == "proj-e2e"
    assert attrs.get("guard.service.name") == "api-e2e"
    assert attrs.get("guard.deployment.environment") == "prod"
    assert attrs.get("guard.threat_score") == 50
    assert attrs.get("guard.rule.id") == "rule-xyz"
    assert attrs.get("guard.rule.version") == 5
    assert attrs.get("guard.behavior.recent_event_count") == 1
    assert isinstance(attrs.get("guard.behavior.correlation_key"), str)
    assert len(attrs.get("guard.behavior.correlation_key") or "") == 16


@pytest.mark.asyncio
async def test_enrichment_skipped_when_enable_enrichment_false(
    monkeypatch: MonkeyPatch,
) -> None:
    DynamicRuleManager._instance = None
    exporter = InMemorySpanExporter()
    config = SecurityConfig(
        enable_otel=True,
        otel_service_name="api-raw",
        agent_enable_events=True,
    )

    fake_event_cls = MagicMock(side_effect=lambda **kw: type("E", (), kw)())
    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.SecurityEvent",
        fake_event_cls,
        raising=False,
    )

    async def fake_extract(*_a: object, **_kw: object) -> str:
        return "1.2.3.4"

    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.extract_client_ip",
        fake_extract,
    )
    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.get_pipeline_response_time",
        lambda _r: 0.0,
    )

    initializer = HandlerInitializer(config=config, agent_handler=None)
    monkeypatch.setattr(
        initializer,
        "build_composite_handler",
        _prewired_composite_factory(exporter, config, enricher=None),
    )

    await initializer.initialize_agent_integrations()
    bus = initializer.build_event_bus()

    await bus.send_middleware_event(
        event_type="ip_blocked",
        request=_build_request(),
        action_taken="blocked",
        reason="test",
    )

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    attrs = dict(spans[0].attributes or {})
    assert "guard.project_id" not in attrs
    assert "guard.threat_score" not in attrs
    assert "guard.rule.id" not in attrs
    assert "guard.behavior.correlation_key" not in attrs
