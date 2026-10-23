import importlib
import sys
from collections.abc import Generator
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SyncSecurityConfig


def _fresh_otel_handler_module() -> ModuleType:
    module_name = "guard_core.sync.core.events.otel_handler"
    if module_name in sys.modules:
        return importlib.reload(sys.modules[module_name])
    return importlib.import_module(module_name)


@pytest.fixture(autouse=True)
def _reload_otel_handler_between_tests() -> Generator[None, None, None]:
    _fresh_otel_handler_module()
    yield
    _fresh_otel_handler_module()


def test_otel_resource_attributes_default_empty() -> None:
    assert SyncSecurityConfig().otel_resource_attributes == {}


def test_otel_resource_attributes_accepts_map() -> None:
    config = SyncSecurityConfig(
        otel_resource_attributes={
            "deployment.environment": "prod",
            "service.version": "1.0.3",
        }
    )
    assert config.otel_resource_attributes["deployment.environment"] == "prod"
    assert config.otel_resource_attributes["service.version"] == "1.0.3"


def test_otel_handler_applies_resource_attributes() -> None:
    module = _fresh_otel_handler_module()
    fake_resource = MagicMock()
    fake_resource_cls = MagicMock()
    fake_resource_cls.create = MagicMock(return_value=fake_resource)

    with (
        patch.object(module, "_otel_available", True),
        patch.object(module, "Resource", fake_resource_cls),
        patch.object(module, "TracerProvider"),
        patch.object(module, "BatchSpanProcessor"),
        patch.object(module, "OTLPSpanExporter"),
        patch.object(module, "OTLPMetricExporter"),
        patch.object(module, "PeriodicExportingMetricReader"),
        patch.object(module, "MeterProvider"),
        patch.object(module, "trace"),
        patch.object(module, "metrics"),
    ):
        config = SimpleNamespace(
            otel_service_name="guard-core",
            otel_exporter_endpoint="http://localhost:4318",
            otel_resource_attributes={
                "deployment.environment": "prod",
                "service.version": "1.0.3",
            },
        )
        handler = module.OtelHandler(config)
        handler.start()

    fake_resource_cls.create.assert_called_once()
    attrs = fake_resource_cls.create.call_args.args[0]
    assert attrs["service.name"] == "guard-core"
    assert attrs["deployment.environment"] == "prod"
    assert attrs["service.version"] == "1.0.3"


def test_send_event_extracts_traceparent_from_metadata() -> None:
    module = _fresh_otel_handler_module()
    propagator = MagicMock()
    propagator.extract = MagicMock(return_value="resumed_context")
    prop_cls = MagicMock(return_value=propagator)

    tracer = MagicMock()
    span_cm = MagicMock()
    span = MagicMock()
    span_cm.__enter__ = MagicMock(return_value=span)
    span_cm.__exit__ = MagicMock(return_value=False)
    tracer.start_as_current_span = MagicMock(return_value=span_cm)

    with (
        patch.object(module, "_otel_available", True),
        patch.object(module, "TraceContextTextMapPropagator", prop_cls),
    ):
        handler = module.OtelHandler(
            config=SimpleNamespace(
                otel_service_name="svc",
                otel_exporter_endpoint=None,
                otel_resource_attributes={},
            )
        )
        handler._tracer = tracer

        event = SimpleNamespace(
            event_type="penetration_attempt",
            ip_address="1.2.3.4",
            action_taken="blocked",
            reason="test",
            endpoint="/x",
            method="GET",
            status_code=0,
            metadata={
                "traceparent": (
                    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
                )
            },
        )
        handler.send_event(event)

    propagator.extract.assert_called_once()
    call = propagator.extract.call_args
    carrier = call.kwargs.get("carrier") or (call.args[0] if call.args else None)
    assert carrier == {
        "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    }
    tracer.start_as_current_span.assert_called_once()
    sas_kwargs = tracer.start_as_current_span.call_args.kwargs
    assert sas_kwargs.get("context") == "resumed_context"


def test_send_event_malformed_traceparent_does_not_crash() -> None:
    module = _fresh_otel_handler_module()
    tracer = MagicMock()
    span_cm = MagicMock()
    span = MagicMock()
    span_cm.__enter__ = MagicMock(return_value=span)
    span_cm.__exit__ = MagicMock(return_value=False)
    tracer.start_as_current_span = MagicMock(return_value=span_cm)

    with patch.object(module, "_otel_available", True):
        handler = module.OtelHandler(
            config=SimpleNamespace(
                otel_service_name="svc",
                otel_exporter_endpoint=None,
                otel_resource_attributes={},
            )
        )
        handler._tracer = tracer
        event = SimpleNamespace(
            event_type="penetration_attempt",
            ip_address="1.2.3.4",
            action_taken="blocked",
            reason="",
            endpoint="",
            method="",
            status_code=0,
            metadata={"traceparent": "garbage"},
        )
        handler.send_event(event)
    tracer.start_as_current_span.assert_called_once()


def test_send_event_propagator_failure_falls_back_to_root_span() -> None:
    module = _fresh_otel_handler_module()
    tracer = MagicMock()
    span_cm = MagicMock()
    span = MagicMock()
    span_cm.__enter__ = MagicMock(return_value=span)
    span_cm.__exit__ = MagicMock(return_value=False)
    tracer.start_as_current_span = MagicMock(return_value=span_cm)

    failing_propagator = MagicMock(side_effect=RuntimeError("propagator broken"))

    with (
        patch.object(module, "_otel_available", True),
        patch.object(module, "TraceContextTextMapPropagator", failing_propagator),
    ):
        handler = module.OtelHandler(
            config=SimpleNamespace(
                otel_service_name="svc",
                otel_exporter_endpoint=None,
                otel_resource_attributes={},
            )
        )
        handler._tracer = tracer
        event = SimpleNamespace(
            event_type="penetration_attempt",
            ip_address="1.2.3.4",
            action_taken="blocked",
            reason="",
            endpoint="",
            method="",
            status_code=0,
            metadata={"traceparent": "00-abc-def-01"},
        )
        handler.send_event(event)

    tracer.start_as_current_span.assert_called_once()
    sas_kwargs = tracer.start_as_current_span.call_args.kwargs
    assert sas_kwargs.get("context") is None


def test_send_event_forwards_tracestate_when_present() -> None:
    module = _fresh_otel_handler_module()
    propagator = MagicMock()
    propagator.extract = MagicMock(return_value="ctx")
    prop_cls = MagicMock(return_value=propagator)

    tracer = MagicMock()
    span_cm = MagicMock()
    span_cm.__enter__ = MagicMock(return_value=MagicMock())
    span_cm.__exit__ = MagicMock(return_value=False)
    tracer.start_as_current_span = MagicMock(return_value=span_cm)

    with (
        patch.object(module, "_otel_available", True),
        patch.object(module, "TraceContextTextMapPropagator", prop_cls),
    ):
        handler = module.OtelHandler(
            config=SimpleNamespace(
                otel_service_name="svc",
                otel_exporter_endpoint=None,
                otel_resource_attributes={},
            )
        )
        handler._tracer = tracer
        tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        event = SimpleNamespace(
            event_type="penetration_attempt",
            ip_address="1.2.3.4",
            action_taken="blocked",
            reason="",
            endpoint="",
            method="",
            status_code=0,
            metadata={"traceparent": tp, "tracestate": "vendor=abc"},
        )
        handler.send_event(event)

    carrier = propagator.extract.call_args.kwargs["carrier"]
    assert carrier == {"traceparent": tp, "tracestate": "vendor=abc"}


def test_send_event_no_traceparent_starts_root_span() -> None:
    module = _fresh_otel_handler_module()
    tracer = MagicMock()
    span_cm = MagicMock()
    span = MagicMock()
    span_cm.__enter__ = MagicMock(return_value=span)
    span_cm.__exit__ = MagicMock(return_value=False)
    tracer.start_as_current_span = MagicMock(return_value=span_cm)

    with patch.object(module, "_otel_available", True):
        handler = module.OtelHandler(
            config=SimpleNamespace(
                otel_service_name="svc",
                otel_exporter_endpoint=None,
                otel_resource_attributes={},
            )
        )
        handler._tracer = tracer

        event = SimpleNamespace(
            event_type="penetration_attempt",
            ip_address="1.2.3.4",
            action_taken="blocked",
            reason="",
            endpoint="",
            method="",
            status_code=0,
            metadata={},
        )
        handler.send_event(event)

    tracer.start_as_current_span.assert_called_once()
    sas_kwargs = tracer.start_as_current_span.call_args.kwargs
    assert sas_kwargs.get("context") is None


def test_event_bus_attaches_tracestate_from_request_headers() -> None:
    from types import SimpleNamespace as _SN
    from typing import cast as _cast

    from guard_core.sync.core.events.event_types import EVENT_PENETRATION_ATTEMPT
    from guard_core.sync.core.events.middleware_events import SecurityEventBus

    captured: dict[str, Any] = {}

    def capture_send(event: object) -> None:
        captured["event"] = event

    agent = MagicMock()
    agent.send_event = capture_send

    cfg = _cast(
        SyncSecurityConfig,
        _SN(
            agent_enable_events=True,
            log_sensitive_params=None,
            log_sensitive_body_fields=None,
            log_sensitive_headers=None,
        ),
    )
    bus = SecurityEventBus(agent_handler=agent, config=cfg)

    request = MagicMock()
    request.client_host = "1.2.3.4"
    request.headers = {
        "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        "tracestate": "vendor=abc",
    }
    request.url_path = "/x"
    request.method = "GET"

    fake_event_cls = MagicMock(side_effect=lambda **kw: _SN(**kw))
    with (
        patch(
            "guard_core.sync.core.events.middleware_events.extract_client_ip",
            new=MagicMock(return_value="1.2.3.4"),
        ) as mock_extract,
        patch(
            "guard_core.sync.core.events.middleware_events.SecurityEvent",
            fake_event_cls,
            create=True,
        ),
    ):

        def _async_return_ip(*_a: object, **_kw: object) -> str:
            return "1.2.3.4"

        mock_extract.side_effect = _async_return_ip
        bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="blocked",
            reason="test",
        )

    event = captured["event"]
    assert event.metadata["tracestate"] == "vendor=abc"


def test_event_bus_attaches_traceparent_from_request_headers() -> None:
    from typing import cast as _cast

    from guard_core.sync.core.events.event_types import EVENT_PENETRATION_ATTEMPT
    from guard_core.sync.core.events.middleware_events import SecurityEventBus

    captured: dict[str, Any] = {}

    agent = MagicMock()

    def capture_send(event: object) -> None:
        captured["event"] = event

    agent.send_event = capture_send

    cfg = _cast(
        SyncSecurityConfig,
        SimpleNamespace(
            agent_enable_events=True,
            log_sensitive_params=None,
            log_sensitive_body_fields=None,
            log_sensitive_headers=None,
        ),
    )
    bus = SecurityEventBus(agent_handler=agent, config=cfg)

    request = MagicMock()
    request.client_host = "1.2.3.4"
    request.headers = {
        "User-Agent": "test",
        "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
    }
    request.url_path = "/x"
    request.method = "GET"

    fake_event_cls = MagicMock(side_effect=lambda **kw: SimpleNamespace(**kw))
    with (
        patch(
            "guard_core.sync.core.events.middleware_events.extract_client_ip",
            new=MagicMock(return_value="1.2.3.4"),
        ) as mock_extract,
        patch(
            "guard_core.sync.core.events.middleware_events.SecurityEvent",
            fake_event_cls,
            create=True,
        ),
    ):

        def _async_return_ip(*_a: object, **_kw: object) -> str:
            return "1.2.3.4"

        mock_extract.side_effect = _async_return_ip
        bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="blocked",
            reason="test",
        )

    event = captured["event"]
    assert (
        event.metadata["traceparent"]
        == "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    )


def test_send_metric_warns_on_unknown_type(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    module = _fresh_otel_handler_module()
    with patch.object(module, "_otel_available", True):
        handler = module.OtelHandler(
            config=SimpleNamespace(
                otel_service_name="svc",
                otel_exporter_endpoint=None,
                otel_resource_attributes={},
            )
        )
        handler._meter = MagicMock()
        handler._rt_histogram = MagicMock()
        handler._request_counter = MagicMock()
        handler._error_counter = MagicMock()

        metric = SimpleNamespace(
            metric_type="new_metric_type",
            value=1.0,
            endpoint="/x",
            tags={},
        )
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            handler.send_metric(metric)

    messages = [r.getMessage() for r in caplog.records]
    assert any("unknown otel metric type" in m.lower() for m in messages), messages
    assert any("new_metric_type" in m for m in messages), messages
    handler._rt_histogram.record.assert_not_called()
    handler._request_counter.add.assert_not_called()
    handler._error_counter.add.assert_not_called()


def test_otel_handler_works_without_resource_attrs_field() -> None:
    module = _fresh_otel_handler_module()
    fake_resource = MagicMock()
    fake_resource_cls = MagicMock()
    fake_resource_cls.create = MagicMock(return_value=fake_resource)

    with (
        patch.object(module, "_otel_available", True),
        patch.object(module, "Resource", fake_resource_cls),
        patch.object(module, "TracerProvider"),
        patch.object(module, "BatchSpanProcessor"),
        patch.object(module, "OTLPSpanExporter"),
        patch.object(module, "OTLPMetricExporter"),
        patch.object(module, "PeriodicExportingMetricReader"),
        patch.object(module, "MeterProvider"),
        patch.object(module, "trace"),
        patch.object(module, "metrics"),
    ):
        config = SimpleNamespace(
            otel_service_name="guard-core",
            otel_exporter_endpoint=None,
        )
        handler = module.OtelHandler(config)
        handler.start()

    attrs = fake_resource_cls.create.call_args.args[0]
    assert attrs == {"service.name": "guard-core"}
