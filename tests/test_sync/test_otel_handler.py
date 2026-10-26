from unittest.mock import MagicMock, patch

import pytest

from guard_core.sync.core.events.otel_handler import OtelHandler


@pytest.fixture
def config() -> MagicMock:
    return MagicMock(
        otel_service_name="guard-core-test",
        otel_exporter_endpoint="http://localhost:4318",
    )


def test_health_check_true_when_available(config: MagicMock) -> None:
    with patch("guard_core.sync.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        assert handler.health_check() is True


def test_health_check_false_when_unavailable() -> None:
    with patch("guard_core.sync.core.events.otel_handler._otel_available", False):
        handler = OtelHandler(MagicMock())
        assert handler.health_check() is False


def test_noop_when_otel_unavailable(config: MagicMock) -> None:
    with patch("guard_core.sync.core.events.otel_handler._otel_available", False):
        handler = OtelHandler(config)
        handler.send_event(MagicMock())
        handler.send_metric(MagicMock())
        handler.start()
        handler.stop()
        handler.flush_buffer()
        handler.initialize_redis(MagicMock())


def test_get_dynamic_rules_returns_none(config: MagicMock) -> None:
    handler = OtelHandler(config)
    assert handler.get_dynamic_rules() is None


def test_send_event_creates_span(config: MagicMock) -> None:
    with patch("guard_core.sync.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        mock_tracer = MagicMock()
        mock_span = MagicMock()
        cm = MagicMock()
        cm.__enter__ = MagicMock(return_value=mock_span)
        cm.__exit__ = MagicMock(return_value=False)
        mock_tracer.start_as_current_span.return_value = cm
        handler._tracer = mock_tracer

        event = MagicMock()
        event.event_type = "penetration_attempt"
        event.ip_address = "1.2.3.4"
        event.action_taken = "blocked"
        event.reason = "test"
        event.endpoint = "/test"
        event.method = "GET"
        event.status_code = 403

        handler.send_event(event)
        mock_tracer.start_as_current_span.assert_called_once()
        args, kwargs = mock_tracer.start_as_current_span.call_args
        assert args[0] == "guard.event.penetration_attempt"
        assert kwargs.get("context") is None
        assert mock_span.set_attribute.call_count >= 4


def test_send_metric_records_histogram(config: MagicMock) -> None:
    with patch("guard_core.sync.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        mock_histogram = MagicMock()
        mock_counter = MagicMock()
        mock_error_counter = MagicMock()
        handler._rt_histogram = mock_histogram
        handler._request_counter = mock_counter
        handler._error_counter = mock_error_counter
        handler._meter = MagicMock()

        metric = MagicMock()
        metric.metric_type = "response_time"
        metric.value = 0.5
        metric.endpoint = "/test"
        metric.tags = {"method": "GET"}

        handler.send_metric(metric)
        mock_histogram.record.assert_called_once()
        mock_counter.add.assert_not_called()
        mock_error_counter.add.assert_not_called()


def test_send_metric_records_counter(config: MagicMock) -> None:
    with patch("guard_core.sync.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        mock_histogram = MagicMock()
        mock_counter = MagicMock()
        mock_error_counter = MagicMock()
        handler._rt_histogram = mock_histogram
        handler._request_counter = mock_counter
        handler._error_counter = mock_error_counter
        handler._meter = MagicMock()

        metric = MagicMock()
        metric.metric_type = "request_count"
        metric.value = 1.0
        metric.endpoint = "/test"
        metric.tags = {"method": "GET"}

        handler.send_metric(metric)
        mock_counter.add.assert_called_once()
        mock_histogram.record.assert_not_called()


def test_send_metric_records_error_counter(config: MagicMock) -> None:
    with patch("guard_core.sync.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        mock_histogram = MagicMock()
        mock_counter = MagicMock()
        mock_error_counter = MagicMock()
        handler._rt_histogram = mock_histogram
        handler._request_counter = mock_counter
        handler._error_counter = mock_error_counter
        handler._meter = MagicMock()

        metric = MagicMock()
        metric.metric_type = "error_rate"
        metric.value = 1.0
        metric.endpoint = "/test"
        metric.tags = {"method": "GET"}

        handler.send_metric(metric)
        mock_error_counter.add.assert_called_once()
        mock_histogram.record.assert_not_called()


def test_stop_shuts_down_only_owned_providers(config: MagicMock) -> None:
    with patch("guard_core.sync.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        handler._tracer = MagicMock()
        handler._meter = MagicMock()
        mock_tracer_provider = MagicMock()
        mock_meter_provider = MagicMock()
        handler._owned_tracer_provider = mock_tracer_provider
        handler._owned_meter_provider = mock_meter_provider

        handler.stop()

        mock_tracer_provider.shutdown.assert_called_once()
        mock_meter_provider.shutdown.assert_called_once()
        assert vars(handler)["_tracer"] is None
        assert vars(handler)["_meter"] is None
        assert vars(handler)["_owned_tracer_provider"] is None
        assert vars(handler)["_owned_meter_provider"] is None


def test_stop_does_not_shut_down_borrowed_providers(config: MagicMock) -> None:
    with patch("guard_core.sync.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        handler._tracer = MagicMock()
        handler._meter = MagicMock()
        handler._owned_tracer_provider = None
        handler._owned_meter_provider = None

        with (
            patch("guard_core.sync.core.events.otel_handler.trace") as mock_trace,
            patch("guard_core.sync.core.events.otel_handler.metrics") as mock_metrics,
        ):
            handler.stop()
            mock_trace.get_tracer_provider.assert_not_called()
            mock_metrics.get_meter_provider.assert_not_called()

        assert vars(handler)["_tracer"] is None
        assert vars(handler)["_meter"] is None


def test_stop_no_tracer_or_meter(config: MagicMock) -> None:
    with patch("guard_core.sync.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        handler._tracer = None
        handler._meter = None
        handler._owned_tracer_provider = None
        handler._owned_meter_provider = None
        handler.stop()


def test_stop_is_idempotent(config: MagicMock) -> None:
    with patch("guard_core.sync.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        handler._tracer = MagicMock()
        handler._meter = MagicMock()
        mock_tracer_provider = MagicMock()
        mock_meter_provider = MagicMock()
        handler._owned_tracer_provider = mock_tracer_provider
        handler._owned_meter_provider = mock_meter_provider

        handler.stop()
        handler.stop()

        mock_tracer_provider.shutdown.assert_called_once()
        mock_meter_provider.shutdown.assert_called_once()
        assert vars(handler)["_tracer"] is None
        assert vars(handler)["_meter"] is None


def test_stop_providers_without_shutdown_attr(config: MagicMock) -> None:
    with patch("guard_core.sync.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        handler._tracer = MagicMock()
        handler._meter = MagicMock()

        class _NoShutdown:
            pass

        handler._owned_tracer_provider = _NoShutdown()
        handler._owned_meter_provider = _NoShutdown()

        handler.stop()

        assert vars(handler)["_owned_tracer_provider"] is None
        assert vars(handler)["_owned_meter_provider"] is None


def test_start_configures_otel(config: MagicMock) -> None:
    with patch("guard_core.sync.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        mock_tracer = MagicMock()
        mock_meter = MagicMock()
        mock_histogram = MagicMock()
        mock_counter = MagicMock()
        mock_error_counter = MagicMock()
        mock_meter.create_histogram.return_value = mock_histogram
        mock_meter.create_counter.side_effect = [mock_counter, mock_error_counter]
        with (
            patch("guard_core.sync.core.events.otel_handler.trace") as mock_trace,
            patch("guard_core.sync.core.events.otel_handler.metrics") as mock_metrics,
            patch("guard_core.sync.core.events.otel_handler.Resource") as MockResource,
            patch("guard_core.sync.core.events.otel_handler.TracerProvider") as MockTP,
            patch("guard_core.sync.core.events.otel_handler.BatchSpanProcessor"),
            patch(
                "guard_core.sync.core.events.otel_handler.OTLPSpanExporter"
            ) as MockSpanExporter,
            patch(
                "guard_core.sync.core.events.otel_handler.PeriodicExportingMetricReader"
            ),
            patch(
                "guard_core.sync.core.events.otel_handler.OTLPMetricExporter"
            ) as MockMetricExporter,
            patch("guard_core.sync.core.events.otel_handler.MeterProvider") as MockMP,
        ):
            mock_tp = MagicMock()
            MockTP.return_value = mock_tp
            mock_mp = MagicMock()
            MockMP.return_value = mock_mp
            mock_trace.get_tracer_provider.return_value = mock_tp
            mock_metrics.get_meter_provider.return_value = mock_mp
            mock_trace.get_tracer.return_value = mock_tracer
            mock_metrics.get_meter.return_value = mock_meter
            handler.start()
            MockResource.create.assert_called_once()
            MockTP.assert_called_once()
            mock_tp.add_span_processor.assert_called_once()
            mock_trace.set_tracer_provider.assert_called_once_with(mock_tp)
            mock_trace.get_tracer.assert_called_once_with("guard_core.otel")
            MockMP.assert_called_once()
            mock_metrics.set_meter_provider.assert_called_once_with(mock_mp)
            mock_metrics.get_meter.assert_called_once_with("guard_core.otel")
            MockSpanExporter.assert_called_once_with(
                endpoint="http://localhost:4318/v1/traces"
            )
            MockMetricExporter.assert_called_once_with(
                endpoint="http://localhost:4318/v1/metrics"
            )
            assert handler._tracer is mock_tracer
            assert handler._meter is mock_meter
            assert handler._rt_histogram is mock_histogram
            assert handler._request_counter is mock_counter
            assert handler._error_counter is mock_error_counter
            assert handler._owned_tracer_provider is mock_tp
            assert handler._owned_meter_provider is mock_mp
            mock_tp.shutdown.assert_not_called()
            mock_mp.shutdown.assert_not_called()


def test_start_is_idempotent_on_repeated_calls(config: MagicMock) -> None:
    with (
        patch("guard_core.sync.core.events.otel_handler._otel_available", True),
        patch("guard_core.sync.core.events.otel_handler.trace") as mock_trace,
        patch("guard_core.sync.core.events.otel_handler.metrics") as mock_metrics,
        patch("guard_core.sync.core.events.otel_handler.Resource"),
        patch("guard_core.sync.core.events.otel_handler.TracerProvider") as MockTP,
        patch("guard_core.sync.core.events.otel_handler.BatchSpanProcessor"),
        patch("guard_core.sync.core.events.otel_handler.OTLPSpanExporter"),
        patch("guard_core.sync.core.events.otel_handler.PeriodicExportingMetricReader"),
        patch("guard_core.sync.core.events.otel_handler.OTLPMetricExporter"),
        patch("guard_core.sync.core.events.otel_handler.MeterProvider") as MockMP,
    ):
        mock_tp = MagicMock()
        MockTP.return_value = mock_tp
        mock_mp = MagicMock()
        MockMP.return_value = mock_mp
        mock_trace.get_tracer_provider.return_value = mock_tp
        mock_metrics.get_meter_provider.return_value = mock_mp

        handler = OtelHandler(config)
        handler.start()
        handler.start()

        MockTP.assert_called_once()
        MockMP.assert_called_once()
        mock_trace.set_tracer_provider.assert_called_once_with(mock_tp)
        mock_metrics.set_meter_provider.assert_called_once_with(mock_mp)
        assert handler._owned_tracer_provider is mock_tp
        assert handler._owned_meter_provider is mock_mp


def test_start_matrix_no_ambient_tracer_no_ambient_meter_owns_both(
    config: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    with (
        patch("guard_core.sync.core.events.otel_handler._otel_available", True),
        patch("guard_core.sync.core.events.otel_handler.trace") as mock_trace,
        patch("guard_core.sync.core.events.otel_handler.metrics") as mock_metrics,
        patch("guard_core.sync.core.events.otel_handler.Resource"),
        patch("guard_core.sync.core.events.otel_handler.TracerProvider") as MockTP,
        patch("guard_core.sync.core.events.otel_handler.BatchSpanProcessor"),
        patch("guard_core.sync.core.events.otel_handler.OTLPSpanExporter"),
        patch("guard_core.sync.core.events.otel_handler.PeriodicExportingMetricReader"),
        patch("guard_core.sync.core.events.otel_handler.OTLPMetricExporter"),
        patch("guard_core.sync.core.events.otel_handler.MeterProvider") as MockMP,
    ):
        mock_tp = MagicMock()
        MockTP.return_value = mock_tp
        mock_mp = MagicMock()
        MockMP.return_value = mock_mp
        mock_trace.get_tracer_provider.return_value = mock_tp
        mock_metrics.get_meter_provider.return_value = mock_mp

        handler = OtelHandler(config)
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            handler.start()

        assert handler._owned_tracer_provider is mock_tp
        assert handler._owned_meter_provider is mock_mp
        mock_tp.shutdown.assert_not_called()
        mock_mp.shutdown.assert_not_called()
        assert caplog.records == []


def test_start_matrix_ambient_tracer_no_ambient_meter_borrows_tracer_owns_meter(
    config: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    with (
        patch("guard_core.sync.core.events.otel_handler._otel_available", True),
        patch("guard_core.sync.core.events.otel_handler.trace") as mock_trace,
        patch("guard_core.sync.core.events.otel_handler.metrics") as mock_metrics,
        patch("guard_core.sync.core.events.otel_handler.Resource"),
        patch("guard_core.sync.core.events.otel_handler.TracerProvider") as MockTP,
        patch("guard_core.sync.core.events.otel_handler.BatchSpanProcessor"),
        patch("guard_core.sync.core.events.otel_handler.OTLPSpanExporter"),
        patch("guard_core.sync.core.events.otel_handler.PeriodicExportingMetricReader"),
        patch("guard_core.sync.core.events.otel_handler.OTLPMetricExporter"),
        patch("guard_core.sync.core.events.otel_handler.MeterProvider") as MockMP,
    ):
        mock_tp = MagicMock()
        MockTP.return_value = mock_tp
        mock_mp = MagicMock()
        MockMP.return_value = mock_mp
        host_tp = MagicMock()
        mock_trace.get_tracer_provider.return_value = host_tp
        mock_metrics.get_meter_provider.return_value = mock_mp

        handler = OtelHandler(config)
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            handler.start()

        assert vars(handler)["_owned_tracer_provider"] is None
        assert handler._owned_meter_provider is mock_mp
        mock_tp.shutdown.assert_called_once()
        host_tp.shutdown.assert_not_called()
        mock_mp.shutdown.assert_not_called()
        messages = [r.getMessage() for r in caplog.records]
        assert any("tracer provider" in m and "already active" in m for m in messages)
        assert not any("meter provider" in m for m in messages)


def test_start_matrix_no_ambient_tracer_ambient_meter_owns_tracer_borrows_meter(
    config: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    with (
        patch("guard_core.sync.core.events.otel_handler._otel_available", True),
        patch("guard_core.sync.core.events.otel_handler.trace") as mock_trace,
        patch("guard_core.sync.core.events.otel_handler.metrics") as mock_metrics,
        patch("guard_core.sync.core.events.otel_handler.Resource"),
        patch("guard_core.sync.core.events.otel_handler.TracerProvider") as MockTP,
        patch("guard_core.sync.core.events.otel_handler.BatchSpanProcessor"),
        patch("guard_core.sync.core.events.otel_handler.OTLPSpanExporter"),
        patch("guard_core.sync.core.events.otel_handler.PeriodicExportingMetricReader"),
        patch("guard_core.sync.core.events.otel_handler.OTLPMetricExporter"),
        patch("guard_core.sync.core.events.otel_handler.MeterProvider") as MockMP,
    ):
        mock_tp = MagicMock()
        MockTP.return_value = mock_tp
        mock_mp = MagicMock()
        MockMP.return_value = mock_mp
        host_mp = MagicMock()
        mock_trace.get_tracer_provider.return_value = mock_tp
        mock_metrics.get_meter_provider.return_value = host_mp

        handler = OtelHandler(config)
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            handler.start()

        assert handler._owned_tracer_provider is mock_tp
        assert vars(handler)["_owned_meter_provider"] is None
        mock_tp.shutdown.assert_not_called()
        mock_mp.shutdown.assert_called_once()
        host_mp.shutdown.assert_not_called()
        messages = [r.getMessage() for r in caplog.records]
        assert any("meter provider" in m and "already active" in m for m in messages)
        assert not any("tracer provider" in m for m in messages)


def test_start_matrix_ambient_tracer_and_ambient_meter_borrows_both(
    config: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    with (
        patch("guard_core.sync.core.events.otel_handler._otel_available", True),
        patch("guard_core.sync.core.events.otel_handler.trace") as mock_trace,
        patch("guard_core.sync.core.events.otel_handler.metrics") as mock_metrics,
        patch("guard_core.sync.core.events.otel_handler.Resource"),
        patch("guard_core.sync.core.events.otel_handler.TracerProvider") as MockTP,
        patch("guard_core.sync.core.events.otel_handler.BatchSpanProcessor"),
        patch("guard_core.sync.core.events.otel_handler.OTLPSpanExporter"),
        patch("guard_core.sync.core.events.otel_handler.PeriodicExportingMetricReader"),
        patch("guard_core.sync.core.events.otel_handler.OTLPMetricExporter"),
        patch("guard_core.sync.core.events.otel_handler.MeterProvider") as MockMP,
    ):
        mock_tp = MagicMock()
        MockTP.return_value = mock_tp
        mock_mp = MagicMock()
        MockMP.return_value = mock_mp
        host_tp = MagicMock()
        host_mp = MagicMock()
        mock_trace.get_tracer_provider.return_value = host_tp
        mock_metrics.get_meter_provider.return_value = host_mp

        handler = OtelHandler(config)
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            handler.start()

        assert vars(handler)["_owned_tracer_provider"] is None
        assert vars(handler)["_owned_meter_provider"] is None
        mock_tp.shutdown.assert_called_once()
        mock_mp.shutdown.assert_called_once()
        host_tp.shutdown.assert_not_called()
        host_mp.shutdown.assert_not_called()
        messages = [r.getMessage() for r in caplog.records]
        assert any("tracer provider" in m and "already active" in m for m in messages)
        assert any("meter provider" in m and "already active" in m for m in messages)


def test_start_rewrites_explicit_traces_endpoint_for_metrics() -> None:
    cfg = MagicMock(
        otel_service_name="guard-core-test",
        otel_exporter_endpoint="http://collector.internal:4318/v1/traces",
    )
    with (
        patch("guard_core.sync.core.events.otel_handler._otel_available", True),
        patch("guard_core.sync.core.events.otel_handler.trace"),
        patch("guard_core.sync.core.events.otel_handler.metrics"),
        patch("guard_core.sync.core.events.otel_handler.Resource"),
        patch("guard_core.sync.core.events.otel_handler.TracerProvider"),
        patch("guard_core.sync.core.events.otel_handler.BatchSpanProcessor"),
        patch(
            "guard_core.sync.core.events.otel_handler.OTLPSpanExporter"
        ) as MockSpanExporter,
        patch("guard_core.sync.core.events.otel_handler.PeriodicExportingMetricReader"),
        patch(
            "guard_core.sync.core.events.otel_handler.OTLPMetricExporter"
        ) as MockMetricExporter,
        patch("guard_core.sync.core.events.otel_handler.MeterProvider"),
    ):
        handler = OtelHandler(cfg)
        handler.start()
        MockSpanExporter.assert_called_once_with(
            endpoint="http://collector.internal:4318/v1/traces"
        )
        MockMetricExporter.assert_called_once_with(
            endpoint="http://collector.internal:4318/v1/metrics"
        )


def test_start_rewrites_explicit_metrics_endpoint_for_traces() -> None:
    cfg = MagicMock(
        otel_service_name="guard-core-test",
        otel_exporter_endpoint="http://collector.internal:4318/v1/metrics",
    )
    with (
        patch("guard_core.sync.core.events.otel_handler._otel_available", True),
        patch("guard_core.sync.core.events.otel_handler.trace"),
        patch("guard_core.sync.core.events.otel_handler.metrics"),
        patch("guard_core.sync.core.events.otel_handler.Resource"),
        patch("guard_core.sync.core.events.otel_handler.TracerProvider"),
        patch("guard_core.sync.core.events.otel_handler.BatchSpanProcessor"),
        patch(
            "guard_core.sync.core.events.otel_handler.OTLPSpanExporter"
        ) as MockSpanExporter,
        patch("guard_core.sync.core.events.otel_handler.PeriodicExportingMetricReader"),
        patch(
            "guard_core.sync.core.events.otel_handler.OTLPMetricExporter"
        ) as MockMetricExporter,
        patch("guard_core.sync.core.events.otel_handler.MeterProvider"),
    ):
        handler = OtelHandler(cfg)
        handler.start()
        MockSpanExporter.assert_called_once_with(
            endpoint="http://collector.internal:4318/v1/traces"
        )
        MockMetricExporter.assert_called_once_with(
            endpoint="http://collector.internal:4318/v1/metrics"
        )


def test_start_handles_none_endpoint() -> None:
    cfg = MagicMock(
        otel_service_name="guard-core-test",
        otel_exporter_endpoint=None,
    )
    with (
        patch("guard_core.sync.core.events.otel_handler._otel_available", True),
        patch("guard_core.sync.core.events.otel_handler.trace"),
        patch("guard_core.sync.core.events.otel_handler.metrics"),
        patch("guard_core.sync.core.events.otel_handler.Resource"),
        patch("guard_core.sync.core.events.otel_handler.TracerProvider"),
        patch("guard_core.sync.core.events.otel_handler.BatchSpanProcessor"),
        patch(
            "guard_core.sync.core.events.otel_handler.OTLPSpanExporter"
        ) as MockSpanExporter,
        patch("guard_core.sync.core.events.otel_handler.PeriodicExportingMetricReader"),
        patch(
            "guard_core.sync.core.events.otel_handler.OTLPMetricExporter"
        ) as MockMetricExporter,
        patch("guard_core.sync.core.events.otel_handler.MeterProvider"),
    ):
        handler = OtelHandler(cfg)
        handler.start()
        MockSpanExporter.assert_called_once_with(endpoint=None)
        MockMetricExporter.assert_called_once_with(endpoint=None)


def test_start_strips_trailing_slash_from_endpoint() -> None:
    cfg = MagicMock(
        otel_service_name="guard-core-test",
        otel_exporter_endpoint="http://jaeger:4318/",
    )
    with (
        patch("guard_core.sync.core.events.otel_handler._otel_available", True),
        patch("guard_core.sync.core.events.otel_handler.trace"),
        patch("guard_core.sync.core.events.otel_handler.metrics"),
        patch("guard_core.sync.core.events.otel_handler.Resource"),
        patch("guard_core.sync.core.events.otel_handler.TracerProvider"),
        patch("guard_core.sync.core.events.otel_handler.BatchSpanProcessor"),
        patch(
            "guard_core.sync.core.events.otel_handler.OTLPSpanExporter"
        ) as MockSpanExporter,
        patch("guard_core.sync.core.events.otel_handler.PeriodicExportingMetricReader"),
        patch(
            "guard_core.sync.core.events.otel_handler.OTLPMetricExporter"
        ) as MockMetricExporter,
        patch("guard_core.sync.core.events.otel_handler.MeterProvider"),
    ):
        handler = OtelHandler(cfg)
        handler.start()
        MockSpanExporter.assert_called_once_with(
            endpoint="http://jaeger:4318/v1/traces"
        )
        MockMetricExporter.assert_called_once_with(
            endpoint="http://jaeger:4318/v1/metrics"
        )


def test_otlp_signal_endpoint_returns_none_when_endpoint_none() -> None:
    assert OtelHandler._otlp_signal_endpoint(None, "/v1/traces") is None


def test_otlp_signal_endpoint_returns_none_when_endpoint_empty() -> None:
    assert OtelHandler._otlp_signal_endpoint("", "/v1/traces") is None


def test_otlp_signal_endpoint_appends_signal_path_to_base() -> None:
    assert (
        OtelHandler._otlp_signal_endpoint("http://host:4318", "/v1/traces")
        == "http://host:4318/v1/traces"
    )


def test_otlp_signal_endpoint_rewrites_known_signal_suffix() -> None:
    assert (
        OtelHandler._otlp_signal_endpoint("http://host:4318/v1/metrics", "/v1/traces")
        == "http://host:4318/v1/traces"
    )
    assert (
        OtelHandler._otlp_signal_endpoint("http://host:4318/v1/logs", "/v1/metrics")
        == "http://host:4318/v1/metrics"
    )


def test_otlp_signal_endpoint_strips_trailing_slash_from_base() -> None:
    assert (
        OtelHandler._otlp_signal_endpoint("http://host:4318/", "/v1/traces")
        == "http://host:4318/v1/traces"
    )


def test_otlp_signal_endpoint_passthrough_when_signal_already_matches() -> None:
    assert (
        OtelHandler._otlp_signal_endpoint("http://host:4318/v1/traces", "/v1/traces")
        == "http://host:4318/v1/traces"
    )
    assert (
        OtelHandler._otlp_signal_endpoint("http://host:4318/v1/metrics", "/v1/metrics")
        == "http://host:4318/v1/metrics"
    )


def test_import_error_branch() -> None:
    import importlib
    import sys

    module_name = "guard_core.sync.core.events.otel_handler"
    original = sys.modules.get(module_name)
    sys.modules.pop(module_name, None)
    for key in list(sys.modules.keys()):
        if key.startswith("opentelemetry"):
            sys.modules.pop(key, None)

    real_import = __import__

    def block_otel(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: list[str] | None = None,
        level: int = 0,
    ) -> object:
        if name == "opentelemetry" or name.startswith("opentelemetry."):
            raise ImportError("opentelemetry not installed")
        return real_import(name, globals, locals, fromlist or [], level)

    try:
        with patch("builtins.__import__", side_effect=block_otel):
            mod = importlib.import_module(module_name)
            assert mod._otel_available is False
    finally:
        sys.modules.pop(module_name, None)
        sys.modules[module_name] = (
            original if original else importlib.import_module(module_name)
        )
