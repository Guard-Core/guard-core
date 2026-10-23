from typing import Any, cast
from unittest.mock import MagicMock, Mock, patch

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events.metrics import MetricsCollector
from guard_core.sync.core.events.middleware_events import SecurityEventBus
from guard_core.sync.decorators.base import RouteConfig
from tests.test_sync.conftest import SyncMockGuardRequest


def _config(**overrides: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(enable_redis=False, **overrides)


def test_metrics_collector_no_agent() -> None:
    collector = MetricsCollector(None, _config())
    collector.send_metric("test", 1.0)


def test_metrics_collector_disabled() -> None:
    agent = MagicMock()
    collector = MetricsCollector(agent, _config(agent_enable_metrics=False))
    collector.send_metric("test", 1.0)
    agent.send_metric.assert_not_called()


def test_metrics_collector_sends_metric() -> None:
    agent = MagicMock()
    agent.send_metric = MagicMock()
    collector = MetricsCollector(agent, _config(agent_enable_metrics=True))
    with patch(
        "guard_core.sync.core.events.metrics.SecurityMetric", create=True
    ) as mock_metric_cls:
        mock_metric_cls.return_value = MagicMock()
        collector.send_metric("response_time", 0.5, {"endpoint": "/api"})
    agent.send_metric.assert_called_once()


def test_metrics_collector_send_metric_exception() -> None:
    agent = MagicMock()
    agent.send_metric = MagicMock(side_effect=Exception("fail"))
    collector = MetricsCollector(agent, _config(agent_enable_metrics=True))
    with patch("guard_core.sync.core.events.metrics.SecurityMetric", create=True):
        collector.send_metric("test", 1.0)


def test_metrics_collect_request_no_agent() -> None:
    collector = MetricsCollector(None, _config())
    req = SyncMockGuardRequest(path="/api", method="GET")
    collector.collect_request_metrics(req, 0.1, 200)


def test_metrics_collect_request_with_agent() -> None:
    agent = MagicMock()
    agent.send_metric = MagicMock()
    collector = MetricsCollector(agent, _config(agent_enable_metrics=True))
    req = SyncMockGuardRequest(path="/api", method="GET")
    with patch("guard_core.sync.core.events.metrics.SecurityMetric", create=True):
        collector.collect_request_metrics(req, 0.1, 200)
    assert agent.send_metric.call_count == 2


def test_metrics_collect_request_error_status() -> None:
    agent = MagicMock()
    agent.send_metric = MagicMock()
    collector = MetricsCollector(agent, _config(agent_enable_metrics=True))
    req = SyncMockGuardRequest(path="/api", method="GET")
    with patch("guard_core.sync.core.events.metrics.SecurityMetric", create=True):
        collector.collect_request_metrics(req, 0.1, 500)
    assert agent.send_metric.call_count == 3


def test_event_bus_no_agent() -> None:
    bus = SecurityEventBus(None, _config())
    req = SyncMockGuardRequest()
    bus.send_middleware_event("test", req, "blocked", "reason")


def test_event_bus_disabled() -> None:
    agent = MagicMock()
    bus = SecurityEventBus(agent, _config(agent_enable_events=False))
    req = SyncMockGuardRequest()
    bus.send_middleware_event("test", req, "blocked", "reason")
    agent.send_event.assert_not_called()


def test_event_bus_sends_event() -> None:
    agent = MagicMock()
    agent.send_event = MagicMock()
    bus = SecurityEventBus(agent, _config(agent_enable_events=True))
    req = SyncMockGuardRequest()
    with patch(
        "guard_core.sync.core.events.middleware_events.extract_client_ip",
        return_value="1.2.3.4",
    ):
        with patch(
            "guard_core.sync.core.events.middleware_events.SecurityEvent", create=True
        ) as mock_event:
            mock_event.return_value = MagicMock()
            bus.send_middleware_event("test", req, "blocked", "reason")
    agent.send_event.assert_called_once()


def test_event_bus_sends_event_with_geo() -> None:
    agent = MagicMock()
    agent.send_event = MagicMock()
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="US")
    bus = SecurityEventBus(agent, _config(agent_enable_events=True), geo_ip_handler=geo)
    req = SyncMockGuardRequest()
    with patch(
        "guard_core.sync.core.events.middleware_events.extract_client_ip",
        return_value="1.2.3.4",
    ):
        with patch(
            "guard_core.sync.core.events.middleware_events.SecurityEvent", create=True
        ) as mock_event:
            mock_event.return_value = MagicMock()
            bus.send_middleware_event("test", req, "blocked", "reason")
    agent.send_event.assert_called_once()


def test_event_bus_sends_event_exception() -> None:
    agent = MagicMock()
    agent.send_event = MagicMock(side_effect=Exception("fail"))
    bus = SecurityEventBus(agent, _config(agent_enable_events=True))
    req = SyncMockGuardRequest()
    with patch(
        "guard_core.sync.core.events.middleware_events.extract_client_ip",
        return_value="1.2.3.4",
    ):
        with patch(
            "guard_core.sync.core.events.middleware_events.SecurityEvent", create=True
        ):
            bus.send_middleware_event("test", req, "blocked", "reason")


def test_event_bus_https_violation_route_config() -> None:
    agent = MagicMock()
    agent.send_event = MagicMock()
    bus = SecurityEventBus(agent, _config(agent_enable_events=True))
    mock_send = MagicMock()
    cast(Any, bus).send_middleware_event = mock_send
    req = SyncMockGuardRequest(scheme="http")
    rc = RouteConfig()
    rc.require_https = True
    bus.send_https_violation_event(req, rc)
    cast(Mock, bus.send_middleware_event).assert_called_once()
    call_kwargs = cast(Mock, bus.send_middleware_event).call_args
    assert call_kwargs.kwargs["event_type"] == "decorator_violation"


def test_event_bus_https_violation_global() -> None:
    bus = SecurityEventBus(None, _config())
    mock_send = MagicMock()
    cast(Any, bus).send_middleware_event = mock_send
    req = SyncMockGuardRequest(scheme="http")
    bus.send_https_violation_event(req, None)
    cast(Mock, bus.send_middleware_event).assert_called_once()
    call_kwargs = cast(Mock, bus.send_middleware_event).call_args
    assert call_kwargs.kwargs["event_type"] == "https_enforced"


def test_event_bus_https_violation_promotes_decorator_type_and_handler_name() -> None:
    agent = MagicMock()
    agent.send_event = MagicMock()
    bus = SecurityEventBus(agent, _config(agent_enable_events=True))
    req = SyncMockGuardRequest(scheme="http")
    rc = RouteConfig()
    rc.require_https = True

    with patch(
        "guard_core.sync.core.events.middleware_events.extract_client_ip",
        return_value="1.2.3.4",
    ):
        bus.send_https_violation_event(req, rc)

    agent.send_event.assert_called_once()
    sent_event = agent.send_event.call_args[0][0]
    assert sent_event.decorator_type == "authentication"
    assert sent_event.rule_type is None
    assert sent_event.handler_name == "middleware"
    assert sent_event.metadata["decorator_type"] == "authentication"


def test_event_bus_cloud_detection_with_details() -> None:
    agent = MagicMock()
    bus = SecurityEventBus(agent, _config(agent_enable_events=True))
    mock_send = MagicMock()
    cast(Any, bus).send_middleware_event = mock_send
    req = SyncMockGuardRequest()
    cloud_handler = MagicMock()
    cloud_handler.get_cloud_provider_details = MagicMock(
        return_value=("AWS", "10.0.0.0/8")
    )
    cloud_handler.agent_handler = MagicMock()
    cloud_handler.send_cloud_detection_event = MagicMock()
    rc = RouteConfig()
    rc.block_cloud_providers = {"AWS"}
    bus.send_cloud_detection_events(req, "1.2.3.4", ["AWS"], rc, cloud_handler, False)
    cloud_handler.send_cloud_detection_event.assert_called_once()
    cast(Mock, bus.send_middleware_event).assert_called_once()


def test_event_bus_cloud_detection_no_details() -> None:
    bus = SecurityEventBus(None, _config())
    mock_send2 = MagicMock()
    cast(Any, bus).send_middleware_event = mock_send2
    req = SyncMockGuardRequest()
    cloud_handler = MagicMock()
    cloud_handler.get_cloud_provider_details = MagicMock(return_value=None)
    cloud_handler.agent_handler = None
    bus.send_cloud_detection_events(req, "1.2.3.4", ["AWS"], None, cloud_handler, False)
    cast(Mock, bus.send_middleware_event).assert_not_called()


def test_event_bus_geo_exception() -> None:
    agent = MagicMock()
    agent.send_event = MagicMock()
    geo = MagicMock()
    geo.get_country = MagicMock(side_effect=Exception("geo fail"))
    bus = SecurityEventBus(agent, _config(agent_enable_events=True), geo_ip_handler=geo)
    req = SyncMockGuardRequest()
    with patch(
        "guard_core.sync.core.events.middleware_events.extract_client_ip",
        return_value="1.2.3.4",
    ):
        with patch(
            "guard_core.sync.core.events.middleware_events.SecurityEvent", create=True
        ) as mock_event:
            mock_event.return_value = MagicMock()
            bus.send_middleware_event("test", req, "blocked", "reason")
    agent.send_event.assert_called_once()


def test_metrics_collector_filtered_metric() -> None:
    agent = MagicMock()
    agent.send_metric = MagicMock()
    from guard_core.sync.core.events.event_types import (
        METRIC_RESPONSE_TIME,
        EventFilter,
    )

    collector = MetricsCollector(
        agent,
        _config(agent_enable_metrics=True),
        event_filter=EventFilter(muted_metric_types=frozenset({METRIC_RESPONSE_TIME})),
    )
    with patch("guard_core.sync.core.events.metrics.SecurityMetric", create=True):
        collector.send_metric(METRIC_RESPONSE_TIME, 0.5, {"endpoint": "/api"})
    agent.send_metric.assert_not_called()
