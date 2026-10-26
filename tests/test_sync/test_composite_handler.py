from unittest.mock import MagicMock

import pytest

from guard_core.protocols.agent_protocol import JsonValue
from guard_core.sync.core.events.composite_handler import CompositeAgentHandler


@pytest.fixture
def handler_a() -> MagicMock:
    handler = MagicMock()
    handler.send_event = MagicMock()
    handler.send_metric = MagicMock()
    handler.start = MagicMock()
    handler.stop = MagicMock()
    handler.flush_buffer = MagicMock()
    handler.health_check = MagicMock(return_value=True)
    handler.get_dynamic_rules = MagicMock(return_value=None)
    handler.initialize_redis = MagicMock()
    return handler


@pytest.fixture
def handler_b() -> MagicMock:
    handler = MagicMock()
    handler.send_event = MagicMock()
    handler.send_metric = MagicMock()
    handler.start = MagicMock()
    handler.stop = MagicMock()
    handler.flush_buffer = MagicMock()
    handler.health_check = MagicMock(return_value=True)
    handler.get_dynamic_rules = MagicMock(return_value=None)
    handler.initialize_redis = MagicMock()
    return handler


def test_fanout_send_event(handler_a: MagicMock, handler_b: MagicMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    event = {"event_type": "penetration_attempt", "ip": "1.2.3.4"}
    composite.send_event(event)
    handler_a.send_event.assert_called_once_with(event)
    handler_b.send_event.assert_called_once_with(event)


def test_fanout_send_metric(handler_a: MagicMock, handler_b: MagicMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    metric = {"metric_type": "response_time", "value": 0.5}
    composite.send_metric(metric)
    handler_a.send_metric.assert_called_once_with(metric)
    handler_b.send_metric.assert_called_once_with(metric)


def test_delegates_start_stop(handler_a: MagicMock, handler_b: MagicMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    composite.start()
    handler_a.start.assert_called_once()
    handler_b.start.assert_called_once()
    composite.stop()
    handler_a.stop.assert_called_once()
    handler_b.stop.assert_called_once()


def test_delegates_flush_buffer(handler_a: MagicMock, handler_b: MagicMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    composite.flush_buffer()
    handler_a.flush_buffer.assert_called_once()
    handler_b.flush_buffer.assert_called_once()


def test_delegates_initialize_redis(handler_a: MagicMock, handler_b: MagicMock) -> None:
    redis_handler = MagicMock()
    composite = CompositeAgentHandler([handler_a, handler_b])
    composite.initialize_redis(redis_handler)
    handler_a.initialize_redis.assert_called_once_with(redis_handler)
    handler_b.initialize_redis.assert_called_once_with(redis_handler)


def test_health_check_all_healthy(handler_a: MagicMock, handler_b: MagicMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert composite.health_check() is True


def test_health_check_false_if_any_unhealthy(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_b.health_check = MagicMock(return_value=False)
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert composite.health_check() is False


def test_get_dynamic_rules_returns_first_non_none(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    rules = {"rate_limit": 5}
    handler_a.get_dynamic_rules = MagicMock(return_value=rules)
    handler_b.get_dynamic_rules = MagicMock(return_value=None)
    composite = CompositeAgentHandler([handler_a, handler_b])
    result = composite.get_dynamic_rules()
    assert result == rules


def test_get_dynamic_rules_none_if_all_none(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert composite.get_dynamic_rules() is None


def test_send_event_continues_on_handler_failure(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_a.send_event = MagicMock(side_effect=RuntimeError("boom"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    event = {"event_type": "test"}
    composite.send_event(event)
    handler_b.send_event.assert_called_once_with(event)


def test_send_metric_continues_on_handler_failure(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_a.send_metric = MagicMock(side_effect=RuntimeError("boom"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    metric = {"metric_type": "test"}
    composite.send_metric(metric)
    handler_b.send_metric.assert_called_once_with(metric)


def test_empty_handlers() -> None:
    composite = CompositeAgentHandler([])
    composite.send_event({"event_type": "test"})
    composite.send_metric({"metric_type": "test"})
    composite.start()
    composite.stop()
    assert composite.health_check() is True
    assert composite.get_dynamic_rules() is None


def test_composite_filters_muted_events() -> None:
    from guard_core.sync.core.events.event_types import EventFilter

    h = MagicMock()
    h.send_event = MagicMock()
    composite = CompositeAgentHandler(
        [h],
        event_filter=EventFilter(muted_event_types=frozenset({"penetration_attempt"})),
    )

    class _E:
        event_type = "penetration_attempt"

    composite.send_event(_E())
    h.send_event.assert_not_called()

    class _E2:
        event_type = "ip_blocked"

    composite.send_event(_E2())
    h.send_event.assert_called_once()


def test_composite_filters_muted_metrics() -> None:
    from guard_core.sync.core.events.event_types import EventFilter

    h = MagicMock()
    h.send_metric = MagicMock()
    composite = CompositeAgentHandler(
        [h],
        event_filter=EventFilter(muted_metric_types=frozenset({"response_time"})),
    )

    class _M:
        metric_type = "response_time"

    composite.send_metric(_M())
    h.send_metric.assert_not_called()

    class _M2:
        metric_type = "request_count"

    composite.send_metric(_M2())
    h.send_metric.assert_called_once()


def test_composite_default_filter_allows_everything() -> None:
    h = MagicMock()
    h.send_event = MagicMock()
    composite = CompositeAgentHandler([h])

    class _E:
        event_type = "anything"

    composite.send_event(_E())
    h.send_event.assert_called_once()


def test_composite_event_without_event_type_passes_through() -> None:
    from guard_core.sync.core.events.event_types import EventFilter

    h = MagicMock()
    h.send_event = MagicMock()
    composite = CompositeAgentHandler(
        [h],
        event_filter=EventFilter(muted_event_types=frozenset({"penetration_attempt"})),
    )
    composite.send_event(object())
    h.send_event.assert_called_once()


class _StatsAgent:
    def __init__(self, stats: dict[str, JsonValue]) -> None:
        self._stats = stats

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def send_event(self, _: object) -> None:
        return None

    def send_metric(self, _: object) -> None:
        return None

    def initialize_redis(self, _: object) -> None:
        return None

    def flush_buffer(self) -> None:
        return None

    def get_dynamic_rules(self) -> None:
        return None

    def health_check(self) -> bool:
        return True

    def get_stats(self) -> dict[str, JsonValue]:
        return self._stats


class _BrokenStatsAgent(_StatsAgent):
    def get_stats(self) -> dict[str, JsonValue]:
        raise RuntimeError("stats unavailable")


def test_composite_stats_equal_the_agent_stats_after_initialization() -> None:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.core.initialization.handler_initializer import (
        HandlerInitializer,
    )

    agent_stats: dict[str, JsonValue] = {
        "running": True,
        "events_sent": 3,
        "buffer_stats": {"events": 1},
    }
    initializer = HandlerInitializer(
        config=SyncSecurityConfig(enable_agent=True, agent_api_key="a" * 10),
        agent_handler=_StatsAgent(agent_stats),
    )

    initializer.initialize_agent_integrations()

    assert initializer.composite_handler.get_stats() == agent_stats


def test_composite_without_an_agent_has_empty_stats() -> None:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.core.initialization.handler_initializer import (
        HandlerInitializer,
    )

    initializer = HandlerInitializer(config=SyncSecurityConfig(enable_otel=True))

    initializer.initialize_agent_integrations()

    assert initializer.composite_handler.get_stats() == {}


def test_composite_stats_skip_a_handler_that_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    composite = CompositeAgentHandler(
        [_BrokenStatsAgent({}), _StatsAgent({"events_sent": 1})]
    )

    with caplog.at_level("ERROR", logger="guard_core"):
        assert composite.get_stats() == {"events_sent": 1}

    assert "handler.get_stats failed" in caplog.text
