from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.events.composite_handler import CompositeAgentHandler
from guard_core.protocols.agent_protocol import JsonValue


@pytest.fixture
def handler_a() -> AsyncMock:
    handler = AsyncMock()
    handler.send_event = AsyncMock()
    handler.send_metric = AsyncMock()
    handler.start = AsyncMock()
    handler.stop = AsyncMock()
    handler.flush_buffer = AsyncMock()
    handler.health_check = AsyncMock(return_value=True)
    handler.get_dynamic_rules = AsyncMock(return_value=None)
    handler.initialize_redis = AsyncMock()
    return handler


@pytest.fixture
def handler_b() -> AsyncMock:
    handler = AsyncMock()
    handler.send_event = AsyncMock()
    handler.send_metric = AsyncMock()
    handler.start = AsyncMock()
    handler.stop = AsyncMock()
    handler.flush_buffer = AsyncMock()
    handler.health_check = AsyncMock(return_value=True)
    handler.get_dynamic_rules = AsyncMock(return_value=None)
    handler.initialize_redis = AsyncMock()
    return handler


async def test_fanout_send_event(handler_a: AsyncMock, handler_b: AsyncMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    event = {"event_type": "penetration_attempt", "ip": "1.2.3.4"}
    await composite.send_event(event)
    handler_a.send_event.assert_awaited_once_with(event)
    handler_b.send_event.assert_awaited_once_with(event)


async def test_fanout_send_metric(handler_a: AsyncMock, handler_b: AsyncMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    metric = {"metric_type": "response_time", "value": 0.5}
    await composite.send_metric(metric)
    handler_a.send_metric.assert_awaited_once_with(metric)
    handler_b.send_metric.assert_awaited_once_with(metric)


async def test_delegates_start_stop(handler_a: AsyncMock, handler_b: AsyncMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    await composite.start()
    handler_a.start.assert_awaited_once()
    handler_b.start.assert_awaited_once()
    await composite.stop()
    handler_a.stop.assert_awaited_once()
    handler_b.stop.assert_awaited_once()


async def test_delegates_flush_buffer(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    await composite.flush_buffer()
    handler_a.flush_buffer.assert_awaited_once()
    handler_b.flush_buffer.assert_awaited_once()


async def test_delegates_initialize_redis(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    redis_handler = MagicMock()
    composite = CompositeAgentHandler([handler_a, handler_b])
    await composite.initialize_redis(redis_handler)
    handler_a.initialize_redis.assert_awaited_once_with(redis_handler)
    handler_b.initialize_redis.assert_awaited_once_with(redis_handler)


async def test_health_check_all_healthy(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert await composite.health_check() is True


async def test_health_check_false_if_any_unhealthy(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    handler_b.health_check = AsyncMock(return_value=False)
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert await composite.health_check() is False


async def test_get_dynamic_rules_returns_first_non_none(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    rules = {"rate_limit": 5}
    handler_a.get_dynamic_rules = AsyncMock(return_value=rules)
    handler_b.get_dynamic_rules = AsyncMock(return_value=None)
    composite = CompositeAgentHandler([handler_a, handler_b])
    result = await composite.get_dynamic_rules()
    assert result == rules


async def test_get_dynamic_rules_none_if_all_none(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert await composite.get_dynamic_rules() is None


async def test_send_event_continues_on_handler_failure(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    handler_a.send_event = AsyncMock(side_effect=RuntimeError("boom"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    event = {"event_type": "test"}
    await composite.send_event(event)
    handler_b.send_event.assert_awaited_once_with(event)


async def test_send_metric_continues_on_handler_failure(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    handler_a.send_metric = AsyncMock(side_effect=RuntimeError("boom"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    metric = {"metric_type": "test"}
    await composite.send_metric(metric)
    handler_b.send_metric.assert_awaited_once_with(metric)


async def test_empty_handlers() -> None:
    composite = CompositeAgentHandler([])
    await composite.send_event({"event_type": "test"})
    await composite.send_metric({"metric_type": "test"})
    await composite.start()
    await composite.stop()
    assert await composite.health_check() is True
    assert await composite.get_dynamic_rules() is None


async def test_composite_filters_muted_events() -> None:
    from guard_core.core.events.event_types import EventFilter

    h = AsyncMock()
    h.send_event = AsyncMock()
    composite = CompositeAgentHandler(
        [h],
        event_filter=EventFilter(muted_event_types=frozenset({"penetration_attempt"})),
    )

    class _E:
        event_type = "penetration_attempt"

    await composite.send_event(_E())
    h.send_event.assert_not_called()

    class _E2:
        event_type = "ip_blocked"

    await composite.send_event(_E2())
    h.send_event.assert_called_once()


async def test_composite_filters_muted_metrics() -> None:
    from guard_core.core.events.event_types import EventFilter

    h = AsyncMock()
    h.send_metric = AsyncMock()
    composite = CompositeAgentHandler(
        [h],
        event_filter=EventFilter(muted_metric_types=frozenset({"response_time"})),
    )

    class _M:
        metric_type = "response_time"

    await composite.send_metric(_M())
    h.send_metric.assert_not_called()

    class _M2:
        metric_type = "request_count"

    await composite.send_metric(_M2())
    h.send_metric.assert_called_once()


async def test_composite_default_filter_allows_everything() -> None:
    h = AsyncMock()
    h.send_event = AsyncMock()
    composite = CompositeAgentHandler([h])

    class _E:
        event_type = "anything"

    await composite.send_event(_E())
    h.send_event.assert_called_once()


async def test_composite_event_without_event_type_passes_through() -> None:
    from guard_core.core.events.event_types import EventFilter

    h = AsyncMock()
    h.send_event = AsyncMock()
    composite = CompositeAgentHandler(
        [h],
        event_filter=EventFilter(muted_event_types=frozenset({"penetration_attempt"})),
    )
    await composite.send_event(object())
    h.send_event.assert_called_once()


class _StatsAgent:
    def __init__(self, stats: dict[str, JsonValue]) -> None:
        self._stats = stats

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def send_event(self, _: object) -> None:
        return None

    async def send_metric(self, _: object) -> None:
        return None

    async def initialize_redis(self, _: object) -> None:
        return None

    async def flush_buffer(self) -> None:
        return None

    async def get_dynamic_rules(self) -> None:
        return None

    async def health_check(self) -> bool:
        return True

    def get_stats(self) -> dict[str, JsonValue]:
        return self._stats


class _BrokenStatsAgent(_StatsAgent):
    def get_stats(self) -> dict[str, JsonValue]:
        raise RuntimeError("stats unavailable")


async def test_composite_stats_equal_the_agent_stats_after_initialization() -> None:
    from guard_core.core.initialization.handler_initializer import HandlerInitializer
    from guard_core.models import SecurityConfig

    agent_stats: dict[str, JsonValue] = {
        "running": True,
        "events_sent": 3,
        "buffer_stats": {"events": 1},
    }
    initializer = HandlerInitializer(
        config=SecurityConfig(enable_agent=True, agent_api_key="a" * 10),
        agent_handler=_StatsAgent(agent_stats),
    )

    await initializer.initialize_agent_integrations()

    assert initializer.composite_handler is not None
    assert initializer.composite_handler.get_stats() == agent_stats


async def test_composite_without_an_agent_has_empty_stats() -> None:
    from guard_core.core.initialization.handler_initializer import HandlerInitializer
    from guard_core.models import SecurityConfig

    initializer = HandlerInitializer(config=SecurityConfig(enable_otel=True))

    await initializer.initialize_agent_integrations()

    assert initializer.composite_handler is not None
    assert initializer.composite_handler.get_stats() == {}


async def test_composite_stats_skip_a_handler_that_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    composite = CompositeAgentHandler(
        [_BrokenStatsAgent({}), _StatsAgent({"events_sent": 1})]
    )

    with caplog.at_level("ERROR", logger="guard_core"):
        assert composite.get_stats() == {"events_sent": 1}

    assert "handler.get_stats failed" in caplog.text
