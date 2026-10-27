import logging
from unittest.mock import AsyncMock, patch

import pytest

from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.events.middleware_events import SecurityEventBus
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.models import SecurityConfig


def _initializer(config: SecurityConfig) -> HandlerInitializer:
    agent = AsyncMock()
    agent.start = AsyncMock()
    agent.initialize_redis = AsyncMock()
    return HandlerInitializer(config=config, agent_handler=agent)


async def test_build_event_bus_returns_configured_instance() -> None:
    config = SecurityConfig(
        muted_event_types={"penetration_attempt"},
        agent_enable_events=True,
    )
    initializer = _initializer(config)
    with (
        patch.object(initializer, "initialize_agent_for_handlers", AsyncMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", AsyncMock()),
    ):
        await initializer.initialize_agent_integrations()

    bus = initializer.build_event_bus()
    assert isinstance(bus, SecurityEventBus)
    assert bus.event_filter.muted_event_types == frozenset({"penetration_attempt"})
    assert bus.agent_handler is initializer.composite_handler


async def test_build_metrics_collector_returns_configured_instance() -> None:
    config = SecurityConfig(muted_metric_types={"response_time"})
    initializer = _initializer(config)
    with (
        patch.object(initializer, "initialize_agent_for_handlers", AsyncMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", AsyncMock()),
    ):
        await initializer.initialize_agent_integrations()

    collector = initializer.build_metrics_collector()
    assert isinstance(collector, MetricsCollector)
    assert collector.event_filter.muted_metric_types == frozenset({"response_time"})
    assert collector.agent_handler is initializer.composite_handler


async def test_initialize_agent_integrations_starts_composite_handler() -> None:
    config = SecurityConfig(enable_otel=True)
    initializer = HandlerInitializer(config=config, agent_handler=None)
    fake_composite = AsyncMock()
    with (
        patch.object(
            initializer, "build_composite_handler", return_value=fake_composite
        ),
        patch.object(initializer, "initialize_agent_for_handlers", AsyncMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", AsyncMock()),
    ):
        await initializer.initialize_agent_integrations()

    fake_composite.start.assert_awaited_once()


async def test_shutdown_agent_integrations_stops_composite_handler() -> None:
    config = SecurityConfig(enable_otel=True)
    initializer = HandlerInitializer(config=config, agent_handler=None)
    fake_composite = AsyncMock()
    with (
        patch.object(
            initializer, "build_composite_handler", return_value=fake_composite
        ),
        patch.object(initializer, "initialize_agent_for_handlers", AsyncMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", AsyncMock()),
    ):
        await initializer.initialize_agent_integrations()
        await initializer.shutdown_agent_integrations()

    fake_composite.stop.assert_awaited_once()


async def test_shutdown_is_idempotent() -> None:
    config = SecurityConfig(enable_otel=True)
    initializer = HandlerInitializer(config=config, agent_handler=None)
    fake_composite = AsyncMock()
    with (
        patch.object(
            initializer, "build_composite_handler", return_value=fake_composite
        ),
        patch.object(initializer, "initialize_agent_for_handlers", AsyncMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", AsyncMock()),
    ):
        await initializer.initialize_agent_integrations()
        await initializer.shutdown_agent_integrations()
        await initializer.shutdown_agent_integrations()

    fake_composite.stop.assert_awaited_once()
    assert initializer.composite_handler is None
    assert initializer.event_filter is None


async def test_shutdown_noop_when_not_initialized() -> None:
    config = SecurityConfig()
    initializer = HandlerInitializer(config=config, agent_handler=None)
    await initializer.shutdown_agent_integrations()


async def test_build_event_bus_before_init_raises() -> None:
    initializer = _initializer(SecurityConfig())
    with pytest.raises(RuntimeError, match="initialize_agent_integrations"):
        initializer.build_event_bus()


async def test_build_metrics_collector_before_init_raises() -> None:
    initializer = _initializer(SecurityConfig())
    with pytest.raises(RuntimeError, match="initialize_agent_integrations"):
        initializer.build_metrics_collector()


async def test_composite_routes_subsystem_events_through_filter() -> None:
    config = SecurityConfig(
        muted_event_types={"access_denied"},
        agent_enable_events=True,
    )
    raw_agent = AsyncMock()
    raw_agent.send_event = AsyncMock()
    raw_agent.initialize_redis = AsyncMock()
    initializer = HandlerInitializer(config=config, agent_handler=raw_agent)
    with (
        patch.object(initializer, "initialize_agent_for_handlers", AsyncMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", AsyncMock()),
    ):
        await initializer.initialize_agent_integrations()

    assert initializer.composite_handler is not None
    event = type("E", (), {"event_type": "access_denied"})()
    await initializer.composite_handler.send_event(event)
    raw_agent.send_event.assert_not_called()

    allowed = type("E", (), {"event_type": "ip_blocked"})()
    await initializer.composite_handler.send_event(allowed)
    raw_agent.send_event.assert_called_once()


async def test_composite_start_exception_is_logged_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(enable_otel=True)
    initializer = HandlerInitializer(config=config, agent_handler=None)

    from guard_core.core.events.composite_handler import CompositeAgentHandler

    failing = AsyncMock()
    failing.start.side_effect = RuntimeError("boom")
    composite = CompositeAgentHandler([failing])

    with (
        patch.object(initializer, "build_composite_handler", return_value=composite),
        patch.object(initializer, "initialize_agent_for_handlers", AsyncMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", AsyncMock()),
        caplog.at_level(logging.ERROR, logger="guard_core"),
    ):
        await initializer.initialize_agent_integrations()

    assert any(
        "failed to start" in r.getMessage() and "boom" in r.getMessage()
        for r in caplog.records
    )
