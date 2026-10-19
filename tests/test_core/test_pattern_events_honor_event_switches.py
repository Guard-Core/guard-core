from typing import Any
from unittest.mock import patch

import pytest

from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.detection_engine.monitor import PerformanceMonitor
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest


class _Agent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def send_event(self, event: Any) -> None:
        self.events.append(event)

    async def send_metric(self, _metric: Any) -> None:
        return None

    async def initialize_redis(self, _redis: Any) -> None:
        return None


def _threat_request() -> MockGuardRequest:
    return MockGuardRequest(path="/s", query_params={"q": "<script>alert(1)</script>"})


async def _wired(**overrides: Any) -> tuple[SecurityConfig, _Agent]:
    config = SecurityConfig(enable_agent=True, agent_api_key="a" * 10, **overrides)
    agent = _Agent()
    await HandlerInitializer(
        config=config, agent_handler=agent
    ).initialize_agent_integrations()
    sus_patterns_handler.configure(config)
    return config, agent


async def _event_types(config: SecurityConfig, agent: _Agent) -> list[str]:
    result = await detect_penetration_attempt(_threat_request(), config)
    assert result.is_threat is True
    return [event.event_type for event in agent.events]


async def test_the_pattern_detected_event_is_sent_by_default() -> None:
    config, agent = await _wired()

    assert "pattern_detected" in await _event_types(config, agent)


async def test_agent_enable_events_false_sends_no_pattern_event() -> None:
    config, agent = await _wired(agent_enable_events=False)

    assert await _event_types(config, agent) == []


async def test_a_muted_pattern_detected_is_not_sent() -> None:
    config, agent = await _wired(muted_event_types=frozenset({"pattern_detected"}))

    assert "pattern_detected" not in await _event_types(config, agent)


async def test_a_directly_attached_agent_still_honors_the_mute_and_the_switch() -> None:
    for overrides in (
        {"muted_event_types": frozenset({"pattern_detected"})},
        {"agent_enable_events": False},
    ):
        config = SecurityConfig(**overrides)
        agent = _Agent()
        sus_patterns_handler.configure(config)
        sus_patterns_handler.agent_handler = agent

        assert await _event_types(config, agent) == []
    sus_patterns_handler.agent_handler = None


@pytest.mark.parametrize(
    ("enabled", "expected_agent_is_none"), [(True, False), (False, True)]
)
async def test_the_anomaly_monitor_is_handed_no_agent_when_events_are_off(
    enabled: bool, expected_agent_is_none: bool
) -> None:
    config, agent = await _wired(agent_enable_events=enabled)
    seen: list[Any] = []
    original = PerformanceMonitor.record_metrics

    async def spy(
        self: PerformanceMonitor, rows: Any, agent_handler: Any = None, **kw: Any
    ) -> None:
        seen.append(agent_handler)
        await original(self, rows, agent_handler=agent_handler, **kw)

    with patch.object(PerformanceMonitor, "record_metrics", spy):
        await detect_penetration_attempt(_threat_request(), config)

    assert seen
    assert all((handler is None) is expected_agent_is_none for handler in seen)
