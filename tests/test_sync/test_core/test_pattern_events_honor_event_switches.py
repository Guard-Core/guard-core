from typing import Any
from unittest.mock import patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.agent_protocol import JsonValue
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.detection_engine.monitor import PerformanceMonitor
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest


class _Agent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def send_event(self, event: Any) -> None:
        self.events.append(event)

    def send_metric(self, _metric: Any) -> None:
        return None

    def initialize_redis(self, _redis: Any) -> None:
        return None

    def flush_buffer(self) -> None:
        return None

    def get_dynamic_rules(self) -> Any | None:
        return None

    def health_check(self) -> bool:
        return True

    def get_stats(self) -> dict[str, JsonValue]:
        return {}


def _threat_request() -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        path="/s", query_params={"q": "<script>alert(1)</script>"}
    )


def _wired(**overrides: Any) -> tuple[SyncSecurityConfig, _Agent]:
    config = SyncSecurityConfig(enable_agent=True, agent_api_key="a" * 10, **overrides)
    agent = _Agent()
    HandlerInitializer(
        config=config, agent_handler=agent
    ).initialize_agent_integrations()
    sus_patterns_handler.configure(config)
    return config, agent


def _event_types(config: SyncSecurityConfig, agent: _Agent) -> list[str]:
    result = detect_penetration_attempt(_threat_request(), config)
    assert result.is_threat is True
    return [event.event_type for event in agent.events]


def test_the_pattern_detected_event_is_sent_by_default() -> None:
    config, agent = _wired()

    assert "pattern_detected" in _event_types(config, agent)


def test_agent_enable_events_false_sends_no_pattern_event() -> None:
    config, agent = _wired(agent_enable_events=False)

    assert _event_types(config, agent) == []


def test_a_muted_pattern_detected_is_not_sent() -> None:
    config, agent = _wired(muted_event_types=frozenset({"pattern_detected"}))

    assert "pattern_detected" not in _event_types(config, agent)


def test_a_directly_attached_agent_still_honors_the_mute_and_the_switch() -> None:
    for overrides in (
        {"muted_event_types": frozenset({"pattern_detected"})},
        {"agent_enable_events": False},
    ):
        config = SyncSecurityConfig(**overrides)
        agent = _Agent()
        sus_patterns_handler.configure(config)
        sus_patterns_handler.agent_handler = agent

        assert _event_types(config, agent) == []
    sus_patterns_handler.agent_handler = None


@pytest.mark.parametrize(
    ("enabled", "expected_agent_is_none"), [(True, False), (False, True)]
)
def test_the_anomaly_monitor_is_handed_no_agent_when_events_are_off(
    enabled: bool, expected_agent_is_none: bool
) -> None:
    config, agent = _wired(agent_enable_events=enabled)
    seen: list[Any] = []
    original = PerformanceMonitor.record_metrics

    def spy(
        self: PerformanceMonitor, rows: Any, agent_handler: Any = None, **kw: Any
    ) -> None:
        seen.append(agent_handler)
        original(self, rows, agent_handler=agent_handler, **kw)

    with patch.object(PerformanceMonitor, "record_metrics", spy):
        detect_penetration_attempt(_threat_request(), config)

    assert seen
    assert all((handler is None) is expected_agent_is_none for handler in seen)
