import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.behavior_handler import BehaviorTracker


@pytest.fixture(autouse=True)
def patch_security_event() -> Any:
    with patch(
        "guard_core.sync.handlers.behavior_handler.SecurityEvent", create=True
    ) as mock_event:
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield mock_event


def test_initialize_agent() -> None:
    config = SecurityConfig()
    tracker = BehaviorTracker(config)
    mock_agent = MagicMock()

    tracker.initialize_agent(mock_agent)

    assert tracker.agent_handler is mock_agent


def test_send_behavior_event_no_agent_handler() -> None:
    config = SecurityConfig()
    tracker = BehaviorTracker(config)
    tracker.agent_handler = None

    tracker._send_behavior_event(
        event_type="behavioral_violation",
        ip_address="192.168.1.1",
        action_taken="log",
        reason="test reason",
    )


def test_send_behavior_event_success() -> None:
    config = SecurityConfig()
    tracker = BehaviorTracker(config)
    mock_agent = MagicMock()
    tracker.agent_handler = mock_agent

    tracker._send_behavior_event(
        event_type="behavioral_violation",
        ip_address="192.168.1.100",
        action_taken="ban",
        reason="Suspicious behavior detected",
        endpoint="/api/test",
        rule_type="usage",
        threshold=10,
        window=3600,
    )

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "behavioral_violation"
    assert sent_event.ip_address == "192.168.1.100"
    assert sent_event.action_taken == "ban"
    assert sent_event.reason == "Suspicious behavior detected"
    assert sent_event.metadata["endpoint"] == "/api/test"
    assert sent_event.metadata["rule_type"] == "usage"
    assert sent_event.metadata["threshold"] == 10
    assert sent_event.metadata["window"] == 3600


def test_send_behavior_event_exception_handling(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig()
    tracker = BehaviorTracker(config)
    mock_agent = MagicMock()
    mock_agent.send_event.side_effect = Exception("Network error")
    tracker.agent_handler = mock_agent

    caplog.set_level(logging.ERROR)

    tracker._send_behavior_event(
        event_type="behavioral_violation",
        ip_address="192.168.1.101",
        action_taken="alert",
        reason="Test failure",
    )

    assert "Failed to send behavior event to agent: Network error" in caplog.text


def test_apply_action_with_behavior_event() -> None:
    config = SecurityConfig()
    tracker = BehaviorTracker(config)
    mock_agent = MagicMock()
    tracker.agent_handler = mock_agent

    from guard_core.sync.handlers.behavior_handler import BehaviorRule

    rule = BehaviorRule(rule_type="usage", threshold=5, window=300, action="log")

    tracker.apply_action(
        rule=rule,
        client_ip="192.168.1.50",
        endpoint_id="/api/data",
        details="Exceeded usage threshold",
    )

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "behavioral_violation"
    assert sent_event.ip_address == "192.168.1.50"
    assert sent_event.action_taken == "log"
    assert sent_event.reason == "Behavioral rule violated: Exceeded usage threshold"
    assert sent_event.metadata["endpoint"] == "/api/data"
    assert sent_event.metadata["rule_type"] == "usage"
    assert sent_event.metadata["threshold"] == 5
    assert sent_event.metadata["window"] == 300
    assert sent_event.rule_type == "usage"
    assert sent_event.handler_name == "behavior"


def test_apply_action_honors_agent_enable_events() -> None:
    config = SecurityConfig(agent_enable_events=False)
    tracker = BehaviorTracker(config)
    mock_agent = MagicMock()
    tracker.agent_handler = mock_agent

    from guard_core.sync.handlers.behavior_handler import BehaviorRule

    rule = BehaviorRule(rule_type="usage", threshold=5, window=300, action="log")

    action_taken = tracker.apply_action(
        rule=rule,
        client_ip="192.168.1.50",
        endpoint_id="/api/data",
        details="Exceeded usage threshold",
    )

    assert action_taken == "log"
    mock_agent.send_event.assert_not_called()
