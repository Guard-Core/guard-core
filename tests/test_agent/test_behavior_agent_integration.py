from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from guard_core.handlers.behavior_handler import BehaviorTracker
from guard_core.models import SecurityConfig


@pytest.fixture(autouse=True)
def patch_security_event() -> Any:
    with patch(
        "guard_core.handlers.behavior_handler.SecurityEvent", create=True
    ) as mock_event:
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield mock_event


@pytest.mark.asyncio
async def test_initialize_agent() -> None:
    config = SecurityConfig()
    tracker = BehaviorTracker(config)
    mock_agent = AsyncMock()

    await tracker.initialize_agent(mock_agent)

    assert tracker.agent_handler is mock_agent


@pytest.mark.asyncio
async def test_apply_action_returns_the_action_and_sends_no_event_of_its_own() -> None:
    config = SecurityConfig()
    tracker = BehaviorTracker(config)
    mock_agent = AsyncMock()
    tracker.agent_handler = mock_agent

    from guard_core.handlers.behavior_handler import BehaviorRule

    rule = BehaviorRule(rule_type="usage", threshold=5, window=300, action="log")

    action_taken = await tracker.apply_action(
        rule=rule,
        client_ip="192.168.1.50",
        endpoint_id="/api/data",
        details="Exceeded usage threshold",
    )

    assert action_taken == "log"
    mock_agent.send_event.assert_not_called()
