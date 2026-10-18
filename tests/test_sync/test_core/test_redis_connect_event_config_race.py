from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.redis_handler import redis_handler


class _RecordingAgentHandler:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def send_event(self, event: Any) -> None:
        self.events.append(event)


def test_connect_success_event_shows_connecting_configs_url() -> None:
    config_a = SecurityConfig(redis_url="redis://config-a:6379")
    config_b = SecurityConfig(redis_url="redis://config-b:6379")
    handler = redis_handler(config_a)
    agent_handler = _RecordingAgentHandler()
    handler.initialize_agent(agent_handler)

    mock_client = MagicMock()

    def _ping_after_concurrent_reconfigure() -> None:
        redis_handler(config_b)

    mock_client.ping.side_effect = _ping_after_concurrent_reconfigure

    with patch(
        "guard_core.sync.handlers.redis_handler._build_redis_client",
        return_value=mock_client,
    ):
        handler.initialize()

    assert len(agent_handler.events) == 1
    assert agent_handler.events[0].metadata["redis_url"] == "redis://config-a:6379"

    handler.close()


def test_connect_failure_event_shows_connecting_configs_url() -> None:
    config_a = SecurityConfig(redis_url="redis://config-a:6379")
    config_b = SecurityConfig(redis_url="redis://config-b:6379")
    handler = redis_handler(config_a)
    agent_handler = _RecordingAgentHandler()
    handler.initialize_agent(agent_handler)

    mock_client = MagicMock()

    def _ping_and_fail_after_concurrent_reconfigure() -> None:
        redis_handler(config_b)
        raise ConnectionError("boom")

    mock_client.ping.side_effect = _ping_and_fail_after_concurrent_reconfigure

    with (
        patch(
            "guard_core.sync.handlers.redis_handler._build_redis_client",
            return_value=mock_client,
        ),
        pytest.raises(Exception, match="Redis connection failed"),
    ):
        handler.initialize()

    assert len(agent_handler.events) == 1
    assert agent_handler.events[0].metadata["redis_url"] == "redis://config-a:6379"

    handler.close()
