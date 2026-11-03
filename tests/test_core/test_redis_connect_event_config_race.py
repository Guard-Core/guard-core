from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from guard_core.handlers.redis_handler import redis_handler
from guard_core.models import SecurityConfig


class _RecordingAgentHandler:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def send_event(self, event: object) -> None:
        self.events.append(event)


@pytest.mark.asyncio
async def test_connect_success_event_shows_connecting_configs_url() -> None:
    config_a = SecurityConfig(redis_url="redis://config-a:6379")
    config_b = SecurityConfig(redis_url="redis://config-b:6379")
    handler = redis_handler(config_a)
    agent_handler = _RecordingAgentHandler()
    await handler.initialize_agent(agent_handler)

    mock_client = AsyncMock()

    async def _ping_after_concurrent_reconfigure() -> None:
        redis_handler(config_b)

    mock_client.ping.side_effect = _ping_after_concurrent_reconfigure

    with patch(
        "guard_core.handlers.redis_handler._build_redis_client",
        return_value=mock_client,
    ):
        await handler.initialize()

    assert len(agent_handler.events) == 1
    assert agent_handler.events[0].metadata["redis_url"] == "redis://config-a:6379"

    await handler.close()


@pytest.mark.asyncio
async def test_connect_failure_event_shows_connecting_configs_url() -> None:
    config_a = SecurityConfig(redis_url="redis://config-a:6379")
    config_b = SecurityConfig(redis_url="redis://config-b:6379")
    handler = redis_handler(config_a)
    agent_handler = _RecordingAgentHandler()
    await handler.initialize_agent(agent_handler)

    mock_client = AsyncMock()

    async def _ping_and_fail_after_concurrent_reconfigure() -> None:
        redis_handler(config_b)
        raise ConnectionError("boom")

    mock_client.ping.side_effect = _ping_and_fail_after_concurrent_reconfigure

    with (
        patch(
            "guard_core.handlers.redis_handler._build_redis_client",
            return_value=mock_client,
        ),
        pytest.raises(Exception, match="Redis connection failed"),
    ):
        await handler.initialize()

    assert len(agent_handler.events) == 1
    assert agent_handler.events[0].metadata["redis_url"] == "redis://config-a:6379"

    await handler.close()
