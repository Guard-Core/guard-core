import os
import uuid
from collections.abc import AsyncGenerator, Generator
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture
async def live_redis() -> AsyncGenerator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=f"wp6-cidr:{uuid.uuid4().hex}:"
    )
    manager = RedisManager(config)
    await manager.initialize()
    yield manager
    await manager.delete_pattern("*")
    await manager.close()


def _events(manager: IPBanManager) -> list[Any]:
    return [call.args[0] for call in manager.agent_handler.send_event.call_args_list]


async def test_a_cidr_ban_sends_an_ip_banned_event() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.agent_handler = Mock(send_event=AsyncMock())

    await manager.ban_ip("198.51.101.0/24", 600, "operator")

    [event] = _events(manager)
    assert event.event_type == "ip_banned"
    assert event.ip_address == "198.51.101.0/24"
    assert event.action_taken == "banned"
    assert event.reason == "operator"
    assert event.metadata == {"duration": 600}


async def test_unbanning_a_cidr_lifts_the_ban_and_sends_an_unban_event() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    await manager.ban_ip("198.51.101.0/24", 600, "operator")
    manager.agent_handler = Mock(send_event=AsyncMock())

    await manager.unban_ip("198.51.101.0/24")

    assert await manager.is_ip_banned("198.51.101.7") is False
    [event] = _events(manager)
    assert event.event_type == "ip_unbanned"
    assert event.ip_address == "198.51.101.0/24"


async def test_a_manual_unban_reports_its_own_reason() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.agent_handler = Mock(send_event=AsyncMock())
    await manager.ban_ip("198.51.100.8", 600, "operator")
    manager.agent_handler.send_event.reset_mock()

    await manager.unban_ip("198.51.100.8")
    await manager.unban_ip("198.51.100.9", reason="dynamic_rule_whitelist")

    reasons = [event.reason for event in _events(manager)]
    assert reasons == ["manual_unban", "dynamic_rule_whitelist"]


async def test_reset_clears_redis_cidr_bans_as_well_as_exact_bans(
    live_redis: RedisManager,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = live_redis
    await manager.ban_ip("198.51.101.0/24", 600, "operator")
    await manager.ban_ip("198.51.100.8", 600, "operator")
    assert await live_redis.keys("banned_*:*")

    await manager.reset()

    assert not await live_redis.keys("banned_*:*")
