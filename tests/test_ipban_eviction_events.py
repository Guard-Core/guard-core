import os
import time
import uuid
from collections.abc import AsyncGenerator, Generator
from unittest.mock import AsyncMock

import pytest

from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from guard_core.protocols.redis_protocol import RedisHandlerProtocol
from tests.fake_agent import mock_agent
from tests.ipban_redis_fake import fake_ban_redis

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
ADDRESSES = [f"203.0.113.{index}" for index in range(1, 6)]


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture
async def live_redis() -> AsyncGenerator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=f"wp6-evict:{uuid.uuid4().hex}:"
    )
    manager = RedisManager(config)
    await manager.initialize()
    yield manager
    await manager.delete_pattern("*")
    await manager.close()


def _manager(redis: RedisHandlerProtocol | None) -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = redis
    manager.config = SecurityConfig(enable_redis=False)
    manager.set_capacity(2)
    manager.agent_handler = AsyncMock()
    return manager


def _evicted(manager: IPBanManager) -> list[str]:
    events = [
        call.args[0]
        for call in mock_agent(manager.agent_handler).send_event.call_args_list
    ]
    return [e.ip_address for e in events if e.event_type == "ip_ban_evicted"]


async def _ban_all(manager: IPBanManager, count: int) -> None:
    for index, address in enumerate(ADDRESSES[:count]):
        await manager.ban_ip(address, 600 + index, "t")


async def test_every_eviction_of_a_memory_only_ban_sends_an_event() -> None:
    manager = _manager(None)

    await _ban_all(manager, 5)

    assert _evicted(manager) == ADDRESSES[:3]


async def test_an_eviction_of_a_ban_that_redis_holds_sends_no_event(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)

    await _ban_all(manager, 3)

    assert _evicted(manager) == []
    assert ADDRESSES[0] not in manager.banned_ips
    assert await manager.is_ip_banned(ADDRESSES[0]) is True


async def test_an_eviction_of_a_ban_whose_redis_write_failed_sends_one_event() -> None:
    redis = fake_ban_redis()
    redis.set_key = AsyncMock(side_effect=OSError("down"))
    manager = _manager(redis)

    await _ban_all(manager, 3)

    assert _evicted(manager) == [ADDRESSES[0]]


async def test_the_event_carries_the_remaining_expiry() -> None:
    manager = _manager(None)

    await _ban_all(manager, 3)

    events = [
        call.args[0]
        for call in mock_agent(manager.agent_handler).send_event.call_args_list
    ]
    event = next(e for e in events if e.event_type == "ip_ban_evicted")
    assert event.metadata["remaining_seconds"] == pytest.approx(600, abs=2)


async def test_the_evictions_of_a_resize_and_of_the_next_ban_are_all_reported() -> None:
    manager = _manager(None)
    manager.set_capacity(3)
    for index, duration in enumerate((100, 200, 300)):
        await manager.ban_ip(ADDRESSES[index], duration, "t")
    manager.set_capacity(1)

    await manager.ban_ip(ADDRESSES[3], 400, "t")

    assert sorted(_evicted(manager)) == sorted(ADDRESSES[:3])
    assert manager.evictions_count == 3
    assert manager.evicted_to_report == []


async def test_a_redis_hit_that_evicts_a_memory_only_ban_reports_it(
    live_redis: RedisManager,
) -> None:
    manager = _manager(None)
    manager.set_capacity(1)
    await manager.ban_ip(ADDRESSES[0], 600, "t")
    manager.redis_handler = live_redis
    await live_redis.set_key("banned_ips", ADDRESSES[1], str(time.time() + 900), 900)

    assert await manager.is_ip_banned(ADDRESSES[1]) is True

    assert _evicted(manager) == [ADDRESSES[0]]
