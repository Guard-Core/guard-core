import asyncio
import os
import time
import uuid
from collections.abc import AsyncGenerator, Generator
from unittest.mock import AsyncMock

import pytest

from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.ipban_redis_fake import fake_ban_redis

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
HOST = "203.0.113.20"
CAP = 1


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture
async def live_redis() -> AsyncGenerator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=f"wp6-cap:{uuid.uuid4().hex}:"
    )
    manager = RedisManager(config)
    await manager.initialize()
    yield manager
    await manager.delete_pattern("*")
    await manager.close()


def _worker(redis: RedisManager | None) -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = redis
    manager.config = SecurityConfig(enable_redis=False)
    manager.LOCAL_CACHE_TTL_CAP_SECONDS = CAP
    return manager


async def test_a_ban_removed_from_redis_out_of_band_stops_after_the_cap(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    await worker.ban_ip(HOST, 600, "t")
    assert await worker.is_ip_banned(HOST) is True

    await live_redis.delete("banned_ips", HOST)

    assert await worker.is_ip_banned(HOST) is True
    await asyncio.sleep(CAP + 0.3)
    assert await worker.is_ip_banned(HOST) is False


async def test_a_ban_that_redis_still_holds_outlives_the_local_cap(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    await worker.ban_ip(HOST, 600, "t")
    await asyncio.sleep(CAP + 0.3)

    assert await worker.is_ip_banned(HOST) is True
    assert worker.banned_ips[HOST] <= time.time() + CAP + 0.1


async def test_the_local_copy_of_a_redis_hit_is_capped_too(
    live_redis: RedisManager,
) -> None:
    writer = _worker(live_redis)
    await writer.ban_ip(HOST, 600, "t")
    reader = _worker(live_redis)
    assert await reader.is_ip_banned(HOST) is True
    assert reader.banned_ips[HOST] <= time.time() + CAP + 0.1

    await live_redis.delete("banned_ips", HOST)
    await asyncio.sleep(CAP + 0.3)

    assert await reader.is_ip_banned(HOST) is False


async def test_the_cap_never_lengthens_a_shorter_ban(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    worker.LOCAL_CACHE_TTL_CAP_SECONDS = 3600

    await worker.ban_ip(HOST, 5, "t")

    assert worker.banned_ips[HOST] <= time.time() + 5.1


async def test_a_ban_held_only_in_memory_keeps_its_full_duration() -> None:
    worker = _worker(None)

    await worker.ban_ip(HOST, 600, "t")
    await asyncio.sleep(CAP + 0.3)

    assert await worker.is_ip_banned(HOST) is True
    assert worker.banned_ips[HOST] > time.time() + 500


async def test_a_ban_whose_redis_write_failed_keeps_its_full_duration() -> None:
    redis = fake_ban_redis()
    redis.set_key = AsyncMock(side_effect=OSError("down"))
    worker = _worker(None)
    worker.redis_handler = redis

    await worker.ban_ip(HOST, 600, "t")

    assert worker.banned_ips[HOST] > time.time() + 500
