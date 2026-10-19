import os
import uuid
from collections.abc import AsyncGenerator, Generator
from unittest.mock import patch

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from guard_core.exceptions import GuardRedisError
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
NETWORK = "198.51.100.0/24"
HOST = "203.0.113.20"
EXEC = "redis.asyncio.client.Pipeline.execute"
EVALSHA = "redis.asyncio.client.Redis.evalsha"


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture
async def live_redis() -> AsyncGenerator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=f"wp6-atomic:{uuid.uuid4().hex}:"
    )
    manager = RedisManager(config)
    await manager.initialize()
    yield manager
    await manager.delete_pattern("*")
    await manager.close()


def _worker(redis: RedisManager) -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = redis
    manager.config = SecurityConfig(enable_redis=False)
    manager._VERSION_RECHECK_SECONDS = 0.05
    return manager


async def _version(redis: RedisManager) -> int:
    return int(await redis.get_key("ban_version", "counter") or 0)


async def test_a_failed_exec_leaves_no_unannounced_cidr_ban(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)

    with patch(EVALSHA, side_effect=RedisConnectionError("lost")):
        await worker.ban_ip(NETWORK, 600, "operator")

    assert await live_redis.get_key("banned_networks", NETWORK) is None
    assert await _version(live_redis) == 0
    assert len(worker.banned_networks) == 1


async def test_a_failed_exec_keeps_the_ban_when_the_unban_fails(
    live_redis: RedisManager,
) -> None:
    holder = _worker(live_redis)
    await holder.ban_ip(HOST, 600, "threshold_exceeded")
    assert await holder.is_ip_banned(HOST) is True

    with patch(EXEC, side_effect=RedisConnectionError("lost")):
        with pytest.raises(GuardRedisError):
            await holder.unban_ip(HOST)

    assert await live_redis.get_key("banned_ips", HOST) is not None
    assert await _version(live_redis) == 0
    assert await holder.is_ip_banned(HOST) is True
