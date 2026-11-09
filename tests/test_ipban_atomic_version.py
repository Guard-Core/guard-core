import os
from collections.abc import AsyncGenerator, Generator
from time import monotonic
from unittest.mock import patch

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from guard_core.exceptions import GuardRedisError
from guard_core.handlers import redis_handler as redis_handler_module
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import suite_redis_prefix

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
        redis_url=REDIS_URL, redis_prefix=suite_redis_prefix("wp6-atomic")
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


async def test_a_healthy_redis_reads_the_real_value_right_after_a_blip(
    live_redis: RedisManager,
) -> None:
    await live_redis.set_key("ban_version", "probe", "real", ttl=30)
    with pytest.raises(GuardRedisError):
        async with live_redis.get_connection():
            raise RedisConnectionError("one blip")
    started = monotonic()
    assert await live_redis.get_key("ban_version", "probe") == "real"
    assert monotonic() - started < 1.0


class DownClient:
    """What a Redis that refuses every new connection builds."""

    async def ping(self) -> bool:
        raise RedisConnectionError("refused")

    async def aclose(self) -> None:
        return None

    async def close(self) -> None:
        return None


async def test_a_down_redis_raises_after_a_blip_then_answers_503_at_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=suite_redis_prefix("wp6-atomic-down"),
        redis_socket_connect_timeout=0.5,
        redis_socket_timeout=0.5,
        redis_retries=0,
    )
    manager = RedisManager(config)
    await manager.initialize()
    monkeypatch.setattr(redis_handler_module, "_build_redis_client", DownClient)
    with pytest.raises(GuardRedisError):
        async with manager.get_connection():
            raise RedisConnectionError("lost")
    with pytest.raises(GuardRedisError):
        await manager.get_key("ban_version", "counter")
    for _ in range(5):
        started = monotonic()
        with pytest.raises(GuardRedisError):
            await manager.get_key("ban_version", "counter")
        assert monotonic() - started < 0.1
    await manager.close()
