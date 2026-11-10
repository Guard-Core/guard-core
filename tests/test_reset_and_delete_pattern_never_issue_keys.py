from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager

import pytest
from redis.asyncio import Redis

from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.ratelimit_handler import rate_limit_handler
from guard_core.handlers.redis_handler import RedisManager, close_redis_client
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix

PREFIX = suite_redis_prefix("wp537keys")


class NoKeysConnection:
    def __init__(self, conn: Redis) -> None:
        self._conn = conn

    async def keys(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("the engine issued KEYS on the shared Redis")

    def __getattr__(self, name: str) -> object:
        return getattr(self._conn, name)


async def _clear(client: Redis) -> None:
    for key in [k async for k in client.scan_iter(match=f"{PREFIX}*")]:
        await client.delete(key)


async def _remaining(client: Redis) -> list[str]:
    return sorted([k async for k in client.scan_iter(match=f"{PREFIX}*")])


@pytest.fixture
async def conn() -> AsyncGenerator[Redis, None]:
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    await _clear(client)
    yield client
    await _clear(client)
    await close_redis_client(client)


@pytest.fixture
def manager(conn: Redis, monkeypatch: pytest.MonkeyPatch) -> RedisManager:
    redis_manager = RedisManager(
        SecurityConfig(enable_redis=True, redis_url=REDIS_URL, redis_prefix=PREFIX)
    )

    @asynccontextmanager
    async def no_keys_connection() -> AsyncIterator[NoKeysConnection]:
        yield NoKeysConnection(conn)

    monkeypatch.setattr(redis_manager, "get_connection", no_keys_connection)
    return redis_manager


async def test_delete_pattern_removes_the_matches_with_scan_and_never_keys(
    conn: Redis, manager: RedisManager
) -> None:
    await conn.set(f"{PREFIX}rate_limit:rate:a", "1")
    await conn.set(f"{PREFIX}other:keep", "1")

    assert await manager.delete_pattern("rate_limit:rate:*") == 1

    assert await _remaining(conn) == [f"{PREFIX}other:keep"]


async def test_the_rate_limit_reset_clears_its_windows_with_scan_and_never_keys(
    conn: Redis, manager: RedisManager
) -> None:
    config = SecurityConfig(
        enable_redis=True, redis_url=REDIS_URL, redis_prefix=PREFIX, rate_limit=2
    )
    limiter = rate_limit_handler(config)
    await limiter.initialize_redis(manager)
    await conn.set(f"{PREFIX}rate_limit:rate:1.2.3.4", "1")
    await conn.set(f"{PREFIX}other:keep", "1")

    await limiter.reset()

    assert await _remaining(conn) == [f"{PREFIX}other:keep"]


async def test_the_ip_ban_reset_clears_its_bans_with_scan_and_never_keys(
    conn: Redis, manager: RedisManager
) -> None:
    bans = IPBanManager()
    bans.redis_handler = manager
    await conn.set(f"{PREFIX}banned_ips:1.2.3.4", "1")
    await conn.set(f"{PREFIX}other:keep", "1")

    await bans.reset()

    left = await _remaining(conn)
    assert f"{PREFIX}other:keep" in left
    assert f"{PREFIX}banned_ips:1.2.3.4" not in left
