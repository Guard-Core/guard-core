from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager

import pytest
from redis.asyncio import Redis

from guard_core.handlers.cloud_ip_stores import RedisCloudIpStore
from guard_core.handlers.redis_handler import RedisManager, close_redis_client
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix

PREFIX = suite_redis_prefix("wp16cloud")


class NoKeysConnection:
    def __init__(self, conn: Redis) -> None:
        self._conn = conn

    async def keys(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("the cloud store issued KEYS on the shared Redis")

    def __getattr__(self, name: str) -> object:
        return getattr(self._conn, name)


async def _clear(client: Redis) -> None:
    for key in [k async for k in client.scan_iter(match=f"{PREFIX}*")]:
        await client.delete(key)


@pytest.fixture
async def conn() -> AsyncGenerator[Redis, None]:
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    await _clear(client)
    yield client
    await _clear(client)
    await close_redis_client(client)


async def test_the_redis_cloud_store_clear_lists_its_keys_with_scan(
    conn: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = RedisManager(
        SecurityConfig(enable_redis=True, redis_url=REDIS_URL, redis_prefix=PREFIX)
    )

    @asynccontextmanager
    async def no_keys_connection() -> AsyncIterator[NoKeysConnection]:
        yield NoKeysConnection(conn)

    monkeypatch.setattr(manager, "get_connection", no_keys_connection)
    store = RedisCloudIpStore(manager)
    await store.set("AWS", {"10.0.0.0/8"})
    await store.set("GCP", {"192.0.2.0/24"})
    await conn.set(f"{PREFIX}other:keep", "1")

    await store.clear()

    left = sorted([k async for k in conn.scan_iter(match=f"{PREFIX}*")])
    assert left == [f"{PREFIX}other:keep"]
