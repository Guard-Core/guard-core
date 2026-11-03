import os
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager

import pytest
from redis.asyncio import Redis

from guard_core.handlers.redis_handler import RedisHandlerBase, close_redis_client
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig

REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"
PREFIX = "wp16reset:"


class NoKeysConnection:
    def __init__(self, conn: Redis) -> None:
        self._conn = conn

    async def keys(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("reset issued KEYS on the shared Redis")

    def __getattr__(self, name: str) -> object:
        return getattr(self._conn, name)


class SharedRedis(RedisHandlerBase):
    def __init__(self, conn: Redis) -> None:
        super().__init__(SecurityConfig(enable_redis=False, redis_prefix=PREFIX))
        self._conn = conn

    @asynccontextmanager
    async def get_connection(self) -> AsyncIterator[NoKeysConnection]:
        yield NoKeysConnection(self._conn)


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


async def test_reset_clears_the_headers_keys_with_scan_and_never_keys(
    conn: Redis,
) -> None:
    manager = SecurityHeadersManager.isolated()
    names = [f"{PREFIX}security_headers:{n}" for n in ("csp_config", "hsts_config")]
    many = [f"{PREFIX}security_headers:bulk{i}" for i in range(1200)]
    await conn.mset({key: "1" for key in [*names, *many, f"{PREFIX}other:keep"]})
    manager.redis_handler = SharedRedis(conn)

    await manager.reset()

    left = sorted([k async for k in conn.scan_iter(match=f"{PREFIX}*")])
    assert left == [f"{PREFIX}other:keep"]
