import asyncio
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock

import pytest

from guard_core.handlers.ratelimit_handler import (
    RateLimitManager,
    check_rate_limit_by_ip,
)
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, MockGuardRequest, suite_redis_prefix

LIMIT = 5
IN_FLIGHT = 8
IP = "198.51.100.9"


@pytest.fixture
async def redis_and_config() -> AsyncGenerator[
    tuple[RedisManager, SecurityConfig], None
]:
    prefix = suite_redis_prefix("wp320")
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_rate_limiting=True,
        rate_limit=LIMIT,
        rate_limit_window=60,
    )
    redis = RedisManager(config)
    await redis.initialize()
    yield redis, config
    async with redis.get_connection() as conn:
        async for key in conn.scan_iter(match=f"{prefix}*"):
            await conn.unlink(key)
    await redis.close()


async def test_by_ip_burst_never_exceeds_the_limit(
    redis_and_config: tuple[RedisManager, SecurityConfig],
) -> None:
    redis, config = redis_and_config
    gate = asyncio.Semaphore(IN_FLIGHT)

    async def one() -> bool:
        async with gate:
            return await check_rate_limit_by_ip(IP, config, redis)

    results = await asyncio.gather(*[one() for _ in range(200)])

    assert sum(results) == LIMIT


async def test_manager_pipeline_fallback_burst_never_exceeds_the_limit(
    redis_and_config: tuple[RedisManager, SecurityConfig],
) -> None:
    redis, config = redis_and_config
    manager = RateLimitManager(config)
    await manager.initialize_redis(redis)
    manager.rate_limit_script_sha = None
    request = MockGuardRequest(path="/x", client_host=IP)
    respond = AsyncMock()

    gate = asyncio.Semaphore(IN_FLIGHT)

    async def one() -> object:
        async with gate:
            return await manager.check_rate_limit(request, IP, respond)

    results = await asyncio.gather(*[one() for _ in range(40)])

    assert sum(result is None for result in results) == LIMIT


async def test_by_ip_auto_ban_reaches_the_callers_redis_without_a_guarded_app() -> None:
    prefix = suite_redis_prefix("wp320")
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_rate_limiting=True,
        rate_limit=2,
        rate_limit_window=60,
        enable_ip_banning=True,
        enable_rate_limit_auto_ban=True,
        auto_ban_threshold=3,
        auto_ban_duration=600,
    )
    redis = RedisManager(config)
    await redis.initialize()
    try:
        ip = "198.51.100.77"
        for _ in range(12):
            await check_rate_limit_by_ip(ip, config, redis)

        assert await redis.keys("banned_ips:*") == [f"{prefix}banned_ips:{ip}"]
    finally:
        async with redis.get_connection() as conn:
            async for key in conn.scan_iter(match=f"{prefix}*"):
                await conn.unlink(key)
        await redis.close()
