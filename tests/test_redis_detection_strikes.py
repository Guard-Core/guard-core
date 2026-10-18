import time
import uuid
from collections.abc import AsyncGenerator

import pytest

from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL

IP = "203.0.113.200"
WINDOW = 3600


@pytest.fixture
async def redis() -> AsyncGenerator[RedisManager, None]:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"test:wp3fu:strikes:{uuid.uuid4().hex}:",
    )
    manager = RedisManager(config)
    await manager.initialize()
    try:
        yield manager
    finally:
        await manager.delete_pattern("*")
        await manager.close()


async def _record(
    redis: RedisManager,
    categories: tuple[str, ...],
    cap: int = 10_000,
    at: float | None = None,
) -> tuple[int, dict[str, int]]:
    now = time.time() if at is None else at
    return await redis.record_detection_strikes(
        IP, categories, now, now - WINDOW, WINDOW, cap
    )


async def _keys(redis: RedisManager) -> list[str]:
    async with redis.get_connection() as conn:
        found = await conn.keys(f"{redis.config.redis_prefix}detection:*")
    return sorted(found)


async def test_one_strike_returns_the_total_and_every_category_count(
    redis: RedisManager,
) -> None:
    assert await _record(redis, ("xss",)) == (1, {"xss": 1})
    assert await _record(redis, ("xss", "sqli")) == (3, {"xss": 2, "sqli": 1})


async def test_every_key_is_bounded_to_the_cap(redis: RedisManager) -> None:
    for _ in range(6):
        total, counts = await _record(redis, ("xss", "sqli"), cap=4)

    assert (total, counts) == (4, {"xss": 4, "sqli": 4})
    prefix = f"{redis.config.redis_prefix}detection:strikes:{IP}"
    async with redis.get_connection() as conn:
        assert await conn.zcard(prefix) == 4
        assert await conn.zcard(f"{prefix}|xss") == 4


async def test_strikes_outside_the_window_leave_the_count(
    redis: RedisManager,
) -> None:
    now = time.time()
    await _record(redis, ("xss",), at=now - WINDOW - 10)

    assert await _record(redis, ("xss",), at=now) == (1, {"xss": 1})


async def test_every_key_expires_with_the_window(redis: RedisManager) -> None:
    await _record(redis, ("xss", "sqli"))

    async with redis.get_connection() as conn:
        for key in await _keys(redis):
            assert 0 < await conn.ttl(key) <= WINDOW


async def test_the_script_is_reloaded_after_a_script_flush(
    redis: RedisManager,
) -> None:
    await _record(redis, ("xss",))
    async with redis.get_connection() as conn:
        await conn.script_flush()

    assert await _record(redis, ("xss",)) == (2, {"xss": 2})


async def test_forgetting_deletes_every_counter_of_the_ip(
    redis: RedisManager,
) -> None:
    await _record(redis, ("xss", "sqli"))
    other = f"{redis.config.redis_prefix}detection:strikes:203.0.113.201"
    async with redis.get_connection() as conn:
        await conn.zadd(other, {"member": 1})

    await redis.forget_detection_strikes(IP)

    assert await _keys(redis) == [other]


async def test_forgetting_reloads_the_script_after_a_script_flush(
    redis: RedisManager,
) -> None:
    await _record(redis, ("xss",))
    async with redis.get_connection() as conn:
        await conn.script_flush()

    await redis.forget_detection_strikes(IP)

    assert await _keys(redis) == []


async def test_a_disabled_redis_records_and_forgets_nothing() -> None:
    manager = RedisManager(SecurityConfig(enable_redis=False))

    assert await manager.record_detection_strikes(IP, ("xss",), 1.0, 0.0, 10, 5) == (
        0,
        {},
    )
    await manager.forget_detection_strikes(IP)
