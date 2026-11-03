import asyncio
import math
import time
from collections import deque
from collections.abc import AsyncGenerator

import pytest

from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from tests.conftest import (
    REDIS_URL,
    MockGuardRequest,
    MockGuardResponse,
    suite_redis_prefix,
)

IP = "198.51.100.10"


async def _error_response(status_code: int, message: str) -> MockGuardResponse:
    return MockGuardResponse(message, status_code)


def _request() -> MockGuardRequest:
    return MockGuardRequest(path="/x", client_host=IP)


def _memory_config(limit: int, window: int) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False, rate_limit=limit, rate_limit_window=window
    )


def _redis_config(limit: int, window: int) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=suite_redis_prefix("wp3"),
        rate_limit=limit,
        rate_limit_window=window,
    )


@pytest.fixture
async def redis_rate_limiter(
    request: pytest.FixtureRequest,
) -> AsyncGenerator[tuple[RateLimitManager, RedisManager, SecurityConfig], None]:
    limit, window = request.param
    config = _redis_config(limit, window)
    redis = RedisManager(config)
    await redis.initialize()
    manager = RateLimitManager(config)
    await manager.initialize_redis(redis)
    try:
        yield manager, redis, config
    finally:
        await redis.delete_pattern("*")
        await redis.close()


async def _hit(manager: RateLimitManager) -> GuardResponse | None:
    return await manager.check_rate_limit(_request(), IP, _error_response)


def _stored_hits(manager: RateLimitManager) -> int:
    stores: list[deque[float]] = list(manager.request_timestamps.values())
    return sum(len(timestamps) for timestamps in stores)


async def test_rejected_requests_never_enter_the_memory_window() -> None:
    manager = RateLimitManager(_memory_config(5, 60))

    results = [await _hit(manager) for _ in range(300)]

    assert sum(result is None for result in results) == 5
    assert _stored_hits(manager) == 5


@pytest.mark.parametrize("redis_rate_limiter", [(5, 60)], indirect=True)
async def test_rejected_requests_never_enter_the_redis_window(
    redis_rate_limiter: tuple[RateLimitManager, RedisManager, SecurityConfig],
) -> None:
    manager, redis, config = redis_rate_limiter

    results = [await _hit(manager) for _ in range(300)]

    assert sum(result is None for result in results) == 5
    async with redis.get_connection() as conn:
        assert await conn.zcard(f"{config.redis_prefix}rate_limit:rate:{IP}") == 5


async def test_a_retrying_client_is_unlocked_when_its_allowed_hits_expire(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = RateLimitManager(_memory_config(2, 2))
    now = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])

    outcomes = []
    for at in (0.0, 0.1, 0.2, 1.9, 2.15):
        now[0] = 1_000_000.0 + at
        outcomes.append((await _hit(manager)) is None)

    assert outcomes == [True, True, False, False, True]


@pytest.mark.parametrize("redis_rate_limiter", [(1, 1)], indirect=True)
async def test_a_retrying_client_is_unlocked_in_redis_too(
    redis_rate_limiter: tuple[RateLimitManager, RedisManager, SecurityConfig],
) -> None:
    manager, _, _ = redis_rate_limiter

    outcomes = [(await _hit(manager)) is None, (await _hit(manager)) is None]
    await asyncio.sleep(0.95)
    outcomes.append((await _hit(manager)) is None)
    await asyncio.sleep(0.25)
    outcomes.append((await _hit(manager)) is None)

    assert outcomes == [True, False, False, True]


@pytest.mark.parametrize("redis_rate_limiter", [(5, 60)], indirect=True)
async def test_a_skewed_peer_clock_cannot_purge_the_shared_window(
    redis_rate_limiter: tuple[RateLimitManager, RedisManager, SecurityConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, _, _ = redis_rate_limiter
    for _ in range(5):
        assert await _hit(manager) is None
    assert await _hit(manager) is not None

    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 61)
    await _hit(manager)
    monkeypatch.setattr(time, "time", real_time)

    assert await _hit(manager) is not None


async def test_retry_after_is_the_time_until_the_oldest_hit_leaves_the_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = RateLimitManager(_memory_config(2, 60))
    now = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])
    await _hit(manager)
    now[0] += 1.0
    await _hit(manager)

    now[0] += 1.5
    blocked = await _hit(manager)

    assert blocked is not None
    assert blocked.headers["Retry-After"] == str(math.ceil(60 - 2.5))


async def test_retry_after_is_at_least_one_second(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = RateLimitManager(_memory_config(1, 60))
    now = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])
    await _hit(manager)

    now[0] += 59.9
    blocked = await _hit(manager)

    assert blocked is not None
    assert blocked.headers["Retry-After"] == "1"


@pytest.mark.parametrize("redis_rate_limiter", [(1, 5)], indirect=True)
async def test_retry_after_counts_down_in_redis(
    redis_rate_limiter: tuple[RateLimitManager, RedisManager, SecurityConfig],
) -> None:
    manager, _, _ = redis_rate_limiter
    await _hit(manager)
    await asyncio.sleep(1.2)

    blocked = await _hit(manager)

    assert blocked is not None
    assert blocked.headers["Retry-After"] in {"3", "4"}
