import asyncio
import time
from collections import Counter
from collections.abc import AsyncGenerator
from typing import Any, Protocol

import pytest
from pydantic import ValidationError

from guard_core.exceptions import GuardRedisError
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import (
    REDIS_URL,
    MockGuardRequest,
    MockGuardResponse,
    suite_redis_prefix,
)

POOL_SIZE = 3


async def _error_response(status_code: int, message: str) -> MockGuardResponse:
    return MockGuardResponse(message, status_code)


def _config(**settings: object) -> SecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": True,
        "redis_url": REDIS_URL,
        "redis_prefix": suite_redis_prefix("wp3"),
        "redis_max_connections": POOL_SIZE,
        "rate_limit": 1000,
        "rate_limit_window": 60,
    }
    return SecurityConfig(**{**defaults, **settings})


async def _stack(
    config: SecurityConfig,
) -> tuple[RateLimitManager, RedisManager]:
    redis = RedisManager(config)
    await redis.initialize()
    manager = RateLimitManager(config)
    await manager.initialize_redis(redis)
    return manager, redis


class _StackFactory(Protocol):
    async def __call__(
        self, **settings: object
    ) -> tuple[RateLimitManager, RedisManager]: ...


@pytest.fixture
async def stack_factory() -> AsyncGenerator[_StackFactory, None]:
    opened: list[RedisManager] = []

    async def make(**settings: object) -> tuple[RateLimitManager, RedisManager]:
        manager, redis = await _stack(_config(**settings))
        opened.append(redis)
        return manager, redis

    yield make
    for redis in opened:
        await redis.delete_pattern("*")
        await redis.close()


def test_the_pool_timeout_is_a_config_field_defaulting_to_one_second() -> None:
    assert SecurityConfig(enable_redis=False).redis_pool_timeout == 1.0


@pytest.mark.parametrize("value", [0, -1.0])
def test_a_pool_timeout_that_is_not_positive_is_rejected(value: float) -> None:
    with pytest.raises(ValidationError):
        SecurityConfig(enable_redis=False, redis_pool_timeout=value)


async def test_a_burst_above_the_pool_waits_instead_of_failing(  # async-only
    stack_factory: _StackFactory,
) -> None:
    manager, _ = await stack_factory()

    async def one(index: int) -> str:
        ip = f"198.51.100.{index % 250}"
        request = MockGuardRequest(path="/x", client_host=ip)
        try:
            response = await manager.check_rate_limit(request, ip, _error_response)
        except GuardRedisError:
            return "error"
        return "allowed" if response is None else "blocked"

    outcomes = Counter(await asyncio.gather(*(one(i) for i in range(120))))

    assert outcomes == {"allowed": 120}


async def _hold_every_connection(redis: RedisManager) -> list[Any]:
    assert redis._redis is not None
    pool = redis._redis.connection_pool
    return [await pool.get_connection() for _ in range(POOL_SIZE)]


async def _release(redis: RedisManager, held: list[Any]) -> None:
    assert redis._redis is not None
    for connection in held:
        await redis._redis.connection_pool.release(connection)


async def test_an_exhausted_pool_fails_closed_after_the_pool_timeout(  # async-only
    stack_factory: _StackFactory,
) -> None:
    manager, redis = await stack_factory(redis_pool_timeout=0.3)
    held = await _hold_every_connection(redis)
    request = MockGuardRequest(path="/x", client_host="198.51.100.5")

    started = time.monotonic()
    try:
        with pytest.raises(GuardRedisError):
            await manager.check_rate_limit(request, "198.51.100.5", _error_response)
    finally:
        await _release(redis, held)

    assert 0.25 <= time.monotonic() - started < 2.0


async def test_an_exhausted_pool_uses_the_memory_window_when_failing_open(  # async-only
    stack_factory: _StackFactory,
) -> None:
    manager, redis = await stack_factory(
        redis_pool_timeout=0.2, redis_fail_open=True, rate_limit=1
    )
    held = await _hold_every_connection(redis)
    request = MockGuardRequest(path="/x", client_host="198.51.100.6")

    try:
        first = await manager.check_rate_limit(request, "198.51.100.6", _error_response)
        second = await manager.check_rate_limit(
            request, "198.51.100.6", _error_response
        )
    finally:
        await _release(redis, held)

    assert first is None
    assert second is not None
