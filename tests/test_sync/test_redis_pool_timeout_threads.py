import time
import uuid
from collections import Counter
from collections.abc import Callable, Generator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL, MockGuardResponse, SyncMockGuardRequest

POOL_SIZE = 3


def _error_response(status_code: int, message: str) -> MockGuardResponse:
    return MockGuardResponse(message, status_code)


_Setting = bool | int | float | str
_StackFactory = Callable[..., tuple[RateLimitManager, RedisManager]]


@pytest.fixture
def stack_factory() -> Generator[_StackFactory, None]:
    opened: list[RedisManager] = []

    def make(**settings: _Setting) -> tuple[RateLimitManager, RedisManager]:
        defaults: dict[str, _Setting] = {
            "enable_redis": True,
            "redis_url": REDIS_URL,
            "redis_prefix": f"test:wp3:{uuid.uuid4().hex}:",
            "redis_max_connections": POOL_SIZE,
            "rate_limit": 1000,
            "rate_limit_window": 60,
        }
        config = SyncSecurityConfig(**{**defaults, **settings})
        redis = RedisManager(config)
        redis.initialize()
        manager = RateLimitManager(config)
        manager.initialize_redis(redis)
        opened.append(redis)
        return manager, redis

    yield make
    for redis in opened:
        redis.delete_pattern("*")
        redis.close()


def _hold_every_connection(redis: RedisManager) -> list[Any]:
    assert redis._redis is not None
    pool = redis._redis.connection_pool
    return [pool.get_connection() for _ in range(POOL_SIZE)]


def _release(redis: RedisManager, held: list[Any]) -> None:
    assert redis._redis is not None
    for connection in held:
        redis._redis.connection_pool.release(connection)


def test_a_burst_above_the_pool_waits_instead_of_failing(
    stack_factory: _StackFactory,
) -> None:
    manager, _ = stack_factory()

    def one(index: int) -> str:
        ip = f"198.51.100.{index % 250}"
        request = SyncMockGuardRequest(path="/x", client_host=ip)
        try:
            response = manager.check_rate_limit(request, ip, _error_response)
        except GuardRedisError:
            return "error"
        return "allowed" if response is None else "blocked"

    with ThreadPoolExecutor(max_workers=40) as executor:
        outcomes = Counter(executor.map(one, range(120)))

    assert outcomes == {"allowed": 120}


def test_an_exhausted_pool_fails_closed_after_the_pool_timeout(
    stack_factory: _StackFactory,
) -> None:
    manager, redis = stack_factory(redis_pool_timeout=0.3)
    held = _hold_every_connection(redis)
    request = SyncMockGuardRequest(path="/x", client_host="198.51.100.5")

    started = time.monotonic()
    try:
        with pytest.raises(GuardRedisError):
            manager.check_rate_limit(request, "198.51.100.5", _error_response)
    finally:
        _release(redis, held)

    assert 0.25 <= time.monotonic() - started < 2.0


def test_an_exhausted_pool_uses_the_memory_window_when_failing_open(
    stack_factory: _StackFactory,
) -> None:
    manager, redis = stack_factory(
        redis_pool_timeout=0.2, redis_fail_open=True, rate_limit=1
    )
    held = _hold_every_connection(redis)
    request = SyncMockGuardRequest(path="/x", client_host="198.51.100.6")

    try:
        first = manager.check_rate_limit(request, "198.51.100.6", _error_response)
        second = manager.check_rate_limit(request, "198.51.100.6", _error_response)
    finally:
        _release(redis, held)

    assert first is None
    assert second is not None
