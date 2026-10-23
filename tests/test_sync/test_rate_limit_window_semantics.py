import math
import time
import uuid
from collections import deque
from collections.abc import Generator
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL, MockGuardResponse, SyncMockGuardRequest

IP = "198.51.100.10"


def _error_response(status_code: int, message: str) -> MockGuardResponse:
    return MockGuardResponse(message, status_code)


def _request() -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path="/x", client_host=IP)


def _memory_config(limit: int, window: int) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False, rate_limit=limit, rate_limit_window=window
    )


def _redis_config(limit: int, window: int) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"test:wp3:{uuid.uuid4().hex}:",
        rate_limit=limit,
        rate_limit_window=window,
    )


@pytest.fixture
def redis_rate_limiter(
    request: pytest.FixtureRequest,
) -> Generator[tuple[RateLimitManager, RedisManager, SyncSecurityConfig], None]:
    limit, window = request.param
    config = _redis_config(limit, window)
    redis = RedisManager(config)
    redis.initialize()
    manager = RateLimitManager(config)
    manager.initialize_redis(redis)
    try:
        yield manager, redis, config
    finally:
        redis.delete_pattern("*")
        redis.close()


def _hit(manager: RateLimitManager) -> Any:
    return manager.check_rate_limit(_request(), IP, _error_response)


def _stored_hits(manager: RateLimitManager) -> int:
    stores: list[deque[float]] = list(manager.request_timestamps.values())
    return sum(len(timestamps) for timestamps in stores)


def test_rejected_requests_never_enter_the_memory_window() -> None:
    manager = RateLimitManager(_memory_config(5, 60))

    results = [_hit(manager) for _ in range(300)]

    assert sum(result is None for result in results) == 5
    assert _stored_hits(manager) == 5


@pytest.mark.parametrize("redis_rate_limiter", [(5, 60)], indirect=True)
def test_rejected_requests_never_enter_the_redis_window(
    redis_rate_limiter: tuple[RateLimitManager, RedisManager, SyncSecurityConfig],
) -> None:
    manager, redis, config = redis_rate_limiter

    results = [_hit(manager) for _ in range(300)]

    assert sum(result is None for result in results) == 5
    with redis.get_connection() as conn:
        assert conn.zcard(f"{config.redis_prefix}rate_limit:rate:{IP}") == 5


def test_a_retrying_client_is_unlocked_when_its_allowed_hits_expire(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = RateLimitManager(_memory_config(2, 2))
    now = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])

    outcomes = []
    for at in (0.0, 0.1, 0.2, 1.9, 2.15):
        now[0] = 1_000_000.0 + at
        outcomes.append((_hit(manager)) is None)

    assert outcomes == [True, True, False, False, True]


@pytest.mark.parametrize("redis_rate_limiter", [(1, 1)], indirect=True)
def test_a_retrying_client_is_unlocked_in_redis_too(
    redis_rate_limiter: tuple[RateLimitManager, RedisManager, SyncSecurityConfig],
) -> None:
    manager, _, _ = redis_rate_limiter

    outcomes = [(_hit(manager)) is None, (_hit(manager)) is None]
    time.sleep(0.95)
    outcomes.append((_hit(manager)) is None)
    time.sleep(0.25)
    outcomes.append((_hit(manager)) is None)

    assert outcomes == [True, False, False, True]


@pytest.mark.parametrize("redis_rate_limiter", [(5, 60)], indirect=True)
def test_a_skewed_peer_clock_cannot_purge_the_shared_window(
    redis_rate_limiter: tuple[RateLimitManager, RedisManager, SyncSecurityConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, _, _ = redis_rate_limiter
    for _ in range(5):
        assert _hit(manager) is None
    assert _hit(manager) is not None

    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 61)
    _hit(manager)
    monkeypatch.setattr(time, "time", real_time)

    assert _hit(manager) is not None


def test_retry_after_is_the_time_until_the_oldest_hit_leaves_the_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = RateLimitManager(_memory_config(2, 60))
    now = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])
    _hit(manager)
    now[0] += 1.0
    _hit(manager)

    now[0] += 1.5
    blocked = _hit(manager)

    assert blocked is not None
    assert blocked.headers["Retry-After"] == str(math.ceil(60 - 2.5))


def test_retry_after_is_at_least_one_second(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = RateLimitManager(_memory_config(1, 60))
    now = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])
    _hit(manager)

    now[0] += 59.9
    blocked = _hit(manager)

    assert blocked is not None
    assert blocked.headers["Retry-After"] == "1"


@pytest.mark.parametrize("redis_rate_limiter", [(1, 5)], indirect=True)
def test_retry_after_counts_down_in_redis(
    redis_rate_limiter: tuple[RateLimitManager, RedisManager, SyncSecurityConfig],
) -> None:
    manager, _, _ = redis_rate_limiter
    _hit(manager)
    time.sleep(1.2)

    blocked = _hit(manager)

    assert blocked is not None
    assert blocked.headers["Retry-After"] in {"3", "4"}
