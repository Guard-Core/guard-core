import time
import uuid
from collections.abc import Generator

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL

IP = "203.0.113.200"
WINDOW = 3600


@pytest.fixture
def redis() -> Generator[RedisManager, None]:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"test:wp3fu:strikes:{uuid.uuid4().hex}:",
    )
    manager = RedisManager(config)
    manager.initialize()
    try:
        yield manager
    finally:
        manager.delete_pattern("*")
        manager.close()


def _record(
    redis: RedisManager,
    categories: tuple[str, ...],
    cap: int = 10_000,
    at: float | None = None,
) -> tuple[int, int, dict[str, int]]:
    now = time.time() if at is None else at
    return redis.record_detection_strikes(
        IP, categories, now, now - WINDOW, WINDOW, cap
    )


def _keys(redis: RedisManager) -> list[str]:
    with redis.get_connection() as conn:
        found = conn.keys(f"{redis.config.redis_prefix}detection:*")
    return sorted(found)


def test_one_strike_returns_the_total_and_every_category_count(
    redis: RedisManager,
) -> None:
    assert _record(redis, ("xss",)) == (1, 0, {"xss": 1})
    assert _record(redis, ("xss", "sqli")) == (3, 0, {"xss": 2, "sqli": 1})


def test_every_key_is_bounded_to_the_cap(redis: RedisManager) -> None:
    for _ in range(6):
        total, _, counts = _record(redis, ("xss", "sqli"), cap=4)

    assert (total, counts) == (4, {"xss": 4, "sqli": 4})
    prefix = f"{redis.config.redis_prefix}detection:strikes:{IP}"
    with redis.get_connection() as conn:
        assert conn.zcard(prefix) == 4
        assert conn.zcard(f"{prefix}|xss") == 4


def test_strikes_outside_the_window_leave_the_count(
    redis: RedisManager,
) -> None:
    now = time.time()
    _record(redis, ("xss",), at=now - WINDOW - 10)

    assert _record(redis, ("xss",), at=now) == (1, 0, {"xss": 1})


def test_every_key_expires_with_the_window(redis: RedisManager) -> None:
    _record(redis, ("xss", "sqli"))

    with redis.get_connection() as conn:
        for key in _keys(redis):
            assert 0 < conn.ttl(key) <= WINDOW


def test_the_script_is_reloaded_after_a_script_flush(
    redis: RedisManager,
) -> None:
    _record(redis, ("xss",))
    with redis.get_connection() as conn:
        conn.script_flush()

    assert _record(redis, ("xss",)) == (2, 0, {"xss": 2})


def test_forgetting_deletes_every_counter_of_the_ip(
    redis: RedisManager,
) -> None:
    _record(redis, ("xss", "sqli"))
    other = f"{redis.config.redis_prefix}detection:strikes:203.0.113.201"
    with redis.get_connection() as conn:
        conn.zadd(other, {"member": 1})

    redis.forget_detection_strikes(IP)

    assert _keys(redis) == [other]


def test_forgetting_reloads_the_script_after_a_script_flush(
    redis: RedisManager,
) -> None:
    _record(redis, ("xss",))
    with redis.get_connection() as conn:
        conn.script_flush()

    redis.forget_detection_strikes(IP)

    assert _keys(redis) == []


def test_a_disabled_redis_records_and_forgets_nothing() -> None:
    manager = RedisManager(SecurityConfig(enable_redis=False))

    assert manager.record_detection_strikes(IP, ("xss",), 1.0, 0.0, 10, 5) == (
        0,
        0,
        {},
    )
    manager.forget_detection_strikes(IP)
