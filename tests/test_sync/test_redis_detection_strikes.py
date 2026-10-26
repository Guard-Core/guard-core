import time
import uuid
from collections.abc import Generator

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL
from tests.test_sync.engine_redis_commands import (
    server_loses_the_script_of_the_next_evalsha,
)

IP = "203.0.113.200"
WINDOW = 3600


@pytest.fixture
def redis() -> Generator[RedisManager, None]:
    config = SyncSecurityConfig(
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


def test_one_strike_returns_the_request_total_and_every_category_count(
    redis: RedisManager,
) -> None:
    assert _record(redis, ("xss",)) == (1, 0, {"xss": 1})
    assert _record(redis, ("xss", "sqli")) == (2, 0, {"xss": 2, "sqli": 1})


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
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    _record(redis, ("xss",))
    turned = server_loses_the_script_of_the_next_evalsha(monkeypatch)

    assert _record(redis, ("xss",)) == (2, 0, {"xss": 2})
    assert len(turned) == 1


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
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    _record(redis, ("xss",))
    turned = server_loses_the_script_of_the_next_evalsha(monkeypatch)

    redis.forget_detection_strikes(IP)

    assert len(turned) == 1
    assert _keys(redis) == []


def test_a_disabled_redis_records_and_forgets_nothing() -> None:
    manager = RedisManager(SyncSecurityConfig(enable_redis=False))

    assert manager.record_detection_strikes(IP, ("xss",), 1.0, 0.0, 10, 5) == (
        0,
        0,
        {},
    )
    manager.forget_detection_strikes(IP)


def test_the_category_read_names_the_rate_limit_violations(
    redis: RedisManager,
) -> None:
    _record(redis, ("xss",))
    with redis.get_connection() as conn:
        key = f"{redis.config.redis_prefix}rate_limit:violations:{IP}"
        conn.zadd(key, {"member": time.time()})

    found = redis.read_detection_categories(IP, time.time() - WINDOW)

    assert found == ["rate_limit", "xss"]
    other = redis.read_detection_categories("203.0.113.201", time.time() - 1)
    assert other == []


def test_the_category_read_drops_categories_outside_the_window(
    redis: RedisManager,
) -> None:
    now = time.time()
    _record(redis, ("xss",), at=now - 100)

    assert redis.read_detection_categories(IP, now - 50) == []
    assert redis.read_detection_categories(IP, now - 200) == []
