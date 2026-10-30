import uuid
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ratelimit_handler import (
    RateLimitManager,
    check_rate_limit_by_ip,
)
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL, SyncMockGuardRequest

LIMIT = 5
IN_FLIGHT = 8
IP = "198.51.100.9"


@pytest.fixture
def redis_and_config() -> Generator[tuple[RedisManager, SyncSecurityConfig], None]:
    prefix = f"wp320:{uuid.uuid4().hex[:8]}:"
    config = SyncSecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_rate_limiting=True,
        rate_limit=LIMIT,
        rate_limit_window=60,
    )
    redis = RedisManager(config)
    redis.initialize()
    yield redis, config
    with redis.get_connection() as conn:
        for key in conn.scan_iter(match=f"{prefix}*"):
            conn.unlink(key)
    redis.close()


def test_by_ip_burst_never_exceeds_the_limit(
    redis_and_config: tuple[RedisManager, SyncSecurityConfig],
) -> None:
    redis, config = redis_and_config

    def one(_: int) -> bool:
        return check_rate_limit_by_ip(IP, config, redis)

    with ThreadPoolExecutor(max_workers=IN_FLIGHT) as pool:
        results = list(pool.map(one, range(200)))

    assert sum(results) == LIMIT


def test_manager_pipeline_fallback_burst_never_exceeds_the_limit(
    redis_and_config: tuple[RedisManager, SyncSecurityConfig],
) -> None:
    redis, config = redis_and_config
    manager = RateLimitManager(config)
    manager.initialize_redis(redis)
    manager.rate_limit_script_sha = None
    request = SyncMockGuardRequest(path="/x", client_host=IP)
    respond = MagicMock()

    def one(_: int) -> object:
        return manager.check_rate_limit(request, IP, respond)

    with ThreadPoolExecutor(max_workers=IN_FLIGHT) as pool:
        results = list(pool.map(one, range(40)))

    assert sum(result is None for result in results) == LIMIT


def test_by_ip_auto_ban_reaches_the_callers_redis_without_a_guarded_app() -> None:
    prefix = f"wp320:{uuid.uuid4().hex[:8]}:"
    config = SyncSecurityConfig(
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
    redis.initialize()
    try:
        ip = "198.51.100.77"
        for _ in range(12):
            check_rate_limit_by_ip(ip, config, redis)

        assert redis.keys("banned_ips:*") == [f"{prefix}banned_ips:{ip}"]
    finally:
        with redis.get_connection() as conn:
            for key in conn.scan_iter(match=f"{prefix}*"):
                conn.unlink(key)
        redis.close()
