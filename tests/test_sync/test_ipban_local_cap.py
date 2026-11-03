import os
import time
from collections.abc import Generator
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import suite_redis_prefix
from tests.test_sync.ipban_redis_fake import fake_ban_redis

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
HOST = "203.0.113.20"
CAP = 1


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture
def live_redis() -> Generator[RedisManager, None]:
    config = SyncSecurityConfig(
        redis_url=REDIS_URL, redis_prefix=suite_redis_prefix("wp6-cap")
    )
    manager = RedisManager(config)
    manager.initialize()
    yield manager
    manager.delete_pattern("*")
    manager.close()


def _worker(redis: RedisManager | None) -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = redis
    manager.config = SyncSecurityConfig(enable_redis=False)
    manager.LOCAL_CACHE_TTL_CAP_SECONDS = CAP
    return manager


def test_a_ban_removed_from_redis_out_of_band_stops_after_the_cap(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    worker.ban_ip(HOST, 600, "t")
    assert worker.is_ip_banned(HOST) is True

    live_redis.delete("banned_ips", HOST)

    assert worker.is_ip_banned(HOST) is True
    time.sleep(CAP + 0.3)
    assert worker.is_ip_banned(HOST) is False


def test_a_ban_that_redis_still_holds_outlives_the_local_cap(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    worker.ban_ip(HOST, 600, "t")
    time.sleep(CAP + 0.3)

    assert worker.is_ip_banned(HOST) is True
    assert worker.banned_ips[HOST] <= time.time() + CAP + 0.1


def test_the_local_copy_of_a_redis_hit_is_capped_too(
    live_redis: RedisManager,
) -> None:
    writer = _worker(live_redis)
    writer.ban_ip(HOST, 600, "t")
    reader = _worker(live_redis)
    assert reader.is_ip_banned(HOST) is True
    assert reader.banned_ips[HOST] <= time.time() + CAP + 0.1

    live_redis.delete("banned_ips", HOST)
    time.sleep(CAP + 0.3)

    assert reader.is_ip_banned(HOST) is False


def test_the_cap_never_lengthens_a_shorter_ban(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    worker.LOCAL_CACHE_TTL_CAP_SECONDS = 3600

    worker.ban_ip(HOST, 5, "t")

    assert worker.banned_ips[HOST] <= time.time() + 5.1


def test_a_ban_held_only_in_memory_keeps_its_full_duration() -> None:
    worker = _worker(None)

    worker.ban_ip(HOST, 600, "t")
    time.sleep(CAP + 0.3)

    assert worker.is_ip_banned(HOST) is True
    assert worker.banned_ips[HOST] > time.time() + 500


def test_a_ban_whose_redis_write_failed_keeps_its_full_duration() -> None:
    redis = fake_ban_redis()
    redis.set_key = MagicMock(side_effect=OSError("down"))
    worker = _worker(None)
    worker.redis_handler = redis

    worker.ban_ip(HOST, 600, "t")

    assert worker.banned_ips[HOST] > time.time() + 500
