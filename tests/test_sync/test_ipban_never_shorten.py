import os
import time
import uuid
from collections.abc import Generator
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.redis_handler import RedisManager

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
HOST = "8.8.4.4"
NETWORK = "10.20.30.0/24"
DAY = 86400


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture
def live_redis() -> Generator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=f"wp17-never-shorten:{uuid.uuid4().hex}:"
    )
    manager = RedisManager(config)
    manager.initialize()
    yield manager
    manager.delete_pattern("*")
    manager.close()


def _manager(redis: RedisManager | None = None, **settings: Any) -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = redis
    manager.config = SecurityConfig(enable_redis=redis is not None, **settings)
    return manager


def _ttl_seconds(redis: RedisManager, namespace: str, key: str) -> float:
    with redis.get_connection() as conn:
        pttl = conn.pttl(f"{redis.config.redis_prefix}{namespace}:{key}")
    return float(pttl) / 1000


def test_a_day_long_rule_ban_keeps_its_ttl_under_a_shorter_auto_ban(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)
    manager.ban_ip(HOST, DAY, "dynamic_rule")

    manager.ban_ip(HOST, 60, "threshold_exceeded")

    assert _ttl_seconds(live_redis, "banned_ips", HOST) > DAY - 5
    assert manager.banned_ips[HOST] - time.time() > 60


def test_a_shorter_ban_keeps_a_longer_one_without_redis() -> None:
    manager = _manager()
    manager.ban_ip(HOST, DAY, "dynamic_rule")

    manager.ban_ip(HOST, 60, "threshold_exceeded")

    assert manager.banned_ips[HOST] - time.time() > DAY - 5


def test_a_longer_ban_extends_a_shorter_one_in_redis_and_memory(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)
    manager.ban_ip(HOST, 60, "threshold_exceeded")

    manager.ban_ip(HOST, 3600, "dynamic_rule")

    assert _ttl_seconds(live_redis, "banned_ips", HOST) > 3590
    assert manager.banned_ips[HOST] - time.time() > 3590


def test_a_sixty_second_foreign_ban_is_not_shortened_by_a_thirty_second_one(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)
    manager.ban_ip(HOST, 60, "threshold_exceeded")

    manager.ban_ip(HOST, 30, "threshold_exceeded")

    assert 55 < _ttl_seconds(live_redis, "banned_ips", HOST) <= 60
    assert manager.banned_ips[HOST] - time.time() > 55


def test_an_explicit_unban_then_a_shorter_ban_still_shortens(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)
    manager.ban_ip(HOST, DAY, "dynamic_rule")
    manager.unban_ip(HOST)

    manager.ban_ip(HOST, 60, "threshold_exceeded")

    assert 55 < _ttl_seconds(live_redis, "banned_ips", HOST) <= 60
    assert manager.banned_ips[HOST] - time.time() <= 60


def test_a_cidr_ban_is_never_shortened_in_redis(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)
    manager.ban_ip(NETWORK, DAY, "operator")

    manager.ban_ip(NETWORK, 60, "operator")

    assert _ttl_seconds(live_redis, "banned_networks", NETWORK) > DAY - 5


def test_a_cidr_ban_is_never_shortened_in_memory() -> None:
    manager = _manager()
    manager.ban_ip(NETWORK, DAY, "operator")

    manager.ban_ip(NETWORK, 60, "operator")

    assert len(manager.banned_networks) == 1
    assert manager.banned_networks[0][1] - time.time() > DAY - 5


def test_a_cidr_ban_advances_the_ban_version_only_when_it_wrote(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)
    manager.ban_ip(NETWORK, DAY, "operator")
    written = live_redis.get_key("ban_version", "counter")

    manager.ban_ip(NETWORK, 60, "operator")

    assert written == "1"
    assert live_redis.get_key("ban_version", "counter") == "1"


def test_the_recidive_escalated_duration_still_applies(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis, enable_recidive=True)
    manager._ban_ip_escalating(HOST, 100, "threshold_exceeded")
    live_redis.delete("banned_ips", HOST)
    manager.banned_ips[HOST] = time.time() - 1

    applied = manager._ban_ip_escalating(HOST, 100, "threshold_exceeded")

    assert applied == 200
    assert 195 < _ttl_seconds(live_redis, "banned_ips", HOST) <= 200
    assert 195 < manager.banned_ips[HOST] - time.time() <= 200


def test_the_ban_value_stays_the_expiry_in_seconds_as_text(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)
    manager.ban_ip(HOST, 600, "threshold_exceeded")

    value = live_redis.get_key("banned_ips", HOST)

    assert float(value) == pytest.approx(time.time() + 600, abs=5)
    assert value == str(float(value))
