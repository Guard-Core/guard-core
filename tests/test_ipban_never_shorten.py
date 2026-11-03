import os
import time
from collections.abc import AsyncGenerator, Generator
from typing import Any

import pytest

from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import suite_redis_prefix

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
async def live_redis() -> AsyncGenerator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=suite_redis_prefix("wp17-never-shorten")
    )
    manager = RedisManager(config)
    await manager.initialize()
    yield manager
    await manager.delete_pattern("*")
    await manager.close()


def _manager(redis: RedisManager | None = None, **settings: Any) -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = redis
    manager.config = SecurityConfig(enable_redis=redis is not None, **settings)
    return manager


async def _ttl_seconds(redis: RedisManager, namespace: str, key: str) -> float:
    async with redis.get_connection() as conn:
        pttl = await conn.pttl(f"{redis.config.redis_prefix}{namespace}:{key}")
    return float(pttl) / 1000


async def test_a_day_long_rule_ban_keeps_its_ttl_under_a_shorter_auto_ban(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)
    await manager.ban_ip(HOST, DAY, "dynamic_rule")

    await manager.ban_ip(HOST, 60, "threshold_exceeded")

    assert await _ttl_seconds(live_redis, "banned_ips", HOST) > DAY - 5
    assert manager.banned_ips[HOST] - time.time() > 60


async def test_a_shorter_ban_keeps_a_longer_one_without_redis() -> None:
    manager = _manager()
    await manager.ban_ip(HOST, DAY, "dynamic_rule")

    await manager.ban_ip(HOST, 60, "threshold_exceeded")

    assert manager.banned_ips[HOST] - time.time() > DAY - 5


async def test_a_longer_ban_extends_a_shorter_one_in_redis_and_memory(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)
    await manager.ban_ip(HOST, 60, "threshold_exceeded")

    await manager.ban_ip(HOST, 3600, "dynamic_rule")

    assert await _ttl_seconds(live_redis, "banned_ips", HOST) > 3590
    assert manager.banned_ips[HOST] - time.time() > 3590


async def test_a_sixty_second_foreign_ban_is_not_shortened_by_a_thirty_second_one(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)
    await manager.ban_ip(HOST, 60, "threshold_exceeded")

    await manager.ban_ip(HOST, 30, "threshold_exceeded")

    assert 55 < await _ttl_seconds(live_redis, "banned_ips", HOST) <= 60
    assert manager.banned_ips[HOST] - time.time() > 55


async def test_an_explicit_unban_then_a_shorter_ban_still_shortens(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)
    await manager.ban_ip(HOST, DAY, "dynamic_rule")
    await manager.unban_ip(HOST)

    await manager.ban_ip(HOST, 60, "threshold_exceeded")

    assert 55 < await _ttl_seconds(live_redis, "banned_ips", HOST) <= 60
    assert manager.banned_ips[HOST] - time.time() <= 60


async def test_a_cidr_ban_is_never_shortened_in_redis(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)
    await manager.ban_ip(NETWORK, DAY, "operator")

    await manager.ban_ip(NETWORK, 60, "operator")

    assert await _ttl_seconds(live_redis, "banned_networks", NETWORK) > DAY - 5


async def test_a_cidr_ban_is_never_shortened_in_memory() -> None:
    manager = _manager()
    await manager.ban_ip(NETWORK, DAY, "operator")

    await manager.ban_ip(NETWORK, 60, "operator")

    assert len(manager.banned_networks) == 1
    assert manager.banned_networks[0][1] - time.time() > DAY - 5


async def test_a_cidr_ban_advances_the_ban_version_only_when_it_wrote(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)
    await manager.ban_ip(NETWORK, DAY, "operator")
    written = await live_redis.get_key("ban_version", "counter")

    await manager.ban_ip(NETWORK, 60, "operator")

    assert written == "1"
    assert await live_redis.get_key("ban_version", "counter") == "1"


async def test_the_recidive_escalated_duration_still_applies(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis, enable_recidive=True)
    await manager._ban_ip_escalating(HOST, 100, "threshold_exceeded")
    await live_redis.delete("banned_ips", HOST)
    manager.banned_ips[HOST] = time.time() - 1

    applied = await manager._ban_ip_escalating(HOST, 100, "threshold_exceeded")

    assert applied == 200
    assert 195 < await _ttl_seconds(live_redis, "banned_ips", HOST) <= 200
    assert 195 < manager.banned_ips[HOST] - time.time() <= 200


async def test_the_ban_value_stays_the_expiry_in_seconds_as_text(
    live_redis: RedisManager,
) -> None:
    manager = _manager(live_redis)
    await manager.ban_ip(HOST, 600, "threshold_exceeded")

    value = await live_redis.get_key("banned_ips", HOST)

    assert value is not None
    assert float(value) == pytest.approx(time.time() + 600, abs=5)
    assert value == str(float(value))
