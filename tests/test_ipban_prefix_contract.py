import os
import uuid
import warnings
from collections.abc import AsyncGenerator, Generator

import pytest

from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture
async def live_redis() -> AsyncGenerator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=f"wp6-contract:{uuid.uuid4().hex}:"
    )
    manager = RedisManager(config)
    await manager.initialize()
    yield manager
    await manager.delete_pattern("*")
    await manager.close()


def _worker(prefix_length: int, **settings: object) -> IPBanManager:
    IPBanManager._instance = None
    manager = IPBanManager()
    manager.config = SecurityConfig(
        enable_redis=False, ipv6_prefix_length=prefix_length, **settings
    )
    return manager


async def test_the_first_worker_records_its_prefix_length_in_redis(
    live_redis: RedisManager,
) -> None:
    await _worker(64).initialize_redis(live_redis)

    assert await live_redis.get_key("config", "ipv6_prefix_length") == "64"


async def test_a_worker_with_the_same_prefix_length_starts_silently(
    live_redis: RedisManager,
) -> None:
    await _worker(64).initialize_redis(live_redis)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        await _worker(64).initialize_redis(live_redis)


async def test_a_different_prefix_length_warns_and_names_the_key_and_the_steps(
    live_redis: RedisManager,
) -> None:
    await _worker(64).initialize_redis(live_redis)

    with pytest.warns(DeprecationWarning) as caught:
        await _worker(56).initialize_redis(live_redis)

    message = str(caught[0].message)
    assert "ipv6_prefix_length" in message
    assert "config:ipv6_prefix_length" in message
    assert "56" in message and "64" in message
    assert "stop all workers" in message
    assert "redis_prefix" in message


async def test_a_different_prefix_length_is_fatal_under_the_misconfiguration_flag(
    live_redis: RedisManager,
) -> None:
    await _worker(64).initialize_redis(live_redis)

    with pytest.raises(ValueError, match="config:ipv6_prefix_length"):
        await _worker(56, fail_on_misconfiguration=True).initialize_redis(live_redis)


async def test_the_recorded_value_is_kept_when_a_second_worker_disagrees(
    live_redis: RedisManager,
) -> None:
    await _worker(64).initialize_redis(live_redis)

    with pytest.warns(DeprecationWarning):
        await _worker(56).initialize_redis(live_redis)

    assert await live_redis.get_key("config", "ipv6_prefix_length") == "64"
