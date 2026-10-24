import uuid
from collections.abc import Generator

import pytest
from redis import Redis

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL
from tests.test_sync.engine_redis_commands import (
    engine_commands_sent,
    engine_redis_url,
    unwatch_engine_commands,
)


@pytest.fixture
def engine() -> Generator[RedisManager, None]:
    config = SyncSecurityConfig(
        enable_redis=True,
        redis_url=engine_redis_url(REDIS_URL),
        redis_prefix=f"test:wp43:{uuid.uuid4().hex}:",
    )
    manager = RedisManager(config)
    manager.initialize()
    try:
        yield manager
    finally:
        manager.delete_pattern("*")
        manager.close()
        unwatch_engine_commands(config.redis_url)


def _another_client_sends_commands() -> None:
    other = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        for index in range(25):
            other.set(f"test:wp43:other:{index}", "1", ex=5)
            other.get(f"test:wp43:other:{index}")
            other.mget([f"test:wp43:other:{index}"])
            other.smembers(f"test:wp43:other:set:{index}")
    finally:
        other.close()


def test_another_client_changes_no_count_of_the_engine(
    engine: RedisManager,
) -> None:
    url = engine.config.redis_url
    before_all = engine_commands_sent(url)
    before_get = engine_commands_sent(url, "get")

    _another_client_sends_commands()

    assert engine_commands_sent(url) == before_all
    assert engine_commands_sent(url, "get") == before_get


def test_one_extra_engine_command_is_one_more_in_every_count(
    engine: RedisManager,
) -> None:
    url = engine.config.redis_url
    before_all = engine_commands_sent(url)
    before_get = engine_commands_sent(url, "get")

    _another_client_sends_commands()
    with engine.get_connection() as conn:
        conn.get(f"{engine.config.redis_prefix}probe")

    assert engine_commands_sent(url) == before_all + 1
    assert engine_commands_sent(url, "get") == before_get + 1


def test_a_command_a_lua_script_runs_is_counted_under_its_own_name(
    engine: RedisManager,
) -> None:
    url = engine.config.redis_url
    before_all = engine_commands_sent(url)
    before_smembers = engine_commands_sent(url, "smembers")

    with engine.get_connection() as conn:
        conn.eval("return redis.call('SMEMBERS', KEYS[1])", 1, "test:wp43:set")

    assert engine_commands_sent(url, "smembers") == before_smembers + 1
    assert engine_commands_sent(url, "eval") >= 1
    assert engine_commands_sent(url) == before_all + 2


def test_a_command_sent_through_a_second_pool_of_the_engine_is_counted(
    engine: RedisManager,
) -> None:
    url = engine.config.redis_url
    before_all = engine_commands_sent(url)
    second_pool = Redis.from_url(url, decode_responses=True)
    try:
        second_pool.get(f"{engine.config.redis_prefix}probe")
    finally:
        second_pool.close()

    assert engine_commands_sent(url) > before_all
