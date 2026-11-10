import uuid
from collections.abc import AsyncGenerator
from urllib.parse import urlsplit, urlunsplit

import pytest
from redis.asyncio import Redis

from guard_core.handlers.redis_handler import RedisManager, close_redis_client
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_PREFIX, REDIS_URL, suite_redis_prefix
from tests.engine_redis_commands import (
    _MONITORS,
    engine_commands_sent,
    engine_redis_url,
    server_loses_the_script_of_the_next_evalsha,
    unwatch_all_engine_commands,
    unwatch_engine_commands,
)


@pytest.fixture
async def engine() -> AsyncGenerator[RedisManager, None]:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=engine_redis_url(REDIS_URL),
        redis_prefix=suite_redis_prefix("wp43"),
    )
    manager = RedisManager(config)
    await manager.initialize()
    try:
        yield manager
    finally:
        await manager.delete_pattern("*")
        await manager.close()
        unwatch_engine_commands(config.redis_url)


async def _another_client_sends_commands() -> None:
    other = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        for index in range(25):
            await other.set(f"{REDIS_PREFIX}wp43:other:{index}", "1", ex=5)
            await other.get(f"{REDIS_PREFIX}wp43:other:{index}")
            await other.mget([f"{REDIS_PREFIX}wp43:other:{index}"])
            await other.smembers(f"{REDIS_PREFIX}wp43:other:set:{index}")
    finally:
        await close_redis_client(other)


async def test_another_client_changes_no_count_of_the_engine(
    engine: RedisManager,
) -> None:
    url = engine.config.redis_url
    before_all = await engine_commands_sent(url)
    before_get = await engine_commands_sent(url, "get")

    await _another_client_sends_commands()

    assert await engine_commands_sent(url) == before_all
    assert await engine_commands_sent(url, "get") == before_get


async def test_one_extra_engine_command_is_one_more_in_every_count(
    engine: RedisManager,
) -> None:
    url = engine.config.redis_url
    before_all = await engine_commands_sent(url)
    before_get = await engine_commands_sent(url, "get")

    await _another_client_sends_commands()
    async with engine.get_connection() as conn:
        await conn.get(f"{engine.config.redis_prefix}probe")

    assert await engine_commands_sent(url) == before_all + 1
    assert await engine_commands_sent(url, "get") == before_get + 1


async def test_a_command_a_lua_script_runs_is_counted_under_its_own_name(
    engine: RedisManager,
) -> None:
    url = engine.config.redis_url
    before_all = await engine_commands_sent(url)
    before_smembers = await engine_commands_sent(url, "smembers")

    async with engine.get_connection() as conn:
        await conn.eval(
            "return redis.call('SMEMBERS', KEYS[1])", 1, f"{REDIS_PREFIX}wp43:set"
        )

    assert await engine_commands_sent(url, "smembers") == before_smembers + 1
    assert await engine_commands_sent(url, "eval") >= 1
    assert await engine_commands_sent(url) == before_all + 2


async def test_a_command_sent_through_a_second_pool_of_the_engine_is_counted(
    engine: RedisManager,
) -> None:
    url = engine.config.redis_url
    before_all = await engine_commands_sent(url)
    second_pool = Redis.from_url(url, decode_responses=True)
    try:
        await second_pool.get(f"{engine.config.redis_prefix}probe")
    finally:
        await close_redis_client(second_pool)

    assert await engine_commands_sent(url) > before_all


async def test_unwatching_all_closes_every_monitor_a_test_left_open(
    engine: RedisManager,
) -> None:
    await engine_commands_sent(engine.config.redis_url)
    monitor = next(iter(_MONITORS.values()))

    unwatch_all_engine_commands()

    assert not _MONITORS
    assert monitor._reader.closed
    monitor._thread.join(timeout=5)
    assert not monitor._thread.is_alive()


async def test_a_noscript_retry_counts_as_one_script_call(
    engine: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = engine.config.redis_url
    key = f"noscript_{uuid.uuid4().hex}"
    await engine.record_sliding_window_hit("wp152", key, 2e9, 2e9 - 1000, 60)
    before_evalsha = await engine_commands_sent(url, "evalsha")
    before_script = await engine_commands_sent(url, "script")
    turned = server_loses_the_script_of_the_next_evalsha(monkeypatch)

    await engine.record_sliding_window_hit("wp152", key, 2e9, 2e9 - 1000, 60)

    assert len(turned) == 1
    assert await engine_commands_sent(url, "evalsha") - before_evalsha == 1
    assert await engine_commands_sent(url, "script") - before_script == 0
    await engine.record_sliding_window_hit("wp152", key, 2e9, 2e9 - 1000, 60)
    assert await engine_commands_sent(url, "evalsha") - before_evalsha == 2


async def test_commands_of_another_database_are_not_kept_by_the_watch(
    engine: RedisManager,
) -> None:
    url = engine.config.redis_url
    assert url is not None
    watched = int(urlsplit(url).path.lstrip("/") or 0)
    other_url = urlunsplit(urlsplit(REDIS_URL)._replace(path=f"/{(watched + 3) % 16}"))
    other_key = f"{REDIS_PREFIX}wp548:other-db"
    before = await engine_commands_sent(url, "get")

    other = Redis.from_url(other_url, decode_responses=True)
    try:
        for _ in range(20):
            await other.set(other_key, "1", ex=5)
            await other.get(other_key)
    finally:
        await other.delete(other_key)
        await close_redis_client(other)
    async with engine.get_connection() as conn:
        await conn.get(f"{engine.config.redis_prefix}probe")

    assert await engine_commands_sent(url, "get") == before + 1
    kept = [arguments for _, _, arguments in _MONITORS[url].snapshot()]
    assert not [arguments for arguments in kept if other_key in arguments]
