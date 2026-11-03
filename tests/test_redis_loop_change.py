import asyncio
from collections.abc import Iterator

import pytest
from redis.asyncio import Redis

from guard_core.handlers.redis_handler import RedisManager, close_redis_client
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix

_CLIENTS: list[Redis] = []


@pytest.fixture
def manager() -> Iterator[RedisManager]:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=suite_redis_prefix("wp313loop"),
    )
    yield RedisManager(config)


async def _set_and_get(manager: RedisManager, value: str) -> str | None:
    await manager.initialize()
    assert manager._redis is not None
    _CLIENTS.append(manager._redis)
    await manager.set_key("loop", "k", value, ttl=30)
    answer = await manager.get_key("loop", "k")
    await _shut_the_loops_connections()
    return answer


async def _shut_the_loops_connections() -> None:
    # What an app does as its loop ends; the manager keeps the dead client.
    for task_client in list(_CLIENTS):
        await close_redis_client(task_client)
    _CLIENTS.clear()


async def _get(manager: RedisManager) -> str | None:
    answer = await manager.get_key("loop", "k")
    assert manager._redis is not None
    _CLIENTS.append(manager._redis)
    await _shut_the_loops_connections()
    return answer


def test_a_client_built_in_one_loop_serves_the_next_loop(
    manager: RedisManager,
) -> None:
    assert asyncio.run(_set_and_get(manager, "one")) == "one"
    first_client = manager._redis

    assert asyncio.run(_get(manager)) == "one"
    assert manager._redis is not first_client
    assert asyncio.run(_get(manager)) == "one"


def test_a_client_of_a_finished_loop_is_dropped_not_closed_from_the_next_loop(
    manager: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    asyncio.run(_set_and_get(manager, "two"))
    closed: list[object] = []

    async def record(client: object) -> None:
        closed.append(client)

    monkeypatch.setattr(manager, "_safe_aclose", record)

    asyncio.run(_get(manager))

    assert closed == []


def test_a_client_is_still_closed_when_it_is_replaced_in_its_own_loop(
    manager: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    closed: list[Redis] = []

    async def scenario() -> None:
        await manager.initialize()
        old_client = manager._redis
        assert old_client is not None

        async def record(client: Redis) -> None:
            closed.append(client)
            await close_redis_client(client)

        monkeypatch.setattr(manager, "_safe_aclose", record)
        await manager.initialize()
        assert closed == [old_client]

    asyncio.run(scenario())
