"""One RedisManager served on two event loops that are both alive: a loop asking for
its connection never aborts the client another live loop is using."""

import asyncio
import threading
from collections.abc import Iterator

import pytest
from redis import Redis as SyncRedis
from redis.asyncio import Redis

from guard_core.exceptions import GuardRedisError
from guard_core.handlers import redis_handler as redis_handler_module
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix
from tests.test_redis_outage_loops import LoopThread

ROUNDS = 6
BLOCK_SECONDS = 5


@pytest.fixture
def built_clients(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[Redis]]:
    real_build = redis_handler_module._build_redis_client
    built: list[Redis] = []

    def recording(
        url: str, max_connections: int, pool_timeout: float, **kwargs: object
    ) -> Redis:
        client = real_build(url, max_connections, pool_timeout, **kwargs)
        built.append(client)
        return client

    monkeypatch.setattr(redis_handler_module, "_build_redis_client", recording)
    yield built


@pytest.fixture
def manager() -> RedisManager:
    return RedisManager(
        SecurityConfig(
            enable_redis=True,
            redis_url=REDIS_URL,
            redis_prefix=suite_redis_prefix("two-live-loops"),
            redis_socket_timeout=BLOCK_SECONDS * 2,
            redis_retries=0,
        )
    )


def open_sockets(client: Redis) -> int:
    pool = client.connection_pool
    return sum(
        connection._writer is not None
        for connection in (*pool._available_connections, *pool._in_use_connections)
    )


def wait_until_blocked_in_redis(key: str) -> None:
    # A blocked BLPOP is visible server side: no sleep, no guess about timing.
    watcher = SyncRedis.from_url(REDIS_URL)
    try:
        for _ in range(BLOCK_SECONDS * 1000):
            if any(c["cmd"] == "blpop" for c in watcher.client_list()):
                return
            threading.Event().wait(0.001)
        raise AssertionError(f"no client blocked on {key}")
    finally:
        watcher.close()


def test_a_second_live_loop_does_not_abort_the_operation_in_flight_on_the_first(
    manager: RedisManager, built_clients: list[Redis]
) -> None:
    prefix = manager.config.redis_prefix
    with LoopThread() as loop_a, LoopThread() as loop_b:

        async def blocked_read(key: str) -> object:
            async with manager.get_connection() as conn:
                return await conn.blpop([key], timeout=BLOCK_SECONDS)

        async def push_from_the_other_loop(key: str) -> None:
            async with manager.get_connection() as conn:
                await conn.rpush(key, "v")

        for round_number in range(ROUNDS):
            key = f"{prefix}round:{round_number}"
            pending = asyncio.run_coroutine_threadsafe(blocked_read(key), loop_a.loop)
            wait_until_blocked_in_redis(key)
            loop_b.run(push_from_the_other_loop(key))
            try:
                popped = pending.result(BLOCK_SECONDS + 5)
            except GuardRedisError as error:
                pytest.fail(
                    f"round {round_number}: the read on loop A was aborted by "
                    f"loop B's connection: {error}"
                )
            assert popped == (key, "v"), f"round {round_number}"
        loop_a.run(manager.close())
    assert len(built_clients) <= 2, "one client per live loop, never one per request"


def test_close_from_one_live_loop_closes_the_other_loops_client_too(
    manager: RedisManager, built_clients: list[Redis]
) -> None:
    prefix = manager.config.redis_prefix

    async def ping() -> object:
        async with manager.get_connection() as conn:
            return await conn.ping()

    with LoopThread() as loop_a, LoopThread() as loop_b:
        assert loop_a.run(ping()) is True
        assert loop_b.run(ping()) is True
        loop_a.run(manager.close())
        # The drop of the other loop's client is queued on that loop.
        loop_b.run(asyncio.sleep(0))
        loop_b.run(asyncio.sleep(0))
        assert [open_sockets(client) for client in built_clients] == [0] * len(
            built_clients
        ), prefix
        with pytest.raises(GuardRedisError, match="closed"):
            loop_b.run(ping())


def test_each_live_loop_answers_for_its_own_client_and_a_new_loop_for_none(
    manager: RedisManager, built_clients: list[Redis]
) -> None:
    async def ping() -> object:
        async with manager.get_connection() as conn:
            return await conn.ping()

    async def connected_here() -> bool:
        return manager.is_connected_on_this_loop()

    with LoopThread() as loop_a, LoopThread() as loop_b:
        assert loop_a.run(connected_here()) is False
        assert loop_a.run(ping()) is True
        assert loop_a.run(connected_here()) is True
        assert loop_b.run(connected_here()) is False
        assert loop_b.run(ping()) is True
        assert loop_b.run(connected_here()) is True
        # The manager's main client belongs to loop B now, loop A's is parked.
        assert loop_a.run(connected_here()) is True
        assert manager._redis is not None
        assert len(built_clients) == 2
        for _ in range(3):
            assert loop_a.run(ping()) is True
            assert loop_b.run(ping()) is True
        assert len(built_clients) == 2, "alternating loops never rebuilds a client"
        loop_a.run(manager.close())


def test_a_closed_loops_parked_client_is_dropped_when_another_loop_connects(
    manager: RedisManager, built_clients: list[Redis]
) -> None:
    async def ping() -> object:
        async with manager.get_connection() as conn:
            return await conn.ping()

    with LoopThread() as loop_a, LoopThread() as loop_c:
        with LoopThread() as loop_b:
            assert loop_b.run(ping()) is True
            assert loop_a.run(ping()) is True
            parked_on_b = built_clients[0]
        assert manager._parked_clients().keys() == {loop_b.loop}
        assert loop_c.run(ping()) is True
        assert open_sockets(parked_on_b) == 0
        assert loop_b.loop not in manager._parked_clients()
        loop_a.run(manager.close())


def test_an_error_on_a_parked_client_discards_only_that_client(
    manager: RedisManager, built_clients: list[Redis]
) -> None:
    async def ping() -> object:
        async with manager.get_connection() as conn:
            return await conn.ping()

    async def discard_own_client() -> bool:
        return await manager._discard_if_current(built_clients[0])

    with LoopThread() as loop_a, LoopThread() as loop_b:
        assert loop_a.run(ping()) is True
        assert loop_b.run(ping()) is True
        assert loop_a.run(discard_own_client()) is True
        assert loop_a.run(discard_own_client()) is False
        assert loop_b.run(ping()) is True
        assert loop_a.run(ping()) is True
        assert len(built_clients) == 3
        loop_a.run(manager.close())


def test_a_connect_on_a_loop_with_a_parked_client_adopts_it(
    manager: RedisManager, built_clients: list[Redis]
) -> None:
    async def ping() -> object:
        async with manager.get_connection() as conn:
            return await conn.ping()

    with LoopThread() as loop_a, LoopThread() as loop_b:
        assert loop_a.run(ping()) is True
        assert loop_b.run(ping()) is True
        assert loop_a.loop in manager._parked_clients()
        loop_a.run(manager.initialize())
        assert manager._client_loop is loop_a.loop
        assert manager._parked_clients().keys() == {loop_b.loop}
        assert len(built_clients) == 2
        loop_a.run(manager.close())
