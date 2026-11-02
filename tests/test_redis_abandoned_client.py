import asyncio
import gc
import threading
import warnings
from collections.abc import Callable
from unittest.mock import Mock

import pytest
from redis.asyncio import Redis
from redis.asyncio.connection import Connection

from guard_core import _redis_abandoned_client as abandoned
from guard_core._redis_abandoned_client import abandon_client
from guard_core._redis_client_loop import EventLoop
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL


def _manager() -> RedisManager:
    return RedisManager(
        SecurityConfig(
            enable_redis=True, redis_url=REDIS_URL, redis_prefix="wp336abandon:"
        )
    )


async def _use(manager: RedisManager) -> None:
    await manager.initialize()
    await manager.get_key("probe", "k")


def _resource_warnings_while(action: Callable[[], None]) -> list[str]:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        action()
        gc.collect()
    return [str(w.message) for w in caught if issubclass(w.category, ResourceWarning)]


def _connections_of(client: Redis) -> list[Connection]:
    pool = client.connection_pool
    return [*pool._available_connections, *pool._in_use_connections]


def test_a_client_left_by_a_finished_loop_leaks_nothing_in_the_next_loop() -> None:
    manager = _manager()
    asyncio.run(_use(manager))

    def second_loop() -> None:
        asyncio.run(_use(manager))
        asyncio.run(manager.close())

    assert _resource_warnings_while(second_loop) == []


def test_a_closed_loops_client_has_every_socket_released() -> None:
    manager = _manager()
    asyncio.run(_use(manager))
    client = manager._redis
    assert client is not None
    loop = manager._client_loop
    assert loop is not None and loop.is_closed()
    assert _connections_of(client)

    abandon_client(client, loop)

    assert all(c._writer is None for c in _connections_of(client))


def test_a_loop_closing_after_the_running_check_still_gets_its_sockets_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _manager()
    asyncio.run(_use(manager))
    client = manager._redis
    loop = manager._client_loop
    assert client is not None and loop is not None and loop.is_closed()
    monkeypatch.setattr(loop, "is_running", lambda: True)

    abandon_client(client, loop)

    assert all(c._writer is None for c in _connections_of(client))


def test_a_running_loops_client_is_dropped_on_its_own_thread_not_this_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _manager()
    loop_ready = threading.Event()
    stop = asyncio.Event()
    owner: dict[str, EventLoop] = {}

    async def own_the_client() -> None:
        await _use(manager)
        owner["loop"] = asyncio.get_running_loop()
        loop_ready.set()
        await stop.wait()

    thread = threading.Thread(target=lambda: asyncio.run(own_the_client()))
    thread.start()
    assert loop_ready.wait(10)
    client = manager._redis
    assert client is not None
    dropped_on = threading.Event()
    seen: list[int] = []
    original = abandoned._close_connection

    def record_thread(connection: Connection) -> None:
        seen.append(threading.get_ident())
        original(connection)
        dropped_on.set()

    monkeypatch.setattr(abandoned, "_close_connection", record_thread)
    abandon_client(client, owner["loop"])
    assert dropped_on.wait(10)
    owner["loop"].call_soon_threadsafe(stop.set)
    thread.join(10)

    assert seen == [thread.ident]


def test_a_connection_that_never_connected_is_left_alone() -> None:
    manager = _manager()
    asyncio.run(_use(manager))
    client = manager._redis
    assert client is not None
    loop = manager._client_loop
    assert loop is not None
    client.connection_pool._available_connections.append(Connection())

    abandon_client(client, loop)

    assert all(c._writer is None for c in _connections_of(client))


class _CountsItsOwnClose(Connection):
    closed_by_redis_py = 0

    def _close(self) -> None:
        self.closed_by_redis_py += 1


class _WithoutItsOwnClose(Connection):
    """A connection of a redis-py before 5.0.2: it has no ``_close``."""

    def __getattribute__(self, name: str) -> object:
        if name == "_close":
            raise AttributeError(name)
        return super().__getattribute__(name)


def test_redis_pys_own_close_is_the_one_called_where_the_connection_has_it() -> None:
    connection = _CountsItsOwnClose()
    writer = Mock(spec=asyncio.StreamWriter)
    connection._writer = writer

    abandoned._close_connection(connection)

    assert connection.closed_by_redis_py == 1
    writer.close.assert_not_called()
    assert connection._writer is writer
    connection._writer = None


def test_a_connection_lacking_its_own_close_has_its_writer_closed_and_forgotten() -> (
    None
):
    connection = _WithoutItsOwnClose()
    writer = Mock(spec=asyncio.StreamWriter)
    connection._writer = writer
    connection._reader = Mock(spec=asyncio.StreamReader)

    abandoned._close_connection(connection)

    writer.close.assert_called_once_with()
    assert connection._writer is None
    assert connection._reader is None


def test_a_connection_without_its_own_close_or_a_writer_is_left_forgotten() -> None:
    connection = _WithoutItsOwnClose()
    connection._reader = Mock(spec=asyncio.StreamReader)

    abandoned._close_connection(connection)

    assert connection._writer is None
    assert connection._reader is None
