import asyncio

from redis import ConnectionPool, Redis

from guard_core._redis_abandoned_client import close_sync_client
from tests.conftest import REDIS_URL


def _is_open(connection: object) -> bool:
    return getattr(connection, "_sock", None) is not None


def _connected(client: Redis) -> object:
    client.ping()
    connection = client.connection_pool._available_connections[0]
    assert _is_open(connection)
    return connection


def _close_through_the_sync_tree(client: Redis) -> None:
    loop = asyncio.new_event_loop()
    try:
        close_sync_client(client, loop)
    finally:
        loop.close()


def test_a_sync_client_that_owns_its_pool_drops_the_pool_with_itself() -> None:
    client = Redis.from_url(REDIS_URL)
    connection = _connected(client)

    _close_through_the_sync_tree(client)

    assert not _is_open(connection)


def test_a_sync_client_over_a_pool_it_does_not_own_leaves_the_pool_open() -> None:
    pool = ConnectionPool.from_url(REDIS_URL)
    client = Redis(connection_pool=pool)
    client.auto_close_connection_pool = False
    connection = _connected(client)

    _close_through_the_sync_tree(client)

    assert _is_open(connection)
    pool.disconnect()
