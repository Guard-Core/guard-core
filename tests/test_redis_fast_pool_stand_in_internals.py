"""The fast path's code that reads redis-py internals, driven through stand-ins.

A redis-py before 7.4.0 lacks some of the internals (the release event, the
connection-count recorder, the wait recorder), so the real ones cannot run that
code there. These tests give the pool stand-ins in the shape the fast path
reads, so every line of it runs, and is covered, on every supported redis-py.
"""

import asyncio
from collections.abc import AsyncGenerator
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from redis.asyncio import Redis
from redis.asyncio.connection import Connection

from guard_core.handlers import _redis_fast_pool
from guard_core.handlers._redis_fast_pool import FastPathConnectionPool
from guard_core.handlers._redis_lean import lean_command
from guard_core.handlers.redis_handler import _build_redis_client, close_redis_client
from tests.conftest import REDIS_URL


class _ReleaseEvent:
    pass


class _DefaultListener:
    pass


class _States:
    IDLE = "idle"
    USED = "used"


def _reader(at_eof: bool = False) -> Mock:
    reader = Mock(spec=asyncio.StreamReader)
    reader.at_eof.return_value = at_eof
    return reader


class _Connection(Connection):
    """A real connection object that never connects, in the shape the fast path
    reads on every redis-py (``_re_auth_token`` and ``should_reconnect`` exist
    only on the newer ones, so they are set here)."""

    def __init__(self, reader: Mock | None = None) -> None:
        super().__init__()
        self._re_auth_token = None
        self._reader = reader

    def should_reconnect(self) -> bool:
        return False


def _providers(
    manager: object | None, instance_present: bool = True
) -> SimpleNamespace:
    instance = SimpleNamespace(_provider_manager=manager)
    namespace = SimpleNamespace(get_observability_instance=lambda: instance)
    if instance_present:
        namespace._observability_instance = instance
    return namespace


def _counting(
    monkeypatch: pytest.MonkeyPatch, providers: SimpleNamespace
) -> list[tuple[str, str, int]]:
    samples: list[tuple[str, str, int]] = []

    async def record(*, pool_name: str, connection_state: str, counter: int) -> None:
        samples.append((pool_name, connection_state, counter))

    monkeypatch.setattr(
        _redis_fast_pool,
        "_COUNT_RECORDER",
        (record, _States, lambda pool: "pool", providers),
    )
    return samples


@pytest.fixture
async def pool() -> AsyncGenerator[FastPathConnectionPool, None]:
    client: Redis = _build_redis_client(REDIS_URL, 2, 0.4)
    built = client.connection_pool
    assert isinstance(built, FastPathConnectionPool)
    listeners = [_DefaultListener()]
    built._release_event = _ReleaseEvent
    built._release_listeners = {_ReleaseEvent: listeners}
    built._silent_release_listeners = listeners
    yield built
    await close_redis_client(client)


def _lent(pool: FastPathConnectionPool, reader: Mock | None = None) -> _Connection:
    connection = _Connection(reader)
    pool._in_use_connections.add(connection)
    return connection


def test_the_wait_recorder_is_loaded_from_the_modules_that_hold_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def record(**_kwargs: object) -> None:
        return None

    modules = {
        "redis.asyncio.observability.recorder": SimpleNamespace(
            record_connection_wait_time=record
        ),
        "redis.observability.attributes": SimpleNamespace(get_pool_name=len),
    }
    monkeypatch.setattr(_redis_fast_pool.importlib, "import_module", modules.get)

    assert _redis_fast_pool._load_wait_recorder() == (record, len)


def test_the_release_events_are_loaded_from_the_module_that_holds_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = SimpleNamespace(
        AsyncAfterConnectionReleasedEvent=_ReleaseEvent,
        AsyncReAuthConnectionListener=_DefaultListener,
    )
    monkeypatch.setattr(
        _redis_fast_pool.importlib, "import_module", lambda name: module
    )

    assert _redis_fast_pool._load_release_events() == (
        _ReleaseEvent,
        _DefaultListener,
    )


def test_observability_is_readable_only_with_its_singleton_and_provider_manager(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _counting(monkeypatch, _providers(object()))
    assert _redis_fast_pool._observability_is_readable() is True

    _counting(monkeypatch, _providers(object(), instance_present=False))
    assert _redis_fast_pool._observability_is_readable() is False

    broken = _providers(object())
    broken.get_observability_instance = lambda: SimpleNamespace()
    _counting(monkeypatch, broken)
    assert _redis_fast_pool._observability_is_readable() is False

    monkeypatch.setattr(_redis_fast_pool, "_COUNT_RECORDER", None)
    assert _redis_fast_pool._observability_is_readable() is True


async def test_the_fast_return_and_the_next_take_record_the_counts_the_plain_pool_does(
    pool: FastPathConnectionPool, monkeypatch: pytest.MonkeyPatch
) -> None:
    samples = _counting(monkeypatch, _providers(object()))
    connection = _lent(pool, _reader())

    await pool.give_back(connection, True)

    assert connection in pool._available_connections
    assert connection in pool._connections_with_nothing_unread
    assert samples == [("pool", "used", -1), ("pool", "idle", 1)]
    samples.clear()

    taken = await pool.take_connection_with_nothing_unread()

    assert taken is connection
    assert connection in pool._in_use_connections
    assert connection not in pool._connections_with_nothing_unread
    assert samples == [("pool", "idle", -1), ("pool", "used", 1)]


async def test_no_count_is_recorded_while_observability_has_no_provider_manager(
    pool: FastPathConnectionPool, monkeypatch: pytest.MonkeyPatch
) -> None:
    samples = _counting(monkeypatch, _providers(None))
    connection = _lent(pool, _reader())

    await pool.give_back(connection, True)
    taken = await pool.take_connection_with_nothing_unread()

    assert taken is connection
    assert samples == []


async def test_nothing_is_recorded_without_a_count_recorder(
    pool: FastPathConnectionPool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_redis_fast_pool, "_COUNT_RECORDER", None)
    connection = _lent(pool, _reader())

    await pool.give_back(connection, True)
    taken = await pool.take_connection_with_nothing_unread()

    assert taken is connection


async def test_a_connection_that_may_have_unread_data_is_never_taken_without_the_lock(
    pool: FastPathConnectionPool,
) -> None:
    assert await pool.take_connection_with_nothing_unread() is None

    unmarked = _Connection(_reader())
    pool._available_connections.append(unmarked)
    assert await pool.take_connection_with_nothing_unread() is None
    pool._available_connections.clear()

    for reader in (None, _reader(at_eof=True)):
        connection = _lent(pool, reader)
        await pool.give_back(connection, True)
        assert await pool.take_connection_with_nothing_unread() is None
        pool._available_connections.clear()
        pool._connections_with_nothing_unread.clear()


async def test_a_wait_for_a_connection_is_recorded_with_its_duration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    waits: list[tuple[str, float]] = []

    async def record(*, pool_name: str, duration_seconds: float) -> None:
        waits.append((pool_name, duration_seconds))

    monkeypatch.setattr(
        _redis_fast_pool, "_WAIT_RECORDER", (record, lambda pool: "pool")
    )
    client: Redis = _build_redis_client(REDIS_URL, 1, 2.0)
    try:
        built = client.connection_pool
        held = await built.get_connection()
        waiter = asyncio.ensure_future(built.get_connection())
        await asyncio.sleep(0.05)
        await built.release(held)
        released = await waiter
        await built.release(released)
    finally:
        await close_redis_client(client)

    assert len(waits) == 1
    assert waits[0][0] == "pool"
    assert waits[0][1] > 0


async def test_a_connection_the_pool_hands_out_without_unread_replies_is_used() -> None:
    client: Redis = _build_redis_client(REDIS_URL, 10, 1.0)
    try:
        built = client.connection_pool
        spare = await built.get_connection()
        with patch.object(
            built,
            "take_connection_with_nothing_unread",
            AsyncMock(return_value=spare),
        ):
            assert await lean_command(client, "PING") == "PONG"
    finally:
        await close_redis_client(client)


async def test_the_default_listener_is_found_only_while_nobody_else_listens(
    pool: FastPathConnectionPool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        _redis_fast_pool, "_RELEASE_EVENTS", (_ReleaseEvent, _DefaultListener)
    )
    monkeypatch.setattr(_redis_fast_pool, "_COUNT_RECORDER", None)
    connection = _Connection(_reader())
    default = [_DefaultListener()]

    def listening(mapping: object) -> None:
        monkeypatch.setattr(
            pool,
            "_event_dispatcher",
            SimpleNamespace(_event_listeners_mapping=mapping),
            raising=False,
        )

    listening({_ReleaseEvent: default})
    assert pool._only_the_default_listener(connection) is default
    assert pool._release_listeners == {_ReleaseEvent: default}

    listening({_ReleaseEvent: [_DefaultListener(), object()]})
    assert pool._only_the_default_listener(connection) is None

    listening({_ReleaseEvent: []})
    assert pool._only_the_default_listener(connection) is None

    listening({_ReleaseEvent: "not a list"})
    assert pool._only_the_default_listener(connection) is None

    listening([("not", "a dict")])
    assert pool._only_the_default_listener(connection) is None
    assert pool._release_listeners == {}
