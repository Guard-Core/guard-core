import asyncio
import importlib
import time
from typing import Any

from redis.asyncio import ConnectionPool
from redis.asyncio.connection import AbstractConnection
from redis.exceptions import ConnectionError as RedisConnectionError

_EXHAUSTED_MESSAGE = "Too many connections"
_TIMEOUT_MESSAGE = "No connection available."


def _load_wait_recorder() -> tuple[Any, Any] | None:
    """redis-py records pool wait samples from 7.3.0 on; older releases have no
    recorder and the pool then waits without reporting it."""
    try:
        recorder = importlib.import_module("redis.asyncio.observability.recorder")
        attributes = importlib.import_module("redis.observability.attributes")
    except ImportError:
        return None
    return recorder.record_connection_wait_time, attributes.get_pool_name


_WAIT_RECORDER = _load_wait_recorder()


def _load_count_recorder() -> tuple[Any, Any, Any, Any] | None:
    """redis-py records connection counts from 7.4.0 on, and only when its OTel
    observability is on. Returns the recorder, the two states, the pool-name
    function and the observability singleton getter."""
    try:
        recorder = importlib.import_module("redis.asyncio.observability.recorder")
        attributes = importlib.import_module("redis.observability.attributes")
        providers = importlib.import_module("redis.observability.providers")
    except ImportError:
        return None
    return (
        recorder.record_connection_count,
        attributes.ConnectionState,
        attributes.get_pool_name,
        providers.get_observability_instance,
    )


_COUNT_RECORDER = _load_count_recorder()


def _count_recorder_when_observed() -> tuple[Any, Any, Any, Any] | None:
    """The count recorder while redis-py's observability is on, else None, so a
    pool with observability off pays one attribute test per fast call."""
    if _COUNT_RECORDER is not None and _COUNT_RECORDER[3]().is_enabled():
        return _COUNT_RECORDER
    return None


def _is_exhaustion(error: RedisConnectionError) -> bool:
    return str(error) == _EXHAUSTED_MESSAGE


class FastPathConnectionPool(ConnectionPool):
    """The plain pool with a bounded wait only when it is exhausted.

    A free connection is taken exactly as the plain pool takes it. Only an
    exhausted pool waits, on its own Condition, until one deadline computed once
    per acquire, then raises the same ``ConnectionError`` the blocking pool
    raises. The wait is not FIFO: a newcomer may take a connection ahead of a
    waiter, which then waits again until the deadline. The fast path records no
    wait sample, only a wait does.
    """

    def __init__(self, *args: Any, timeout: float, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._wait_timeout = timeout
        self._condition = asyncio.Condition()
        self._waiters = 0
        self._connections_with_nothing_unread: set[AbstractConnection] = set()
        self._count_recorder = _count_recorder_when_observed()

    def _has_free_connection(self) -> bool:
        return bool(
            self._available_connections
            or len(self._in_use_connections) < self.max_connections
        )

    async def get_connection(self, *_args: Any, **_kwargs: Any) -> AbstractConnection:
        try:
            connection = await super().get_connection()
        except RedisConnectionError as error:
            if not _is_exhaustion(error):
                raise
            connection = await self._wait_for_connection()
        self._count_recorder = _count_recorder_when_observed()
        self._connections_with_nothing_unread.discard(connection)
        reader = connection._reader
        if reader is not None and reader.at_eof():
            await connection.disconnect()
        return connection

    async def take_connection_with_nothing_unread(self) -> AbstractConnection | None:
        """The newest idle connection that ``give_back`` left with its reply fully
        read, moved to the in-use set without a lock: the pop and the add have no
        await between them, so no other task runs in between. ``None`` when the
        newest idle connection is not one of those; the caller then takes the
        plain ``get_connection``, which also reconnects a connection the server closed
        while it was idle (its reader has seen the end of the stream)."""
        available = self._available_connections
        if not available or available[-1] not in self._connections_with_nothing_unread:
            return None
        reader = available[-1]._reader
        if reader is None or reader.at_eof():
            return None
        connection = available.pop()
        self._connections_with_nothing_unread.remove(connection)
        self._in_use_connections.add(connection)
        recorder = self._count_recorder
        if recorder is not None:
            await self._record_counts(recorder, recorder[1].IDLE, recorder[1].USED)
        return connection

    async def _record_counts(
        self, recorder: tuple[Any, Any, Any, Any], leaving: Any, entering: Any
    ) -> None:
        """The two connection-count samples the plain pool records for one state
        transition (checkout: IDLE to USED, return: USED to IDLE), through the
        same recorder."""
        record = recorder[0]
        pool_name = recorder[2](self)
        await record(pool_name=pool_name, connection_state=leaving, counter=-1)
        await record(pool_name=pool_name, connection_state=entering, counter=1)

    async def give_back(self, connection: AbstractConnection, reply_read: bool) -> None:
        """Release ``connection``. When its reply was fully read, nobody waits for a
        connection and it needs no reconnect, it goes back to the idle list without
        a lock or an event, marked so that the next fast take can use it; every
        other case is the plain ``release``."""
        if reply_read and not self._waiters and not connection.should_reconnect():
            self._in_use_connections.remove(connection)
            self._available_connections.append(connection)
            self._connections_with_nothing_unread.add(connection)
            recorder = self._count_recorder
            if recorder is not None:
                await self._record_counts(recorder, recorder[1].USED, recorder[1].IDLE)
            return
        await self.release(connection)

    async def _wait_for_connection(self) -> AbstractConnection:
        started = time.monotonic()
        deadline = started + self._wait_timeout
        self._waiters += 1
        try:
            while True:
                await self._wait_until_a_connection_is_free(deadline)
                try:
                    connection = await super().get_connection()
                except RedisConnectionError as error:
                    if not _is_exhaustion(error):
                        raise
                    continue
                break
        finally:
            self._waiters -= 1
        if _WAIT_RECORDER is not None:
            record, pool_name_of = _WAIT_RECORDER
            await record(
                pool_name=pool_name_of(self),
                duration_seconds=time.monotonic() - started,
            )
        return connection

    async def _wait_until_a_connection_is_free(self, deadline: float) -> None:
        remaining = max(deadline - time.monotonic(), 0.0)
        try:
            await asyncio.wait_for(self._wait_on_the_condition(), remaining)
        except asyncio.TimeoutError as error:
            raise RedisConnectionError(_TIMEOUT_MESSAGE) from error

    async def _wait_on_the_condition(self) -> None:
        async with self._condition:
            await self._condition.wait_for(self._has_free_connection)

    async def release(self, connection: AbstractConnection) -> None:
        await super().release(connection)
        if self._waiters:
            async with self._condition:
                self._condition.notify()
