import importlib
import inspect
import threading
import time
from collections.abc import Callable
from typing import Protocol

from redis import ConnectionPool
from redis.connection import Connection
from redis.exceptions import ConnectionError as RedisConnectionError

_EXHAUSTED_MESSAGE = "Too many connections"
_TIMEOUT_MESSAGE = "No connection available."


class _RecordWait(Protocol):
    def __call__(self, *, pool_name: str, duration_seconds: float) -> None: ...


_WaitRecorder = tuple[_RecordWait, Callable[[ConnectionPool], str]]


def _load_wait_recorder() -> _WaitRecorder | None:
    """redis-py records pool wait samples from 7.3.0 on; older releases have no
    recorder and the pool then waits without reporting it."""
    try:
        recorder = importlib.import_module("redis.observability.recorder")
        attributes = importlib.import_module("redis.observability.attributes")
    except ImportError:
        return None
    return recorder.record_connection_wait_time, attributes.get_pool_name


_WAIT_RECORDER = _load_wait_recorder()


def _command_name_is_required() -> bool:
    """redis-py before 5.3.0 declares ``get_connection(self, command_name, ...)``
    with the name required, and from 5.3.0 on optional."""
    parameter = inspect.signature(ConnectionPool.get_connection).parameters[
        "command_name"
    ]
    return parameter.default is inspect.Parameter.empty


_PLAIN_GET_CONNECTION_ARGS: tuple[str, ...] = (
    ("",) if _command_name_is_required() else ()
)


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

    Hand-written twin of ``guard_core.handlers._redis_fast_pool``: the waiter
    count and the predicate check run under the Condition's lock. redis-py calls
    ``reset`` in a forked child, which gives the child its own Condition and a
    zero waiter count: the parent's lock may be held by a thread the child lacks.
    """

    def __init__(
        self,
        connection_class: type[Connection] = Connection,
        max_connections: int | None = None,
        *,
        timeout: float,
        **connection_kwargs: object,
    ) -> None:
        super().__init__(connection_class, max_connections, **connection_kwargs)
        self._wait_timeout = timeout

    def reset(self) -> None:
        super().reset()
        self._condition = threading.Condition()
        self._waiters = 0

    def _has_free_connection(self) -> bool:
        return bool(
            self._available_connections
            or self._created_connections < self.max_connections
        )

    def _plain_get_connection(self) -> Connection:
        """The plain pool's checkout, with the command name only the redis-py
        releases that require it get (the plain pool never reads it)."""
        return super().get_connection(*_PLAIN_GET_CONNECTION_ARGS)

    def get_connection(self, *_args: object, **_kwargs: object) -> Connection:
        try:
            return self._plain_get_connection()
        except RedisConnectionError as error:
            if not _is_exhaustion(error):
                raise
        return self._wait_for_connection()

    def _wait_for_connection(self) -> Connection:
        started = time.monotonic()
        deadline = started + self._wait_timeout
        free = self._wait_until_a_connection_is_free(deadline, register=True)
        try:
            while True:
                if not free:
                    raise RedisConnectionError(_TIMEOUT_MESSAGE)
                try:
                    connection = self._plain_get_connection()
                except RedisConnectionError as error:
                    if not _is_exhaustion(error):
                        raise
                    free = self._wait_until_a_connection_is_free(deadline)
                    continue
                break
        finally:
            with self._condition:
                self._waiters -= 1
        if _WAIT_RECORDER is not None:
            record, pool_name_of = _WAIT_RECORDER
            record(
                pool_name=pool_name_of(self),
                duration_seconds=time.monotonic() - started,
            )
        return connection

    def _wait_until_a_connection_is_free(
        self, deadline: float, *, register: bool = False
    ) -> bool:
        with self._condition:
            if register:
                self._waiters += 1
            return self._condition.wait_for(
                self._has_free_connection, max(deadline - time.monotonic(), 0.0)
            )

    def take_connection_with_nothing_unread(self) -> Connection | None:
        """The async pool takes an idle connection without a lock; here a thread
        pool takes the plain ``get_connection``, so this twin never hands one out."""
        return None

    def give_back(self, connection: Connection, reply_read: bool) -> None:
        """The plain ``release``: the async pool's lock-free return needs the
        absence of an await between its pop and add, which threads do not have."""
        self.release(connection)

    def release(self, connection: Connection) -> None:
        super().release(connection)
        if self._waiters:
            with self._condition:
                self._condition.notify()
