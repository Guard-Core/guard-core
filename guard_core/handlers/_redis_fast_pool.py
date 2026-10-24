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
    """redis-py records connection counts from 7.4.0 on, and only while its OTel
    observability is on. Returns the recorder, the two states, the pool-name
    function and the module that holds the observability singleton, which the
    fast path reads on each call to see observability switched on later."""
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
        providers,
    )


_COUNT_RECORDER = _load_count_recorder()


def _load_release_events() -> tuple[Any, Any] | None:
    """The event the plain release dispatches and the one listener redis-py
    always registers for it (re-authentication, which acts only on a connection
    holding a re-authentication token). ``None`` for a redis-py without them."""
    try:
        events = importlib.import_module("redis.event")
        return (
            events.AsyncAfterConnectionReleasedEvent,
            events.AsyncReAuthConnectionListener,
        )
    except (ImportError, AttributeError):
        return None


_RELEASE_EVENTS = _load_release_events()


def _observability_is_readable() -> bool:
    """Whether the fast path can tell if redis-py's observability is on: the
    singleton module attribute and the provider-manager field it reads exist."""
    if _COUNT_RECORDER is None:
        return True
    providers = _COUNT_RECORDER[3]
    return hasattr(providers, "_observability_instance") and hasattr(
        providers.get_observability_instance(), "_provider_manager"
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
    """

    def __init__(self, *args: Any, timeout: float, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._wait_timeout = timeout
        self._condition = asyncio.Condition()
        self._waiters = 0
        self._connections_with_nothing_unread: set[AbstractConnection] = set()
        self._release_listeners: dict[Any, Any] = {}
        self._release_event = _RELEASE_EVENTS[0] if _RELEASE_EVENTS else None
        self._silent_release_listeners: Any = None

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
        recorder = _COUNT_RECORDER
        if recorder is not None:
            observed = recorder[3]._observability_instance
            if observed is not None and observed._provider_manager is not None:
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

    def _only_the_default_listener(self, connection: AbstractConnection) -> Any:
        """The list of listeners of the release event while it holds nothing but
        redis-py's own re-authentication listener, else ``None``. Registering or
        unregistering a listener replaces the list in the dispatcher's mapping,
        so an identity test against this list tells the fast return that nobody
        else listens. Every redis-py internal the fast return reads (the
        dispatcher's mapping, the connection's re-authentication token, the
        observability singleton and its provider manager) is looked up here, on
        the slow path; one that is missing or of another type gives ``None``,
        and the plain ``release`` does the work."""
        mapping = getattr(
            getattr(self, "_event_dispatcher", None), "_event_listeners_mapping", None
        )
        if (
            _RELEASE_EVENTS is None
            or not isinstance(mapping, dict)
            or not hasattr(connection, "_re_auth_token")
            or not _observability_is_readable()
        ):
            self._release_listeners = {}
            return None
        self._release_listeners = mapping
        listeners = mapping.get(_RELEASE_EVENTS[0])
        if (
            isinstance(listeners, list | tuple)
            and listeners
            and all(isinstance(item, _RELEASE_EVENTS[1]) for item in listeners)
        ):
            return listeners
        return None

    async def give_back(self, connection: AbstractConnection, reply_read: bool) -> None:
        """Release ``connection``. When its reply was fully read, nobody waits for a
        connection, it needs no reconnect, only redis-py's own listener hears the
        release event and the connection holds no re-authentication token, it goes
        back to the idle list without a lock or an event, marked so that the next
        fast take can use it. Every other case is the plain ``release``, which
        dispatches the event to the listeners."""
        silent = self._silent_release_listeners
        if (
            reply_read
            and silent is not None
            and silent is self._release_listeners.get(self._release_event)
            and not self._waiters
            and connection._re_auth_token is None
            and not connection.should_reconnect()
        ):
            self._in_use_connections.remove(connection)
            self._available_connections.append(connection)
            self._connections_with_nothing_unread.add(connection)
            recorder = _COUNT_RECORDER
            if recorder is not None:
                observed = recorder[3]._observability_instance
                if observed is not None and observed._provider_manager is not None:
                    await self._record_counts(
                        recorder, recorder[1].USED, recorder[1].IDLE
                    )
            return
        self._silent_release_listeners = self._only_the_default_listener(connection)
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
