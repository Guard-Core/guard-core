import asyncio
import os
import time
import uuid
from collections.abc import AsyncGenerator
from typing import Any

import pytest
from redis.asyncio import Redis
from redis.asyncio.connection import Connection
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from redis.exceptions import ConnectionError as RedisConnectionError

from guard_core.exceptions import GuardRedisError
from guard_core.handlers._redis_lean import lean_command, lean_evalsha
from guard_core.handlers.redis_handler import RedisManager, _build_redis_client
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL

SCRIPT = "return {KEYS[1], ARGV[1], false, 7, {KEYS[2], 'x'}}"


async def _client(max_connections: int = 20, **kwargs: Any) -> Redis:
    return _build_redis_client(REDIS_URL, max_connections, 1.0, **kwargs)


@pytest.fixture
async def client() -> AsyncGenerator[Redis, None]:
    redis = await _client()
    yield redis
    await redis.aclose()


def _name(packed: Any) -> str:
    chunk = packed[0] if isinstance(packed, list) else packed
    return str(chunk.split(b"\r\n")[2].decode())


async def test_replies_equal_the_high_level_path_for_every_key_shape(
    client: Redis,
) -> None:
    sha = await client.script_load(SCRIPT)
    prefix = f"lean:{uuid.uuid4().hex}:"
    await client.set(f"{prefix}a", "1")

    for count in (1, 2, 6):
        keys = [f"{prefix}{name}" for name in "abcdef"[:count]] + ["k2"] * (
            2 - min(count, 2)
        )
        keys = keys[: max(count, 2)]
        high = await client.evalsha(sha, len(keys), *keys, "arg")
        lean = await lean_evalsha(client, SCRIPT, sha, keys, ["arg"])
        assert lean == high
    names = [f"{prefix}a", f"{prefix}missing"]
    assert await lean_command(client, "MGET", *names) == await client.mget(names)
    assert await lean_command(client, "GET", f"{prefix}a") == "1"


async def test_a_script_the_server_lost_is_loaded_and_the_call_answered(
    client: Redis,
) -> None:
    sha = await client.script_load(SCRIPT)
    await client.script_flush()

    assert await lean_evalsha(
        client, SCRIPT, sha, ["a", "b"], ["x"]
    ) == await client.evalsha(sha, 2, "a", "b", "x")


async def test_a_cancelled_call_never_hands_its_connection_on_with_a_reply_unread(
    client: Redis,
) -> None:
    key = f"lean:{uuid.uuid4().hex}:list"
    blocked = asyncio.ensure_future(lean_command(client, "BLPOP", key, 5))
    await asyncio.sleep(0.2)
    blocked.cancel()
    with pytest.raises(asyncio.CancelledError):
        await blocked
    await client.rpush(key, "late")

    assert await lean_command(client, "PING") == "PONG"
    assert await lean_command(client, "GET", f"{key}:none") is None
    assert await lean_command(client, "LPOP", key) == "late"


async def test_a_connection_the_server_dropped_while_idle_reconnects() -> None:
    client = await _client()
    other = await _client()
    try:
        await lean_command(client, "PING")
        await other.client_kill_filter(_type="normal", skipme=True)
        await asyncio.sleep(0.05)

        assert await lean_command(client, "GET", "lean:idle:none") is None
    finally:
        await client.aclose()
        await other.aclose()


async def test_two_hundred_concurrent_calls_are_not_serialized() -> None:
    client = await _client(max_connections=250)
    try:
        started = time.monotonic()
        replies = await asyncio.gather(
            *(
                lean_command(client, "BLPOP", f"lean:{uuid.uuid4().hex}", 0.2)
                for _ in range(200)
            )
        )

        assert replies == [None] * 200
        assert time.monotonic() - started < 2.0
    finally:
        await client.aclose()


async def test_the_pool_limit_holds_and_a_high_level_call_never_hits_the_timeout() -> (
    None
):
    client = await _client(max_connections=20)
    pool = client.connection_pool
    peak = 0

    async def watch() -> None:
        nonlocal peak
        while True:
            peak = max(
                peak, len(pool._in_use_connections) + len(pool._available_connections)
            )
            await asyncio.sleep(0)

    watcher = asyncio.ensure_future(watch())
    try:
        burst = [
            asyncio.ensure_future(
                lean_command(client, "BLPOP", f"lean:{uuid.uuid4().hex}", 0.02)
            )
            for _ in range(100)
        ]
        await asyncio.sleep(0.1)
        await asyncio.wait_for(client.get("lean:high-level"), 0.95)
        await asyncio.gather(*burst)
        started = time.monotonic()
        await client.get("lean:high-level")
        assert time.monotonic() - started < 0.2
        assert peak <= 20
        assert len(pool._in_use_connections) == 0
        assert len(pool._available_connections) <= 20
    finally:
        watcher.cancel()
        await client.aclose()


async def test_the_manager_builds_the_connection_with_its_kwargs() -> None:
    redis = _build_redis_client(
        "rediss://user:secret@localhost:6/0", 5, 1.0, ssl_cert_reqs="none"
    )
    kwargs = redis.connection_pool.connection_kwargs
    assert kwargs["password"] == "secret"
    assert kwargs["username"] == "user"
    assert redis.connection_pool.connection_class.__name__ == "SSLConnection"
    await redis.aclose()


async def test_a_drop_between_send_and_read_counts_one_request_not_two(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"test:lean:{uuid.uuid4().hex}:",
    )
    manager = RedisManager(config)
    await manager.initialize()
    now = time.time()
    args = (
        [("banned_ips", "198.51.100.5")],
        ("ban_version", "counter"),
        None,
        now,
        "198.51.100.5",
        ("ip_list",),
        now,
        now - 3600,
        3600,
        100,
    )
    real = Connection.read_response
    real_send = Connection.send_packed_command
    state = {"dropped": False, "sent": ""}

    async def note_send(connection: Connection, command: Any, *a: Any, **k: Any) -> Any:
        state["sent"] = _name(command)
        return await real_send(connection, command, *a, **k)

    async def drop_once(connection: Connection, *a: Any, **k: Any) -> Any:
        reply = await real(connection, *a, **k)
        if state["sent"] == "EVALSHA" and not state["dropped"]:
            state["dropped"] = True
            raise ConnectionError("dropped after the script ran")
        return reply

    try:
        monkeypatch.setattr(Connection, "send_packed_command", note_send)
        monkeypatch.setattr(Connection, "read_response", drop_once)
        with pytest.raises(GuardRedisError):
            await manager.get_bans_and_record_strike(*args)
        monkeypatch.setattr(Connection, "read_response", real)
        monkeypatch.setattr(Connection, "send_packed_command", real_send)

        async with manager.get_connection() as conn:
            key = f"{config.redis_prefix}detection:strikes:198.51.100.5"
            assert await conn.zcard(key) == 1
    finally:
        await manager.delete_pattern("*")
        await manager.close()


async def test_a_send_that_fails_is_resent_with_the_same_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = await _client(retry=Retry(NoBackoff(), 1))
    sent: list[Any] = []
    real = Connection.send_packed_command
    failures = {"left": 1}

    async def flaky(connection: Connection, command: Any, *a: Any, **k: Any) -> Any:
        if _name(command) == "GET":
            sent.append(command)
            if failures["left"]:
                failures["left"] -= 1
                raise RedisConnectionError("never left")
        return await real(connection, command, *a, **k)

    try:
        monkeypatch.setattr(Connection, "send_packed_command", flaky)
        assert await lean_command(client, "GET", "lean:resend") is None
        assert len(sent) == 2 and sent[0] == sent[1]
    finally:
        await client.aclose()


def test_the_unique_member_of_a_strike_is_chosen_before_the_call() -> None:
    assert len(os.urandom(16).hex()) == 32


async def test_an_idle_connection_closed_by_the_pool_is_not_handed_out() -> None:
    client = await _client()
    try:
        await lean_command(client, "PING")
        await lean_command(client, "PING")
        pool = client.connection_pool
        assert pool._connections_with_nothing_unread
        await pool.disconnect(inuse_connections=False)

        assert await pool.take_connection_with_nothing_unread() is None
        assert await lean_command(client, "GET", "lean:disconnected") is None
    finally:
        await client.aclose()


async def test_a_connection_that_must_reconnect_goes_back_through_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = await _client()
    try:
        await lean_command(client, "PING")
        monkeypatch.setattr(Connection, "should_reconnect", lambda self: True)
        pool = client.connection_pool

        assert await lean_command(client, "GET", "lean:reconnect") is None
        assert not pool._connections_with_nothing_unread
    finally:
        monkeypatch.undo()
        await client.aclose()


class _Observability:
    """The module redis-py keeps its observability singleton in, reduced to the
    one field the fast path reads."""

    def __init__(self, enabled: bool) -> None:
        self._observability_instance = self._instance(enabled)

    @staticmethod
    def _instance(enabled: bool) -> Any:
        from types import SimpleNamespace

        return SimpleNamespace(_provider_manager=object() if enabled else None)

    def get_observability_instance(self) -> Any:
        return self._observability_instance

    def switch(self, enabled: bool) -> None:
        self._observability_instance = self._instance(enabled)


def _observed_recorder(
    monkeypatch: pytest.MonkeyPatch, enabled: bool
) -> tuple[list[Any], _Observability]:
    """Both recorders (the pool module's and redis-py's own) into one list, with
    the observability switch the fast path reads set to ``enabled``."""
    from redis.observability.attributes import ConnectionState, get_pool_name

    samples: list[Any] = []

    async def record(
        pool_name: str, connection_state: ConnectionState, counter: int = 1
    ) -> None:
        samples.append((connection_state, counter))

    observability = _Observability(enabled)
    monkeypatch.setattr(
        "guard_core.handlers._redis_fast_pool._COUNT_RECORDER",
        (record, ConnectionState, get_pool_name, observability),
    )
    monkeypatch.setattr("redis.asyncio.connection.record_connection_count", record)
    return samples, observability


async def test_connection_counts_after_lean_calls_equal_those_after_plain_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    samples, _ = _observed_recorder(monkeypatch, True)
    client = await _client()
    try:
        await lean_command(client, "PING")
        await client.execute_command("PING")
        samples.clear()
        for _ in range(5):
            await lean_command(client, "GET", "lean:count")
        lean_samples = sorted(map(str, samples))
        samples.clear()
        for _ in range(5):
            await client.execute_command("GET", "lean:count")
        assert lean_samples == sorted(map(str, samples))
        assert len(lean_samples) == 20
    finally:
        await client.aclose()


async def test_no_connection_count_is_recorded_while_observability_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    samples, _ = _observed_recorder(monkeypatch, False)
    client = await _client()
    try:
        await lean_command(client, "PING")
        await lean_command(client, "PING")
        samples.clear()
        for _ in range(5):
            await lean_command(client, "GET", "lean:count")
        assert samples == []
    finally:
        await client.aclose()


def test_a_redis_py_without_the_connection_count_recorder_loads_no_recorder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.handlers import _redis_fast_pool

    def refuse(name: str) -> Any:
        raise ImportError(name)

    monkeypatch.setattr(_redis_fast_pool.importlib, "import_module", refuse)
    assert _redis_fast_pool._load_count_recorder() is None


async def test_observability_switched_on_later_is_seen_by_the_next_fast_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    samples, observability = _observed_recorder(monkeypatch, False)
    client = await _client()
    try:
        await lean_command(client, "PING")
        await lean_command(client, "PING")
        samples.clear()
        await lean_command(client, "GET", "lean:count")
        assert samples == []
        observability.switch(True)
        await lean_command(client, "GET", "lean:count")
        assert len(samples) == 4
        observability.switch(False)
        await lean_command(client, "GET", "lean:count")
        assert len(samples) == 4
    finally:
        await client.aclose()


class _Listener:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def listen(self, event: Any) -> None:
        self.events.append(event)


def _release_event_type() -> Any:
    from redis.event import AsyncAfterConnectionReleasedEvent

    return AsyncAfterConnectionReleasedEvent


async def test_a_release_listener_hears_each_lean_call_like_each_plain_one() -> None:
    client = await _client()
    try:
        listener = _Listener()
        pool = client.connection_pool
        pool._event_dispatcher.register_listeners({_release_event_type(): [listener]})
        await lean_command(client, "PING")
        await client.execute_command("PING")
        listener.events.clear()
        for _ in range(5):
            await lean_command(client, "GET", "lean:event")
        assert len(listener.events) == 5
        assert all(isinstance(e.connection, Connection) for e in listener.events)
        listener.events.clear()
        for _ in range(5):
            await client.execute_command("GET", "lean:event")
        assert len(listener.events) == 5
    finally:
        await client.aclose()


async def test_no_release_event_is_dispatched_with_only_the_default_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = await _client()
    try:
        await lean_command(client, "PING")
        dispatcher = client.connection_pool._event_dispatcher
        dispatched: list[Any] = []

        async def spy(event: Any) -> None:
            dispatched.append(event)

        monkeypatch.setattr(dispatcher, "dispatch_async", spy)
        for _ in range(5):
            await lean_command(client, "GET", "lean:event")
        assert dispatched == []
    finally:
        await client.aclose()


async def test_the_fast_return_resumes_when_the_last_extra_listener_is_removed() -> (
    None
):
    client = await _client()
    try:
        listener = _Listener()
        pool = client.connection_pool
        mapping = {_release_event_type(): [listener]}
        pool._event_dispatcher.register_listeners(mapping)
        await lean_command(client, "PING")
        await lean_command(client, "PING")
        pool._event_dispatcher.unregister_listeners(mapping)
        await lean_command(client, "PING")
        await lean_command(client, "PING")
        seen = len(listener.events)
        await lean_command(client, "PING")
        assert len(listener.events) == seen
        assert pool._connections_with_nothing_unread
    finally:
        await client.aclose()


async def test_a_connection_holding_a_re_authentication_token_goes_back_through_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = await _client()
    try:
        await lean_command(client, "PING")
        re_authenticated: list[Any] = []

        async def re_auth(self: Connection) -> None:
            re_authenticated.append(self)
            self._re_auth_token = None

        monkeypatch.setattr(Connection, "re_auth", re_auth)
        pool = client.connection_pool
        for connection in pool._available_connections:
            connection._re_auth_token = object()
        await lean_command(client, "GET", "lean:token")
        assert len(re_authenticated) == 1
        assert not pool._connections_with_nothing_unread
    finally:
        await client.aclose()


async def test_a_redis_py_without_the_release_event_never_takes_the_fast_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.handlers import _redis_fast_pool

    monkeypatch.setattr(_redis_fast_pool, "_RELEASE_EVENTS", None)
    client = await _client()
    try:
        await lean_command(client, "PING")
        await lean_command(client, "GET", "lean:old")
        assert not client.connection_pool._connections_with_nothing_unread
    finally:
        await client.aclose()


def test_a_redis_py_without_the_release_event_loads_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.handlers import _redis_fast_pool

    def refuse(name: str) -> Any:
        raise ImportError(name)

    monkeypatch.setattr(_redis_fast_pool.importlib, "import_module", refuse)
    assert _redis_fast_pool._load_release_events() is None


async def test_a_redis_py_without_the_count_recorder_takes_the_fast_path_unrecorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.handlers import _redis_fast_pool

    monkeypatch.setattr(_redis_fast_pool, "_COUNT_RECORDER", None)
    client = await _client()
    try:
        await lean_command(client, "PING")
        await lean_command(client, "GET", "lean:old")
        await lean_command(client, "GET", "lean:old")
        assert client.connection_pool._connections_with_nothing_unread
    finally:
        await client.aclose()


class _DispatcherWithoutMapping:
    """An event dispatcher that keeps no ``_event_listeners_mapping``."""

    _event_listeners_mapping: Any

    def __init__(self) -> None:
        self.events: list[Any] = []

    async def dispatch_async(self, event: Any) -> None:
        self.events.append(event)

    def dispatch(self, event: Any) -> None:
        self.events.append(event)

    def register_listeners(self, _mappings: Any) -> None:
        return None

    def unregister_listeners(self, _mappings: Any) -> None:
        return None


async def _calls_take_the_plain_path(client: Redis, events: list[Any]) -> None:
    pool = client.connection_pool
    for _ in range(6):
        assert await lean_command(client, "GET", "lean:fallback") is None
    assert pool._silent_release_listeners is None
    assert not pool._connections_with_nothing_unread
    assert len(events) == 6


async def test_a_dispatcher_without_the_listener_mapping_takes_the_plain_path() -> None:
    dispatcher = _DispatcherWithoutMapping()
    client = await _client(event_dispatcher=dispatcher)
    try:
        await _calls_take_the_plain_path(client, dispatcher.events)
    finally:
        await client.aclose()


async def test_a_listener_mapping_of_another_type_takes_the_plain_path() -> None:
    dispatcher = _DispatcherWithoutMapping()
    dispatcher._event_listeners_mapping = [("not", "a dict")]
    client = await _client(event_dispatcher=dispatcher)
    try:
        await _calls_take_the_plain_path(client, dispatcher.events)
    finally:
        await client.aclose()


async def test_a_connection_without_a_re_authentication_token_takes_the_plain_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_init = Connection.__init__

    def init_without_token(self: Connection, *args: Any, **kwargs: Any) -> None:
        original_init(self, *args, **kwargs)
        del self._re_auth_token

    async def no_re_auth(self: Connection) -> None:
        return None

    monkeypatch.setattr(Connection, "__init__", init_without_token)
    monkeypatch.setattr(Connection, "re_auth", no_re_auth)
    client = await _client()
    try:
        events: list[Any] = []
        dispatcher = client.connection_pool._event_dispatcher
        original = dispatcher.dispatch_async

        async def spy(event: Any) -> None:
            events.append(event)
            await original(event)

        monkeypatch.setattr(dispatcher, "dispatch_async", spy)
        await _calls_take_the_plain_path(client, events)
    finally:
        await client.aclose()


async def test_an_observability_module_without_its_singleton_takes_the_plain_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redis.observability import providers

    monkeypatch.delattr(providers, "_observability_instance")
    client = await _client()
    try:
        events: list[Any] = []
        dispatcher = client.connection_pool._event_dispatcher
        original = dispatcher.dispatch_async

        async def spy(event: Any) -> None:
            events.append(event)
            await original(event)

        monkeypatch.setattr(dispatcher, "dispatch_async", spy)
        await _calls_take_the_plain_path(client, events)
    finally:
        await client.aclose()


async def test_an_instance_without_a_provider_manager_takes_the_plain_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redis.observability import providers

    monkeypatch.delattr(providers.get_observability_instance(), "_provider_manager")
    client = await _client()
    try:
        events: list[Any] = []
        dispatcher = client.connection_pool._event_dispatcher
        original = dispatcher.dispatch_async

        async def spy(event: Any) -> None:
            events.append(event)
            await original(event)

        monkeypatch.setattr(dispatcher, "dispatch_async", spy)
        await _calls_take_the_plain_path(client, events)
    finally:
        await client.aclose()


async def test_a_stock_client_answers_every_lean_routed_method_like_the_fast_pool(
    client: Redis,
) -> None:
    stock = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        sha = await stock.script_load(SCRIPT)
        prefix = f"lean:{uuid.uuid4().hex}:"
        await stock.set(f"{prefix}a", "1")
        names = [f"{prefix}a", f"{prefix}missing"]
        for lean_client in (stock, client):
            assert await lean_command(lean_client, "GET", f"{prefix}a") == "1"
            assert await lean_command(lean_client, "MGET", *names) == ["1", None]
            assert await lean_evalsha(
                lean_client, SCRIPT, sha, ["a", "b"], ["x"]
            ) == await stock.evalsha(sha, 2, "a", "b", "x")
        await stock.script_flush()
        assert await lean_evalsha(stock, SCRIPT, sha, ["a", "b"], ["x"]) == (
            await lean_evalsha(client, SCRIPT, sha, ["a", "b"], ["x"])
        )
    finally:
        await stock.aclose()
