import logging
import os
import subprocess
import sys
import textwrap
import time
from collections.abc import AsyncIterator
from functools import partial
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from redis.asyncio import Redis
from redis.asyncio.retry import Retry

from guard_core._redis_exceptions import (
    NoScriptError,
    RedisConnectionError,
    RedisTimeoutError,
)
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.redis_handler import (
    _EXTEND_ONLY_BAN_WRITE_SHA,
    _FORGET_DETECTION_STRIKES_SHA,
    _PURGE_OWNED_BAN_SHA,
    _READ_DETECTION_CATEGORIES_SHA,
    _RECORD_DETECTION_STRIKES_SHA,
    _SLIDING_WINDOW_SHA,
    _SUM_INDEXED_WINDOW_HITS_SHA,
    RedisHandlerBase,
    RedisManager,
    _redact_redis_url,
    _unparseable_redis_url,
    scan_unlink,
    scan_unlink_through_new_client,
)
from guard_core.handlers.redis_handler import redis_handler as redis_handler_alias
from guard_core.models import SecurityConfig
from guard_core.scripts.ban_write_lua import (
    EXTEND_ONLY_BAN_WRITE_SCRIPT,
    PURGE_OWNED_BAN_SCRIPT,
)
from guard_core.scripts.detection_strikes_lua import (
    FORGET_DETECTION_STRIKES_SCRIPT,
    READ_DETECTION_CATEGORIES_SCRIPT,
    RECORD_DETECTION_STRIKES_SCRIPT,
)
from guard_core.scripts.rule_hit_index_lua import SUM_INDEXED_WINDOW_HITS_SCRIPT
from guard_core.scripts.sliding_window_lua import SLIDING_WINDOW_HIT_SCRIPT
from tests.conftest import suite_redis_prefix

_SHA1_CALLS_PROBE = textwrap.dedent(
    """
    import hashlib

    real = hashlib.sha1
    calls = []

    def spy(data=b"", *args, **kwargs):
        calls.append(kwargs)
        return real(data, *args, **kwargs)

    hashlib.sha1 = spy
    import guard_core.handlers.redis_handler

    print(len(calls), all(c == {"usedforsecurity": False} for c in calls))
    """
)


async def test_a_redis_event_names_the_redis_handler_as_its_source() -> None:
    manager = RedisManager(SecurityConfig(enable_redis=True, redis_url="redis://x"))
    agent = AsyncMock()
    manager.agent_handler = agent

    await manager._send_redis_event("redis_connection", "established", "ok", a=1)

    event = agent.send_event.call_args[0][0]
    assert event.handler_name == "redis"
    assert event.metadata == {"a": 1}


def test_every_script_digest_is_declared_not_for_security() -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-c", _SHA1_CALLS_PROBE],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )

    assert result.stdout.split() == ["9", "True"]


async def test_a_redis_event_carries_the_action_and_the_system_address() -> None:
    manager = RedisManager(SecurityConfig(enable_redis=True, redis_url="redis://x"))
    agent = AsyncMock()
    manager.agent_handler = agent

    await manager._send_redis_event("redis_connection", "established", "why")

    event = agent.send_event.call_args[0][0]
    assert event.event_type == "redis_connection"
    assert event.ip_address == "system"
    assert event.action_taken == "established"
    assert event.reason == "why"
    assert event.metadata == {}


async def test_a_redis_event_failure_is_logged_with_its_cause(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = RedisManager(SecurityConfig(enable_redis=True, redis_url="redis://x"))
    manager.agent_handler = AsyncMock(send_event=AsyncMock(side_effect=OSError("boom")))

    with caplog.at_level(logging.ERROR, logger="guard_core.handlers.redis"):
        await manager._send_redis_event("t", "a", "r")

    assert "Failed to send Redis event to agent: boom" in [
        r.getMessage() for r in caplog.records
    ]


class _ScanConnection:
    def __init__(self, keys: list[str]) -> None:
        self.keys = keys
        self.scan_counts: list[int] = []
        self.scanned: list[str] = []
        self.unlinked: list[tuple[str, ...]] = []

    async def scan_iter(self, match: str, count: int) -> AsyncIterator[str]:
        self.scan_counts.append(count)
        for key in self.keys:
            self.scanned.append(key)
            yield key

    async def unlink(self, *keys: str) -> int:
        self.unlinked.append(keys)
        return len(keys)


async def test_scan_unlink_scans_and_unlinks_in_batches_of_500() -> None:
    connection = _ScanConnection([f"k{i}" for i in range(1001)])

    removed = await scan_unlink(Mock(wraps=connection), "k*")

    assert removed == 1001
    assert connection.scan_counts == [500]
    assert len(connection.scanned) == 1001
    assert [len(batch) for batch in connection.unlinked] == [500, 500, 1]


async def test_keys_scans_with_a_count_of_500() -> None:
    handler = RedisHandlerBase(
        SecurityConfig(enable_redis=True, redis_url="redis://x", redis_prefix="p:")
    )
    connection = _ScanConnection(["p:a", "p:b", "p:a"])
    handler._redis = Mock(wraps=connection)

    assert await handler.keys("*") == ["p:a", "p:b"]
    assert connection.scan_counts == [500]


async def _built_with(
    monkeypatch: pytest.MonkeyPatch, redis_max_connections: int | None = None
) -> tuple[object, ...]:
    calls: list[tuple[object, ...]] = []

    def build(*args: object, **kwargs: object) -> Mock:
        calls.append(args)
        return Mock(ping=AsyncMock(), aclose=AsyncMock())

    monkeypatch.setattr("guard_core.handlers.redis_handler._build_redis_client", build)
    config = SecurityConfig(
        enable_redis=True,
        redis_url="redis://x",
        redis_max_connections=redis_max_connections,
    )
    await RedisHandlerBase(config).initialize()
    return calls[0]


async def test_the_pool_defaults_to_100_connections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = await _built_with(monkeypatch)

    assert args[1] == 100


async def test_a_configured_pool_size_is_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = await _built_with(monkeypatch, redis_max_connections=7)

    assert args[1] == 7


def test_connection_kwargs_come_from_the_given_config_not_the_managers() -> None:
    manager = RedisHandlerBase(
        SecurityConfig(enable_redis=True, redis_url="redis://x", redis_socket_timeout=1)
    )
    other = SecurityConfig(
        enable_redis=True, redis_url="redis://x", redis_socket_timeout=9
    )

    assert manager._connection_kwargs(other)["socket_timeout"] == 9
    assert manager._connection_kwargs()["socket_timeout"] == 1


def test_a_fresh_redis_manager_is_open_and_has_no_agent_client_or_odd_logger() -> None:
    original = RedisManager._instance
    RedisManager._instance = None
    try:
        manager = RedisManager(SecurityConfig(enable_redis=True, redis_url="redis://x"))

        assert RedisManager._redis is None
        assert RedisManager._closed is False
        assert manager._closed is False
        assert manager.agent_handler is None
        assert manager.logger.name == "guard_core.handlers.redis"
    finally:
        RedisManager._instance = original


async def test_initialize_agent_stores_the_agent_handler() -> None:
    handler = RedisHandlerBase(SecurityConfig(enable_redis=True, redis_url="redis://x"))
    agent = AsyncMock()

    await handler.initialize_agent(agent)

    assert handler.agent_handler is agent


def test_a_custom_handler_starts_without_an_agent() -> None:
    handler = RedisHandlerBase(SecurityConfig(enable_redis=True, redis_url="redis://x"))

    assert handler.agent_handler is None


def _handler(prefix: str = "p:") -> RedisHandlerBase:
    handler = RedisHandlerBase(
        SecurityConfig(enable_redis=True, redis_url="redis://x", redis_prefix=prefix)
    )
    handler.agent_handler = AsyncMock()
    return handler


def _client_of(handler: RedisHandlerBase) -> object:
    return handler._redis


def _events(handler: RedisHandlerBase) -> list[MagicMock]:
    agent = handler.agent_handler
    assert isinstance(agent, AsyncMock)
    sent: list[MagicMock] = [call.args[0] for call in agent.send_event.call_args_list]
    return sent


def _messages(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [record.getMessage() for record in caplog.records]


def _build_returning(monkeypatch: pytest.MonkeyPatch, client: Mock) -> None:
    monkeypatch.setattr(
        "guard_core.handlers.redis_handler._build_redis_client",
        lambda *args, **kwargs: client,
    )


def test_unparseable_url_text_keeps_the_scheme_only_when_the_url_has_one() -> None:
    assert _unparseable_redis_url("redis://[bad") == "redis://<unparseable>"
    assert _unparseable_redis_url("nonsense") == "<unparseable>"
    assert _unparseable_redis_url("nonsense", "redis") == "<unparseable>"
    assert _unparseable_redis_url("://x") == "<unparseable>"
    assert _unparseable_redis_url("a://b", "rediss") == "rediss://<unparseable>"


def test_a_url_without_a_hostname_keeps_its_port_and_drops_nothing_else() -> None:
    assert _redact_redis_url("redis://:6379/0") == "redis://:6379/0"
    assert _redact_redis_url("redis://user:secret@host:6380/2?x=1#f") == (
        "redis://host:6380/2?x=1#f"
    )
    assert _redact_redis_url("redis://[::1]:6379") == "redis://[::1]:6379"
    assert _redact_redis_url("redis://host") == "redis://host"


async def test_a_successful_connect_is_logged_and_reported(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    handler = _handler()
    client = Mock(ping=AsyncMock(), aclose=AsyncMock())
    _build_returning(monkeypatch, client)

    with caplog.at_level(logging.INFO, logger="guard_core.handlers.redis"):
        await handler.initialize()

    assert handler._redis is client
    assert handler._closed is False
    assert "Redis connection established" in _messages(caplog)
    (event,) = _events(handler)
    assert event.event_type == "redis_connection"
    assert event.action_taken == "connection_established"
    assert event.reason == "Redis connection successfully established"
    assert event.metadata == {"redis_url": "redis://x"}


async def test_initialize_reopens_a_closed_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = _handler()
    handler._closed = True
    _build_returning(monkeypatch, Mock(ping=AsyncMock(), aclose=AsyncMock()))

    await handler.initialize()

    assert handler._closed is False


async def test_a_failed_connect_is_logged_reported_and_closed(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    handler = _handler()
    client = Mock(ping=AsyncMock(side_effect=RuntimeError("nope")), aclose=AsyncMock())
    _build_returning(monkeypatch, client)

    with caplog.at_level(logging.ERROR, logger="guard_core.handlers.redis"):
        with pytest.raises(GuardRedisError) as raised:
            await handler.initialize()

    assert raised.value.status_code == 503
    assert raised.value.detail == "Redis connection failed"
    assert "Redis connection failed: nope" in _messages(caplog)
    assert handler._redis is None
    client.aclose.assert_awaited_once()
    (event,) = _events(handler)
    assert event.event_type == "redis_error"
    assert event.action_taken == "connection_failed"
    assert event.reason == "Redis connection failed: nope"
    assert event.metadata == {
        "redis_url": "redis://x",
        "error_type": "connection_error",
    }


async def test_a_build_failure_closes_nothing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    handler = _handler()

    def refuse(*args: object, **kwargs: object) -> Mock:
        raise RuntimeError("no pool")

    monkeypatch.setattr("guard_core.handlers.redis_handler._build_redis_client", refuse)

    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.redis"):
        with pytest.raises(GuardRedisError):
            await handler.initialize()

    assert not [m for m in _messages(caplog) if "Failed to close" in m]


async def test_a_client_that_will_not_close_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    handler = _handler()
    client = Mock()
    client.aclose.side_effect = OSError("boom")

    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.redis"):
        await handler._safe_aclose(client)

    assert "Failed to close a Redis client: boom" in _messages(caplog)


async def test_close_logs_reports_and_marks_the_handler_closed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    handler = _handler()
    client = Mock(aclose=AsyncMock())
    handler._redis = client

    with caplog.at_level(logging.INFO, logger="guard_core.handlers.redis"):
        await handler.close()

    assert "Redis connection closed" in _messages(caplog)
    assert handler._closed is True
    assert _client_of(handler) is None
    client.aclose.assert_awaited_once()
    (event,) = _events(handler)
    assert event.event_type == "redis_connection"
    assert event.action_taken == "connection_closed"
    assert event.reason == "Redis connection closed gracefully"


async def test_closing_a_handler_without_a_client_still_marks_it_closed() -> None:
    handler = _handler()
    handler._redis = None

    await handler.close()

    assert handler._closed is True
    assert _events(handler) == []


async def test_using_a_closed_handler_is_refused_and_reported() -> None:
    handler = _handler()
    handler._closed = True

    with pytest.raises(GuardRedisError) as raised:
        async with handler.get_connection():
            pass

    assert raised.value.status_code == 503
    assert raised.value.detail == "Redis connection closed"
    (event,) = _events(handler)
    assert event.event_type == "redis_error"
    assert event.action_taken == "operation_failed"
    assert event.reason == "Attempted to use closed Redis connection"
    assert event.metadata == {"error_type": "connection_closed"}


async def test_a_handler_that_stays_unconnected_is_refused_and_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = _handler()
    handler._redis = None
    monkeypatch.setattr(handler, "initialize", AsyncMock())

    with pytest.raises(GuardRedisError) as raised:
        async with handler.get_connection():
            pass

    assert raised.value.detail == "Redis connection failed"
    (event,) = _events(handler)
    assert event.action_taken == "operation_failed"
    assert event.reason == "Redis connection is None after initialization"
    assert event.metadata == {"error_type": "initialization_failed"}


async def test_a_connection_error_inside_a_connection_is_logged_and_reported(
    caplog: pytest.LogCaptureFixture,
) -> None:
    handler = _handler()
    handler._redis = Mock()

    with caplog.at_level(logging.ERROR, logger="guard_core.handlers.redis"):
        with pytest.raises(GuardRedisError) as raised:
            async with handler.get_connection():
                raise RedisConnectionError("reset")

    assert raised.value.status_code == 503
    assert raised.value.detail == "Redis connection failed"
    assert "Redis operation failed: reset" in _messages(caplog)
    (event,) = _events(handler)
    assert event.action_taken == "operation_failed"
    assert event.reason == "Redis operation failed: reset"
    assert event.metadata == {"error_type": "operation_error"}


async def test_a_failing_safe_operation_is_logged_reported_and_named(
    caplog: pytest.LogCaptureFixture,
) -> None:
    handler = _handler()
    handler._redis = Mock()

    async def explode(conn: Mock) -> None:
        raise RuntimeError("boom")

    with caplog.at_level(logging.ERROR, logger="guard_core.handlers.redis"):
        with pytest.raises(GuardRedisError) as raised:
            await handler.safe_operation(explode)

    assert raised.value.status_code == 503
    assert raised.value.detail == "Redis operation failed"
    assert "Redis operation failed: boom" in _messages(caplog)
    (event,) = _events(handler)
    assert event.action_taken == "safe_operation_failed"
    assert event.reason == "Redis safe operation failed: boom"
    assert event.metadata == {
        "error_type": "safe_operation_error",
        "function_name": "explode",
    }


async def test_a_nameless_failing_operation_is_reported_as_unknown() -> None:
    handler = _handler()
    handler._redis = Mock()

    async def explode(conn: Mock, message: str) -> None:
        raise RuntimeError(message)

    with pytest.raises(GuardRedisError):
        await handler.safe_operation(partial(explode, message="x"))

    assert _events(handler)[0].metadata["function_name"] == "unknown"


class _Pipeline:
    def __init__(self, results: list[int]) -> None:
        self.results = results
        self.calls: list[tuple[str, tuple[str, ...], dict[str, int | None]]] = []

    async def __aenter__(self) -> "_Pipeline":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.calls.append(("set", (key, value), {"ex": ex}))

    async def delete(self, key: str) -> None:
        self.calls.append(("delete", (key,), {}))

    async def incr(self, key: str) -> None:
        self.calls.append(("incr", (key,), {}))

    async def expire(self, key: str, ttl: int) -> None:
        self.calls.append(("expire", (key, str(ttl)), {}))

    async def execute(self) -> list[int]:
        return self.results


class _PipelineConnection:
    def __init__(self, results: list[int]) -> None:
        self.pipe = _Pipeline(results)
        self.pipeline_kwargs: list[dict[str, bool]] = []

    def pipeline(self, **kwargs: bool) -> _Pipeline:
        self.pipeline_kwargs.append(kwargs)
        return self.pipe


async def test_incr_returns_the_counter_and_expires_it_only_with_a_ttl() -> None:
    handler = _handler()
    connection = _PipelineConnection([7, 1])
    handler._redis = Mock(wraps=connection)

    assert await handler.incr("ns", "k", 30) == 7
    assert connection.pipe.calls == [
        ("incr", ("p:ns:k",), {}),
        ("expire", ("p:ns:k", "30"), {}),
    ]
    connection.pipe.calls.clear()

    assert await handler.incr("ns", "k") == 7
    assert connection.pipe.calls == [("incr", ("p:ns:k",), {})]


async def test_incr_of_an_empty_pipeline_result_is_zero() -> None:
    handler = _handler()
    handler._redis = Mock(wraps=_PipelineConnection([]))

    assert await handler.incr("ns", "k") == 0


async def test_write_atomically_runs_one_transaction_with_sets_deletes_and_incr() -> (
    None
):
    handler = _handler()
    connection = _PipelineConnection([])
    handler._redis = Mock(wraps=connection)

    await handler.write_atomically(
        sets=[("a", "1", "v", 60), ("b", "2", "w", None)],
        deletes=[("c", "3")],
        increment=("ban_version", "counter"),
    )

    assert connection.pipeline_kwargs == [{"transaction": True}]
    assert connection.pipe.calls == [
        ("set", ("p:a:1", "v"), {"ex": 60}),
        ("set", ("p:b:2", "w"), {"ex": None}),
        ("delete", ("p:c:3",), {}),
        ("incr", ("p:ban_version:counter",), {}),
    ]


async def test_write_atomically_without_an_increment_does_not_increment() -> None:
    handler = _handler()
    connection = _PipelineConnection([])
    handler._redis = Mock(wraps=connection)

    await handler.write_atomically(sets=[("a", "1", "v", 5)])

    assert [name for name, _, _ in connection.pipe.calls] == ["set"]


class _ScriptConnection:
    def __init__(self, answer: object, missing_first: bool = False) -> None:
        self.answer = answer
        self.missing_first = missing_first
        self.evalsha_calls: list[tuple[str | int | float, ...]] = []
        self.loaded: list[str] = []

    async def evalsha(self, *args: str | int | float) -> object:
        self.evalsha_calls.append(args)
        if self.missing_first and len(self.evalsha_calls) == 1:
            raise NoScriptError("missing")
        return self.answer

    async def script_load(self, script: str) -> str:
        self.loaded.append(script)
        return "sha"


class _LeanScriptConnection(_ScriptConnection):
    """A client whose pool has no fast return, so ``lean_command`` sends each
    command through ``execute_command`` (the path a RedisHandlerBase subclass
    takes), with the command's arguments as the server would receive them."""

    connection_pool = object()

    async def execute_command(self, name: str, *args: str) -> object:
        if name == "SCRIPT":
            return await self.script_load(args[1])
        return await self.evalsha(*args)


@pytest.mark.parametrize(
    ("advance", "owned", "flags"),
    [(False, False, ("0", "0")), (True, True, ("1", "1")), (True, False, ("1", "0"))],
)
async def test_the_extend_only_ban_write_sends_keys_and_flags_to_the_script(
    advance: bool, owned: bool, flags: tuple[str, str]
) -> None:
    handler = _handler()
    connection = _ScriptConnection([1, 4242.5])
    handler._redis = Mock(wraps=connection)

    kept = await handler.write_ban_extending_only(
        "banned_ips",
        "1.2.3.4",
        "1000.5",
        60,
        version=("ban_version", "counter"),
        advance_version=advance,
        rule_owned=owned,
    )

    assert kept == 4242.5
    assert connection.evalsha_calls == [
        (
            _EXTEND_ONLY_BAN_WRITE_SHA,
            4,
            "p:banned_ips:1.2.3.4",
            "p:ban_version:counter",
            handler._owned_bans_key(),
            handler.ban_floor_key("banned_ips", "1.2.3.4"),
            "1000.5",
            60,
            *flags,
        )
    ]


async def test_the_extend_only_ban_write_loads_a_missing_script_and_retries() -> None:
    handler = _handler()
    connection = _ScriptConnection([1, 9.0], missing_first=True)
    handler._redis = Mock(wraps=connection)

    kept = await handler.write_ban_extending_only(
        "banned_ips", "1.2.3.4", "1.0", 60, version=("v", "c")
    )

    assert kept == 9.0
    assert connection.loaded == [EXTEND_ONLY_BAN_WRITE_SCRIPT]
    assert len(connection.evalsha_calls) == 2
    assert connection.evalsha_calls[0] == connection.evalsha_calls[1]


@pytest.fixture
async def live_handler() -> AsyncIterator[RedisHandlerBase]:
    handler = RedisHandlerBase(
        SecurityConfig(
            redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379"),
            redis_prefix=suite_redis_prefix("wp100"),
        )
    )
    await handler.initialize()
    yield handler
    await handler.delete_pattern("*")
    await handler.close()


def test_the_owned_ban_set_and_floor_keys_keep_their_wire_layout() -> None:
    handler = _handler()

    assert handler._owned_bans_key() == "p:dynamic_rules:owned_bans"
    assert handler.ban_floor_key("banned_ips", "1.2.3.4") == (
        "p:ban_floors:banned_ips:1.2.3.4"
    )


def test_the_detection_strike_keys_keep_their_wire_layout() -> None:
    handler = _handler()

    assert handler._detection_strike_keys("1.2.3.4") == (
        "p:detection:strikes_index:1.2.3.4",
        "p:detection:strikes:1.2.3.4",
        "p:detection:strikes:1.2.3.4|",
    )
    assert handler.detection_correlation_keys("1.2.3.4") == [
        "p:detection:strikes_index:1.2.3.4",
        "p:rate_limit:violations:1.2.3.4",
    ]


async def test_the_owned_ban_state_reads_the_rule_score_and_the_live_expiry(
    live_handler: RedisHandlerBase,
) -> None:
    await live_handler.set_key("banned_ips", "1.2.3.4", "2000.25")
    async with live_handler.get_connection() as conn:
        await conn.zadd(
            live_handler._owned_bans_key(),
            {f"{live_handler.config.redis_prefix}banned_ips:1.2.3.4": 1500.5},
        )

    assert await live_handler.owned_ban_state("banned_ips", "1.2.3.4") == (
        1500.5,
        2000.25,
    )
    assert await live_handler.owned_ban_state("banned_ips", "9.9.9.9") == (None, None)


async def test_owned_ban_members_lists_the_set_and_disown_removes_one(
    live_handler: RedisHandlerBase,
) -> None:
    prefix = live_handler.config.redis_prefix
    async with live_handler.get_connection() as conn:
        await conn.zadd(
            live_handler._owned_bans_key(),
            {f"{prefix}banned_ips:1.1.1.1": 1, f"{prefix}banned_ips:2.2.2.2": 2},
        )

    assert await live_handler.owned_ban_members() == [
        f"{prefix}banned_ips:1.1.1.1",
        f"{prefix}banned_ips:2.2.2.2",
    ]
    await live_handler.disown_ban("banned_ips", "1.1.1.1")
    assert await live_handler.owned_ban_members() == [f"{prefix}banned_ips:2.2.2.2"]


async def test_a_sliding_window_index_at_its_cap_refuses_and_reports_it(
    live_handler: RedisHandlerBase,
) -> None:
    now = time.time()
    first: list[bool] = []
    second: list[bool] = []

    one = await live_handler.record_sliding_window_hit(
        "rl", "a", now, now - 60, 120, index=("idx", 1), index_refused=first
    )
    two = await live_handler.record_sliding_window_hit(
        "rl", "b", now, now - 60, 120, index=("idx", 1), index_refused=second
    )

    assert (one, two) == (1, 1)
    assert first == []
    assert second == [True]


async def test_exists_and_delete_report_what_redis_holds(
    live_handler: RedisHandlerBase,
) -> None:
    await live_handler.set_key("ns", "k", "v", 60)

    assert await live_handler.exists("ns", "k") is True
    assert await live_handler.exists("ns", "other") is False
    assert await live_handler.delete("ns", "k") == 1
    assert await live_handler.delete("ns", "k") == 0
    assert await live_handler.exists("ns", "k") is False


async def test_delete_counts_a_missing_reply_as_zero() -> None:
    handler = _handler()
    handler._redis = Mock(delete=AsyncMock(return_value=None))

    assert await handler.delete("ns", "k") == 0


async def test_sliding_window_counts_and_the_indexed_sum_follow_the_window(
    live_handler: RedisHandlerBase,
) -> None:
    now = time.time()
    await live_handler.record_sliding_window_hit(
        "rl", "a", now - 100, now - 200, 300, index=("idx", 10)
    )
    await live_handler.record_sliding_window_hit(
        "rl", "a", now, now - 200, 300, index=("idx", 10)
    )
    await live_handler.record_sliding_window_hit(
        "rl", "b", now, now - 200, 300, index=("idx", 10)
    )

    assert await live_handler.count_sliding_window_hits("rl", "a", now - 200) == 2
    assert await live_handler.count_sliding_window_hits("rl", "a", now - 50) == 1
    assert await live_handler.sum_indexed_window_hits("rl", "idx", now - 200) == 3
    assert await live_handler.sum_indexed_window_hits("rl", "idx", now - 50) == 2


async def test_detection_strikes_are_recorded_read_and_forgotten(
    live_handler: RedisHandlerBase,
) -> None:
    now = time.time()

    recorded = await live_handler.record_detection_strikes(
        "1.2.3.4", ["xss", "sqli"], now, now - 60, 120, 100
    )
    again = await live_handler.record_detection_strikes(
        "1.2.3.4", ["xss"], now, now - 60, 120, 100
    )

    assert recorded == (1, 0, {"xss": 1, "sqli": 1})
    assert again == (2, 0, {"xss": 2})
    assert await live_handler.read_detection_categories("1.2.3.4", now - 60) == [
        "sqli",
        "xss",
    ]
    await live_handler.forget_detection_strikes("1.2.3.4")
    assert await live_handler.read_detection_categories("1.2.3.4", now - 60) == []


async def test_a_missing_detection_script_is_loaded_and_the_call_repeated() -> None:
    handler = _handler()
    connection = _LeanScriptConnection([3, 1, 2, 5], missing_first=True)
    handler._redis = Mock(wraps=connection)

    result = await handler.record_detection_strikes(
        "1.2.3.4", ["a", "b"], 10.5, 5.5, 60, 9
    )

    assert result == (3, 1, {"a": 2, "b": 5})
    assert connection.loaded == [RECORD_DETECTION_STRIKES_SCRIPT]
    first, second = connection.evalsha_calls
    assert first == second
    assert first[:2] == (_RECORD_DETECTION_STRIKES_SHA, "5")
    assert first[2:5] == (
        "p:detection:strikes_index:1.2.3.4",
        "p:detection:strikes:1.2.3.4",
        "p:rate_limit:violations:1.2.3.4",
    )
    assert first[5:7] == (
        "p:detection:strikes:1.2.3.4|a",
        "p:detection:strikes:1.2.3.4|b",
    )
    assert first[7] == "10.5"
    assert first[9:] == ("5.5", 60, 9)


async def test_a_missing_category_script_is_loaded_and_prefixes_are_stripped() -> None:
    handler = _handler()
    connection = _ScriptConnection(
        ["p:detection:strikes:1.2.3.4|b", "p:detection:strikes:1.2.3.4|a"],
        missing_first=True,
    )
    handler._redis = Mock(wraps=connection)

    assert await handler.read_detection_categories("1.2.3.4", 5.5) == ["a", "b"]

    assert connection.loaded == [READ_DETECTION_CATEGORIES_SCRIPT]
    expected = (
        _READ_DETECTION_CATEGORIES_SHA,
        2,
        "p:detection:strikes_index:1.2.3.4",
        "p:rate_limit:violations:1.2.3.4",
        "5.5",
    )
    assert connection.evalsha_calls == [expected, expected]


async def test_a_missing_forget_script_is_loaded_and_the_call_repeated() -> None:
    handler = _handler()
    connection = _ScriptConnection([], missing_first=True)
    handler._redis = Mock(wraps=connection)

    await handler.forget_detection_strikes("1.2.3.4")

    assert connection.loaded == [FORGET_DETECTION_STRIKES_SCRIPT]
    expected = (
        _FORGET_DETECTION_STRIKES_SHA,
        2,
        "p:detection:strikes_index:1.2.3.4",
        "p:detection:strikes:1.2.3.4",
    )
    assert connection.evalsha_calls == [expected, expected]


async def test_a_missing_purge_script_is_loaded_and_the_call_repeated() -> None:
    handler = _handler()
    connection = _ScriptConnection(2, missing_first=True)
    handler._redis = Mock(wraps=connection)

    assert await handler.purge_owned_ban("p:banned_ips:1.2.3.4") == 2

    assert connection.loaded == [PURGE_OWNED_BAN_SCRIPT]
    expected = (
        _PURGE_OWNED_BAN_SHA,
        3,
        "p:banned_ips:1.2.3.4",
        handler._owned_bans_key(),
        "p:ban_floors:banned_ips:1.2.3.4",
    )
    assert connection.evalsha_calls == [expected, expected]


async def test_a_missing_indexed_sum_script_is_loaded_and_the_call_repeated() -> None:
    handler = _handler()
    connection = _ScriptConnection(7, missing_first=True)
    handler._redis = Mock(wraps=connection)

    assert await handler.sum_indexed_window_hits("rl", "idx", 5.5) == 7

    assert connection.loaded == [SUM_INDEXED_WINDOW_HITS_SCRIPT]
    expected = (_SUM_INDEXED_WINDOW_HITS_SHA, 1, "p:rl:idx", "5.5")
    assert connection.evalsha_calls == [expected, expected]


async def test_a_missing_sliding_window_script_is_loaded_and_the_call_repeated() -> (
    None
):
    handler = _handler()
    connection = _ScriptConnection(3, missing_first=True)
    handler._redis = Mock(wraps=connection)

    count = await handler.record_sliding_window_hit(
        "rl", "k", 10.5, 5.5, 60, index=("idx", 4)
    )

    assert count == 3
    assert connection.loaded == [SLIDING_WINDOW_HIT_SCRIPT]
    first, second = connection.evalsha_calls
    assert first == second
    assert first[:5] == (_SLIDING_WINDOW_SHA, 2, "p:rl:k", "p:rl:idx", "10.5")
    assert first[6:] == ("5.5", 60, 4)


async def test_delete_pattern_returns_how_many_keys_it_removed(
    live_handler: RedisHandlerBase,
) -> None:
    for name in ("a", "b", "c"):
        await live_handler.set_key("ns", name, "v", 60)

    assert await live_handler.delete_pattern("ns:*") == 3
    assert await live_handler.delete_pattern("ns:*") == 0


def test_a_custom_handler_logs_under_the_redis_logger_name() -> None:
    assert RedisHandlerBase.logger.name == "guard_core.handlers.redis"


async def test_scan_unlink_removes_only_the_keys_the_selector_accepts() -> None:
    connection = _ScanConnection(["keep", "drop1", "drop2"])

    removed = await scan_unlink(
        Mock(wraps=connection), "*", lambda key: key.startswith("drop")
    )

    assert removed == 2
    assert connection.unlinked == [("drop1", "drop2")]


async def test_a_short_lived_client_decodes_responses_and_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _ScanConnection(["a"])
    client = Mock(
        scan_iter=connection.scan_iter,
        unlink=connection.unlink,
        aclose=AsyncMock(),
    )
    from_url = Mock(return_value=client)
    monkeypatch.setattr(Redis, "from_url", from_url)

    removed = await scan_unlink_through_new_client("redis://x", "a*")

    assert removed == 1
    from_url.assert_called_once_with("redis://x", decode_responses=True)
    client.aclose.assert_awaited_once()


def test_the_legacy_alias_is_the_manager_class() -> None:
    assert redis_handler_alias is RedisManager


@pytest.mark.parametrize("retries", [1, 3])
def test_any_positive_retry_count_builds_a_retry_policy(retries: int) -> None:
    handler = RedisHandlerBase(
        SecurityConfig(enable_redis=True, redis_url="redis://x", redis_retries=retries)
    )

    kwargs = handler._connection_kwargs()

    assert isinstance(kwargs["retry"], Retry)
    assert kwargs["retry"]._retries == retries
    assert kwargs["retry_on_error"] == [RedisConnectionError, RedisTimeoutError]


def test_zero_retries_build_no_retry_policy() -> None:
    handler = RedisHandlerBase(
        SecurityConfig(enable_redis=True, redis_url="redis://x", redis_retries=0)
    )

    assert "retry" not in handler._connection_kwargs()


async def test_set_key_reports_success_as_true(
    live_handler: RedisHandlerBase,
) -> None:
    assert await live_handler.set_key("ns", "k", "v") is True
    assert await live_handler.set_key("ns", "k2", "v", 30) is True
    assert await live_handler.get_key("ns", "k") == "v"


class _StatePipeline:
    async def __aenter__(self) -> "_StatePipeline":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def zscore(self, key: str, member: str) -> None:
        return None

    async def get(self, member: str) -> None:
        return None

    async def execute(self) -> list[None]:
        return [None, None]


async def test_the_owned_ban_state_reads_in_a_non_transactional_pipeline() -> None:
    handler = _handler()
    pipeline_kwargs: list[dict[str, bool]] = []

    def pipeline(**kwargs: bool) -> _StatePipeline:
        pipeline_kwargs.append(kwargs)
        return _StatePipeline()

    handler._redis = Mock(pipeline=pipeline)

    assert await handler.owned_ban_state("banned_ips", "1.2.3.4") == (None, None)
    assert pipeline_kwargs == [{"transaction": False}]


async def test_a_refused_hit_still_returns_the_keys_own_count(
    live_handler: RedisHandlerBase,
) -> None:
    now = time.time()
    await live_handler.record_sliding_window_hit(
        "rl", "a", now, now - 60, 120, index=("idx", 1), index_refused=[]
    )
    refused: list[bool] = []

    await live_handler.record_sliding_window_hit(
        "rl", "b", now, now - 60, 120, index=("idx", 1), index_refused=refused
    )
    count = await live_handler.record_sliding_window_hit(
        "rl", "b", now, now - 60, 120, index=("idx", 1), index_refused=refused
    )

    assert count == 2
    assert refused == [True, True]
