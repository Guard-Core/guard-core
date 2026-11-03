from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import patch

import pytest
from redis import Redis
from redis.exceptions import NoScriptError

from guard_core.sync.handlers._redis_lean import lean_command, lean_evalsha
from guard_core.sync.handlers.redis_handler import _build_redis_client
from tests import redis_py_internals as internals
from tests.conftest import REDIS_URL
from tests.test_sync.conftest import suite_redis_prefix
from tests.test_sync.engine_redis_commands import (
    server_loses_the_script_of_the_next_evalsha,
)

SCRIPT = "return {KEYS[1], ARGV[1], false, 7, {KEYS[2], 'x'}}"


def test_replies_equal_the_high_level_path_and_a_lost_script_is_reloaded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _build_redis_client(REDIS_URL, 10, 1.0)
    try:
        sha = client.script_load(SCRIPT)
        assert lean_evalsha(client, SCRIPT, sha, ["a", "b"], ["x"]) == client.evalsha(
            sha, 2, "a", "b", "x"
        )
        turned = server_loses_the_script_of_the_next_evalsha(monkeypatch)
        assert lean_evalsha(client, SCRIPT, sha, ["a", "b"], ["x"]) == client.evalsha(
            sha, 2, "a", "b", "x"
        )
        assert len(turned) == 1
        key = f"{suite_redis_prefix('lean')}key"
        client.set(key, "1")
        assert lean_command(client, "GET", key) == "1"
        assert lean_command(client, "MGET", key, f"{key}:none") == client.mget(
            [key, f"{key}:none"]
        )
    finally:
        client.close()


def test_the_thread_pool_never_hands_out_a_connection_without_the_plain_path() -> None:
    client = _build_redis_client(REDIS_URL, 10, 1.0)
    pool = client.connection_pool
    try:
        with ThreadPoolExecutor(max_workers=8) as executor:
            replies = list(
                executor.map(lambda _: lean_command(client, "PING"), range(100))
            )
        assert replies == ["PONG"] * 100
        assert pool.take_connection_with_nothing_unread() is None
        assert len(pool._in_use_connections) == 0
        assert pool._created_connections <= 10
    finally:
        client.close()


def test_a_missing_script_still_raises_without_a_reload_source() -> None:
    client = _build_redis_client(REDIS_URL, 10, 1.0)
    try:
        try:
            lean_command(client, "EVALSHA", "0" * 40, 0)
        except NoScriptError:
            return
        raise AssertionError("EVALSHA of an unknown sha did not raise NoScriptError")
    finally:
        client.close()


def test_a_failed_read_disconnects_the_connection_and_raises() -> None:
    from redis.connection import Connection

    client = _build_redis_client(REDIS_URL, 10, 1.0)
    try:
        lean_command(client, "PING")
        with patch.object(
            Connection, "read_response", side_effect=KeyboardInterrupt("interrupted")
        ):
            try:
                lean_command(client, "GET", "lean:failed-read")
            except KeyboardInterrupt:
                pass
            else:
                raise AssertionError("the interrupted read did not raise")
        assert lean_command(client, "GET", "lean:failed-read") is None
    finally:
        client.close()


def test_a_connection_the_pool_hands_out_without_unread_replies_is_used() -> None:
    client = _build_redis_client(REDIS_URL, 10, 1.0)
    try:
        pool = client.connection_pool
        spare = pool.get_connection()
        with patch.object(
            pool, "take_connection_with_nothing_unread", return_value=spare
        ):
            assert lean_command(client, "PING") == "PONG"
    finally:
        client.close()


class _Listener:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def listen(self, event: Any) -> None:
        self.events.append(event)


def test_a_release_listener_hears_each_lean_call_like_each_plain_one() -> None:
    client = _build_redis_client(REDIS_URL, 10, 1.0)
    try:
        if not internals.REGISTER_LISTENERS_EXISTS:
            assert not hasattr(
                getattr(client.connection_pool, "_event_dispatcher", None),
                "register_listeners",
            )
            for _ in range(3):
                assert lean_command(client, "GET", "lean:event") is None
                assert client.execute_command("GET", "lean:event") is None
            return
        from redis.event import AfterConnectionReleasedEvent

        listener = _Listener()
        client.connection_pool._event_dispatcher.register_listeners(
            {AfterConnectionReleasedEvent: [listener]}
        )
        lean_command(client, "PING")
        client.execute_command("PING")
        listener.events.clear()
        for _ in range(5):
            lean_command(client, "GET", "lean:event")
        assert len(listener.events) == 5
        listener.events.clear()
        for _ in range(5):
            client.execute_command("GET", "lean:event")
        assert len(listener.events) == 5
    finally:
        client.close()


def test_a_stock_client_answers_every_lean_routed_method_like_the_fast_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fast = _build_redis_client(REDIS_URL, 10, 1.0)
    stock = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        sha = stock.script_load(SCRIPT)
        key = f"{suite_redis_prefix('lean')}key"
        stock.set(key, "1")
        for client in (stock, fast):
            assert lean_command(client, "GET", key) == "1"
            assert lean_command(client, "MGET", key, f"{key}:none") == ["1", None]
            assert lean_evalsha(client, SCRIPT, sha, ["a", "b"], ["x"]) == (
                stock.evalsha(sha, 2, "a", "b", "x")
            )
        turned = server_loses_the_script_of_the_next_evalsha(monkeypatch)
        assert lean_evalsha(stock, SCRIPT, sha, ["a", "b"], ["x"]) == lean_evalsha(
            fast, SCRIPT, sha, ["a", "b"], ["x"]
        )
        assert len(turned) == 1
    finally:
        stock.close()
        fast.close()
