import uuid
from concurrent.futures import ThreadPoolExecutor

from redis.exceptions import NoScriptError

from guard_core.sync.handlers._redis_lean import lean_command, lean_evalsha
from guard_core.sync.handlers.redis_handler import _build_redis_client
from tests.conftest import REDIS_URL

SCRIPT = "return {KEYS[1], ARGV[1], false, 7, {KEYS[2], 'x'}}"


def test_replies_equal_the_high_level_path_and_a_lost_script_is_reloaded() -> None:
    client = _build_redis_client(REDIS_URL, 10, 1.0)
    try:
        sha = client.script_load(SCRIPT)
        assert lean_evalsha(client, SCRIPT, sha, ["a", "b"], ["x"]) == client.evalsha(
            sha, 2, "a", "b", "x"
        )
        client.script_flush()
        assert lean_evalsha(client, SCRIPT, sha, ["a", "b"], ["x"]) == client.evalsha(
            sha, 2, "a", "b", "x"
        )
        key = f"lean:{uuid.uuid4().hex}"
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
    from unittest.mock import patch

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
