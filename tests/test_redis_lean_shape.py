from typing import Any

from redis import __version__ as REDIS_PY_VERSION
from redis.asyncio.connection import Connection

from guard_core.handlers.redis_handler import _build_redis_client
from tests import redis_py_internals as internals
from tests.conftest import REDIS_URL

WHAT = (
    "the lean Redis executor (guard_core/handlers/_redis_lean.py and "
    "_redis_fast_pool.py) reads it; update the executor or make it fall back "
    "before this redis-py is allowed in"
)


def _has(owner: Any, name: str, description: str) -> None:
    assert hasattr(owner, name), (
        f"redis-py {REDIS_PY_VERSION} has no {description} ({name}): {WHAT}"
    )


def test_the_connection_and_pool_keep_the_shape_the_lean_executor_reads() -> None:
    client = _build_redis_client(REDIS_URL, 2, 1.0)
    pool = client.connection_pool
    connection: Connection = pool.make_connection()
    for name in ("_available_connections", "_in_use_connections", "max_connections"):
        _has(pool, name, "connection pool field")
    assert hasattr(pool._available_connections, "pop"), (
        f"redis-py {REDIS_PY_VERSION}: pool._available_connections is no longer "
        f"a stack with pop and append: {WHAT}"
    )
    assert hasattr(pool._in_use_connections, "remove"), (
        f"redis-py {REDIS_PY_VERSION}: pool._in_use_connections is no longer a "
        f"set with add and remove: {WHAT}"
    )
    for name in (
        "_buffer_cutoff",
        "encoder",
        "retry",
        "pack_command",
        "send_packed_command",
        "read_response",
        "disconnect",
    ):
        _has(connection, name, "connection field or method")
    assert isinstance(connection._buffer_cutoff, int), (
        f"redis-py {REDIS_PY_VERSION}: connection._buffer_cutoff is no longer "
        f"an int: {WHAT}"
    )
    assert (
        hasattr(connection, "should_reconnect") is internals.SHOULD_RECONNECT_EXISTS
    ), (
        f"redis-py {REDIS_PY_VERSION}: Connection.should_reconnect is not where "
        f"tests/redis_py_internals.py says it is (from redis-py 7.0.0); without it "
        f"the fast return is refused: {WHAT}"
    )
    for name in ("encoding", "encoding_errors"):
        _has(connection.encoder, name, "encoder field")
    _has(connection.retry, "call_with_retry", "retry method")
