from __future__ import annotations

from typing import TYPE_CHECKING, Any

from guard_core._redis_exceptions import NoScriptError, ResponseError

if TYPE_CHECKING:
    from redis import Redis
    from redis.connection import AbstractConnection


def _packed_by_redis_py(
    connection: AbstractConnection, args: tuple[Any, ...]
) -> list[bytes]:
    chunks: list[bytes] = connection.pack_command(*args)
    return chunks


def _pack(connection: AbstractConnection, args: tuple[Any, ...]) -> list[bytes]:
    """The RESP chunks of ``args``, what ``connection.pack_command`` builds, with
    one encode and one length per argument. An argument that is neither ``str``
    nor ``bytes`` (an int or a float), a first argument that is not one word, or
    a command big enough to be sent in chunks takes ``pack_command`` itself."""
    encoder = connection.encoder
    try:
        data = [
            arg
            if arg.__class__ is bytes
            else arg.encode(encoder.encoding, encoder.encoding_errors)
            for arg in args
        ]
    except AttributeError:
        return _packed_by_redis_py(connection, args)
    if b" " in data[0]:
        return _packed_by_redis_py(connection, args)
    packed = b"*%d\r\n%b" % (
        len(data),
        b"".join([b"$%d\r\n%b\r\n" % (len(item), item) for item in data]),
    )
    if len(packed) > connection._buffer_cutoff:
        return _packed_by_redis_py(connection, args)
    return [packed]


def lean_command(client: Redis, *args: Any) -> Any:
    """One command on a pooled connection, without the client layer (observability
    timing, retry bookkeeping, response callbacks) and without the pool's lock and
    events on each checkout and release.

    The connection comes from the pool (``FastPathConnectionPool`` hands out one
    its fast return left with nothing unread, else the plain ``get_connection``),
    does its own connect, auth, TLS, health check, timeouts and decoding, and goes
    back to the pool through ``give_back``. The send runs inside the connection's
    own retry, so a connection the server dropped while idle reconnects and resends
    a command that never left; the read is never retried, because a script that
    already ran must not run twice (the rate-limit members are the server's clock).
    After an error or a cancellation the connection is disconnected before it
    goes back, so no later call reads a stale reply.

    A client whose pool is not a ``FastPathConnectionPool`` (a ``RedisHandlerBase``
    subclass brings its own) has no fast return to take from, so the command goes
    through the client's own ``execute_command``."""
    pool = client.connection_pool
    take_connection = getattr(pool, "take_connection_with_nothing_unread", None)
    if take_connection is None:
        return client.execute_command(*args)
    connection = take_connection()
    if connection is None:
        connection = pool.get_connection()
    packed = _pack(connection, args)

    def send() -> None:
        connection.send_packed_command(packed)

    reply_read = False
    try:
        connection.retry.call_with_retry(send, lambda _error: connection.disconnect())
        reply = connection.read_response()
        reply_read = True
        return reply
    except ResponseError:
        reply_read = True
        raise
    except BaseException:
        connection.disconnect()
        raise
    finally:
        pool.give_back(connection, reply_read)


def lean_evalsha(
    client: Redis, script: str, sha: str, keys: list[Any], arguments: list[Any]
) -> Any:
    """``EVALSHA`` through ``lean_command``, loading the script and retrying once
    when the server does not have it (a restart or a failover)."""
    try:
        return lean_command(client, "EVALSHA", sha, f"{len(keys)}", *keys, *arguments)
    except NoScriptError:
        lean_command(client, "SCRIPT", "LOAD", script)
        return lean_command(client, "EVALSHA", sha, f"{len(keys)}", *keys, *arguments)
