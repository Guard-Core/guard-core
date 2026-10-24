from typing import Any

from redis.asyncio import Redis
from redis.exceptions import NoScriptError, ResponseError


async def lean_command(client: Redis, *args: Any) -> Any:
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
    goes back, so no later call reads a stale reply."""
    pool = client.connection_pool
    connection = await pool.take_connection_with_nothing_unread()
    if connection is None:
        connection = await pool.get_connection()
    packed = connection.pack_command(*args)

    async def send() -> None:
        await connection.send_packed_command(packed)

    reply_read = False
    try:
        await connection.retry.call_with_retry(
            send, lambda _error: connection.disconnect()
        )
        reply = await connection.read_response()
        reply_read = True
        return reply
    except ResponseError:
        reply_read = True
        raise
    except BaseException:
        await connection.disconnect()
        raise
    finally:
        await pool.give_back(connection, reply_read)


async def lean_evalsha(
    client: Redis, script: str, sha: str, keys: list[Any], arguments: list[Any]
) -> Any:
    """``EVALSHA`` through ``lean_command``, loading the script and retrying once
    when the server does not have it (a restart or a failover)."""
    try:
        return await lean_command(client, "EVALSHA", sha, len(keys), *keys, *arguments)
    except NoScriptError:
        await lean_command(client, "SCRIPT", "LOAD", script)
        return await lean_command(client, "EVALSHA", sha, len(keys), *keys, *arguments)
