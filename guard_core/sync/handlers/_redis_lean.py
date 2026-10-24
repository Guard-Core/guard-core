import weakref
from typing import Any

from redis import Redis
from redis.exceptions import NoScriptError, ResponseError

_FREE_CONNECTIONS: "weakref.WeakKeyDictionary[Any, list[Any]]" = (
    weakref.WeakKeyDictionary()
)


def _free_list_of(pool: Any) -> list[Any]:
    try:
        return _FREE_CONNECTIONS[pool]
    except KeyError:
        return _FREE_CONNECTIONS.setdefault(pool, [])


def lean_command(client: Redis, *args: Any) -> Any:
    """One command on a pooled connection, without the client layer (observability
    timing, retry bookkeeping, response callbacks) and without the pool's checkout
    and release on every call.

    A connection comes from a free list kept beside the pool, or from the pool when
    the list is empty; it does its own connect, auth, TLS, health check, timeouts and
    decoding, and the command runs inside its own retry (a connection the server
    dropped while idle reconnects on the send). A connection goes back to the free
    list only after its reply was read; after an error or a cancellation it is
    disconnected and handed back to the pool, never reused, so no later call reads
    a stale reply. The list holds at most half of the pool's connections, so the
    other users of the pool keep theirs."""
    pool = client.connection_pool
    free = _free_list_of(pool)
    try:
        connection = free.pop()
    except IndexError:
        connection = pool.get_connection()
    packed = connection.pack_command(*args)

    def round_trip() -> Any:
        connection.send_packed_command(packed)
        return connection.read_response()

    clean = False
    try:
        reply = connection.retry.call_with_retry(
            round_trip, lambda _error: connection.disconnect()
        )
        clean = True
        return reply
    except ResponseError:
        clean = True
        raise
    except BaseException:
        connection.disconnect()
        raise
    finally:
        if clean and len(free) < (pool.max_connections >> 1 or 1):
            free.append(connection)
        else:
            pool.release(connection)


def lean_evalsha(
    client: Redis, script: str, sha: str, keys: list[Any], arguments: list[Any]
) -> Any:
    """``EVALSHA`` through ``lean_command``, loading the script and retrying once
    when the server does not have it (a restart or a failover)."""
    try:
        return lean_command(client, "EVALSHA", sha, len(keys), *keys, *arguments)
    except NoScriptError:
        lean_command(client, "SCRIPT", "LOAD", script)
        return lean_command(client, "EVALSHA", sha, len(keys), *keys, *arguments)
