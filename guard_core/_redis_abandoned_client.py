from __future__ import annotations

from typing import TYPE_CHECKING

from guard_core._redis_client_loop import EventLoop

if TYPE_CHECKING:
    from redis import Redis as SyncRedis
    from redis.asyncio import Redis
    from redis.asyncio.connection import Connection

__all__ = ["abandon_client", "close_sync_client"]


def _close_connection(connection: Connection) -> None:
    """redis-py's own ``Connection._close`` (5.0.2 on), else its three steps: close
    the writer when there is one, then forget the writer and the reader."""
    own_close = getattr(connection, "_close", None)
    if own_close is not None:
        own_close()
        return
    if connection._writer is not None:
        connection._writer.close()
    connection._writer = connection._reader = None


def _drop_connection_sockets(client: Redis) -> None:
    pool = client.connection_pool
    for connection in (*pool._available_connections, *pool._in_use_connections):
        if connection._writer is not None:
            transport = connection._writer.transport
            try:
                transport.abort()
            except RuntimeError:
                # The loop is closed and cannot schedule the close abort() asks for:
                # finish it here, the way the loop would have.
                transport._call_connection_lost(None)
        _close_connection(connection)


def abandon_client(client: Redis, client_loop: EventLoop) -> None:
    """Release the sockets of a client built under another event loop.

    ``aclose`` runs only on the loop that owns the sockets, so this never awaits.
    A running loop drops them on its own thread, a stopped or closed loop is
    dropped from here, and the caller's loop is never blocked.
    """
    if client_loop.is_running():
        try:
            client_loop.call_soon_threadsafe(_drop_connection_sockets, client)
        except RuntimeError:
            pass  # the loop closed after the check: nothing runs on it any more
        else:
            return
    _drop_connection_sockets(client)


def close_sync_client(client: SyncRedis, _client_loop: EventLoop) -> None:
    """The sync tree's ``abandon_client``: its sockets belong to no loop. The sync
    ``close`` drops the pool the client owns only from redis-py 5.0.0 on."""
    client.close()
    client.connection_pool.disconnect()
