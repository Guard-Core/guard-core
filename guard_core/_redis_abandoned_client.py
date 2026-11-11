from __future__ import annotations

import atexit
import itertools
import threading
from typing import TYPE_CHECKING

from guard_core._redis_client_loop import EventLoop

if TYPE_CHECKING:
    from redis import Redis as SyncRedis
    from redis.asyncio import Redis
    from redis.asyncio.connection import Connection

__all__ = ["abandon_client", "close_sync_client", "sweep_abandoned_clients"]


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


_pending_lock = threading.Lock()
_pending: dict[int, tuple[Redis, EventLoop]] = {}
_pending_ids = itertools.count()


def _drop_pending(token: int, client: Redis) -> None:
    with _pending_lock:
        _pending.pop(token, None)
    _drop_connection_sockets(client)


def sweep_abandoned_clients() -> None:
    """Drop, from the calling thread, every pending client whose loop stopped running
    before its scheduled drop ran. Dropping twice is harmless."""
    with _pending_lock:
        stranded = [
            token for token, (_, loop) in _pending.items() if not loop.is_running()
        ]
        clients = [_pending.pop(token)[0] for token in stranded]
    for client in clients:
        _drop_connection_sockets(client)


atexit.register(sweep_abandoned_clients)


def abandon_client(client: Redis, client_loop: EventLoop) -> None:
    """Release the sockets of a client built under another event loop.

    ``aclose`` runs only on the loop that owns the sockets, so this never awaits and
    never blocks the caller's loop. A running loop drops them on its own thread. A
    stopped or closed loop is dropped from here at once. A loop in its last iteration
    (``stop()`` already called, still ``is_running()``) may close without running the
    scheduled drop, so the client stays pending until this function runs again after
    that loop stopped, or until interpreter exit, and is then dropped from the
    sweeping thread. That is the residual window: the sockets stay open until the
    next ``abandon_client`` call or ``sweep_abandoned_clients`` after the loop ends.
    """
    sweep_abandoned_clients()
    if client_loop.is_running():
        token = next(_pending_ids)
        with _pending_lock:
            _pending[token] = (client, client_loop)
        try:
            client_loop.call_soon_threadsafe(_drop_pending, token, client)
        except RuntimeError:
            with _pending_lock:
                _pending.pop(token, None)
        else:
            return
    _drop_connection_sockets(client)


def close_sync_client(client: SyncRedis, _client_loop: EventLoop) -> None:
    """The sync tree's ``abandon_client``: its sockets belong to no loop. The sync
    ``close`` drops the pool the client owns only from redis-py 5.0.0 on."""
    client.close()
    client.connection_pool.disconnect()
