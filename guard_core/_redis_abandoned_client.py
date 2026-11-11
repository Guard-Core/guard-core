from __future__ import annotations

import atexit
import itertools
import logging
import threading
import weakref
from typing import TYPE_CHECKING

from guard_core._redis_client_loop import EventLoop

if TYPE_CHECKING:
    from redis import Redis as SyncRedis
    from redis.asyncio import Redis
    from redis.asyncio.connection import Connection

__all__ = [
    "abandon_client",
    "close_sync_client",
    "sweep_abandoned_clients",
    "sweep_no_abandoned_clients",
]


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
_pending: dict[int, tuple[Redis, weakref.ref[EventLoop]]] = {}
_pending_ids = itertools.count()
_logger = logging.getLogger(__name__)


def _drop_once_and_survive_failure(client: Redis) -> None:
    try:
        _drop_connection_sockets(client)
    except Exception:
        _logger.error("An abandoned Redis client could not be dropped")


def _drop_pending(token: int) -> None:
    # Whoever removes the entry owns the drop, so a sweep and the loop's own
    # callback never both touch the same connections. The lock also keeps a pop
    # from resizing the dict while a sweep iterates it.
    with _pending_lock:
        entry = _pending.pop(token, None)
    if entry is not None:
        _drop_once_and_survive_failure(entry[0])


def _is_gone_or_closed(loop: EventLoop | None) -> bool:
    # A collected loop closed itself and discarded its queued drop.
    return loop is None or loop.is_closed()


def _claim_pending(only_closed_loops: bool) -> list[Redis]:
    with _pending_lock:
        tokens = [
            token
            for token, (_, loop_ref) in _pending.items()
            if not only_closed_loops or _is_gone_or_closed(loop_ref())
        ]
        return [_pending.pop(token)[0] for token in tokens]


def sweep_abandoned_clients() -> None:
    """Drop, from the calling thread, every pending client whose loop is closed or
    was garbage collected (the registry holds loops weakly, so it keeps none alive).

    A loop that is stopped but not closed keeps its entry: its scheduled drop is
    still queued and runs on its own thread if it runs again. Each drop is
    independent: one that raises is logged and does not stop the others."""
    for client in _claim_pending(only_closed_loops=True):
        _drop_once_and_survive_failure(client)


def _drop_everything_pending_at_exit() -> None:
    for client in _claim_pending(only_closed_loops=False):
        _drop_once_and_survive_failure(client)


atexit.register(_drop_everything_pending_at_exit)


def abandon_client(client: Redis, client_loop: EventLoop) -> None:
    """Release the sockets of a client built under another event loop.

    ``aclose`` runs only on the loop that owns the sockets, so this never awaits and
    never blocks the caller's loop, and it never touches the transports of a loop
    that may run again from another thread. The drop is scheduled on the owning loop
    and the client stays pending until it runs. If that loop is closed (also if it
    closes before running the drop, for example when ``stop()`` was already called
    on its last iteration) the client is dropped from the calling thread: at once
    for a loop that is already closed, otherwise at the first later sweep that sees
    it closed (the next ``abandon_client``, connect, close or reconnect attempt on
    any manager, or ``sweep_abandoned_clients``) or at interpreter exit. That is the
    residual window: the sockets stay open until then. A drop that raises is logged
    and never stops the other pending drops or this client's own.
    """
    sweep_abandoned_clients()
    token = next(_pending_ids)
    with _pending_lock:
        _pending[token] = (client, weakref.ref(client_loop))
    try:
        client_loop.call_soon_threadsafe(_drop_pending, token)
    except RuntimeError:
        _drop_pending(token)  # the loop is closed: nothing runs on it any more


def close_sync_client(client: SyncRedis, _client_loop: EventLoop) -> None:
    """The sync tree's ``abandon_client``: its sockets belong to no loop. The sync
    ``close`` drops the pool the client owns only from redis-py 5.0.0 on."""
    client.close()
    client.connection_pool.disconnect()


def sweep_no_abandoned_clients() -> None:
    """The sync tree's ``sweep_abandoned_clients``: it keeps none pending."""
