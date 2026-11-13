from __future__ import annotations

import threading
from collections.abc import Callable, Hashable
from threading import Lock
from typing import TYPE_CHECKING

from guard_core._redis_abandoned_client import close_sync_client
from guard_core._redis_client_loop import EventLoop, running_loop_or_none
from guard_core._redis_enablement import configured_redis_url
from guard_core._redis_exceptions import RedisConnectionError, RedisTimeoutError
from guard_core.exceptions import GuardRedisError
from guard_core.sync._utils.app_scope import app_scope_of, in_app_scope
from guard_core.sync.core.events.event_types import EVENT_REDIS_CONNECTION
from guard_core.sync.handlers import _redis_shared_clients
from guard_core.sync.handlers._redis_attempt import ConnectionLocks, RedisAttemptSlot
from guard_core.sync.handlers._redis_handler_support import _redact_redis_url
from guard_core.sync.handlers._redis_probe import redis_answers_within_the_deadline
from guard_core.sync.handlers._redis_reconnect_gate import RedisReconnectGate

if TYPE_CHECKING:
    import logging

    from redis import Redis

    from guard_core.models import SyncSecurityConfig


class RedisOutageMixin:
    """What a RedisManager does when its Redis is down or its loop changed: the
    degrade mark, the background reconnect attempt, the connection lock and the
    swap of the bound client."""

    _redis: Redis | None
    _pool_key: Hashable | None
    _client_loop: EventLoop | None
    _degraded: bool
    _closed: bool
    _connect_generation: int
    config: SyncSecurityConfig
    logger: logging.Logger

    if TYPE_CHECKING:

        def _open_connection(self, url: str) -> None: ...
        def _discard_main_client(self) -> None: ...
        def _discard_client(self) -> None: ...
        def _safe_aclose(self, client: Redis) -> None: ...
        def _send_redis_event(
            self, event_type: str, action_taken: str, reason: str, **kwargs: object
        ) -> None: ...
        def _reconnect_gate(self) -> RedisReconnectGate: ...
        def register_background_user(self, stop: Callable[[], None]) -> None: ...

    def _parked_clients(self) -> dict[EventLoop | None, tuple[Redis, Hashable | None]]:
        # Created on first use: a subclass that overrides __new__ skips __init__ work.
        parked: dict[EventLoop | None, tuple[Redis, Hashable | None]] = vars(
            self
        ).setdefault("_parked_clients_by_loop", {})
        return parked

    def _swap_client(
        self,
        new_redis: Redis | None,
        new_key: Hashable | None,
        new_loop: EventLoop | None,
    ) -> tuple[Redis | None, Hashable | None, EventLoop | None]:
        # No inside: loops on two threads each swap whole, so a client one
        # thread bound is always the "old" one of the next swap and gets released,
        # unless its loop is still alive: then it is parked, never aborted.
        swap_lock: Lock = vars(self).setdefault("_client_swap_lock", Lock())
        with swap_lock:
            old = (self._redis, self._pool_key, self._client_loop)
            if new_redis is not None:
                old = self._park_or_keep(old, new_redis, new_loop)
            self._pool_key = new_key
            # A reader on another thread sees the pair between the two stores: it
            # must never see a client together with the loop of the thread reading.
            # Binding a client writes the loop first (the one loop that then
            # matches is the writer's own), dropping it writes the client first.
            if new_redis is None:
                self._redis, self._client_loop = new_redis, new_loop
            else:
                self._client_loop, self._redis = new_loop, new_redis
        return old

    def _park_or_keep(
        self,
        old: tuple[Redis | None, Hashable | None, EventLoop | None],
        new_redis: Redis,
        new_loop: EventLoop | None,
    ) -> tuple[Redis | None, Hashable | None, EventLoop | None]:
        # The caller holds the swap lock. A client of a loop that is still alive is
        # parked under that loop; one of a closed loop is returned to be released.
        parked = self._parked_clients()
        held = parked.get(new_loop)
        if held is not None and held[0] is new_redis:
            del parked[new_loop]
        old_redis, old_key, old_loop = old
        if (
            old_redis is None
            or old_redis is new_redis
            or old_loop in (None, new_loop)
            or old_loop.is_closed()
        ):
            return old
        parked[old_loop] = (old_redis, old_key)
        return None, None, None

    def _client_here(self) -> Redis | None:
        """The client bound to the running loop: the manager's main one when it
        belongs to this loop (or to none), else the one parked for this loop."""
        client = self._redis
        client_loop = self._client_loop
        if client is not None and (
            client_loop is None or client_loop is running_loop_or_none()
        ):
            return client
        return self._parked_client_here()

    def _parked_client_here(self) -> Redis | None:
        held = self._parked_clients().get(running_loop_or_none())
        return None if held is None else held[0]

    def is_connected_on_this_loop(self) -> bool:
        """Whether the running loop has a client of this manager."""
        return self._client_here() is not None

    def _holds_a_client(self) -> bool:
        return self._redis is not None or bool(self._parked_clients())

    def _take_parked(
        self, wanted: Callable[[EventLoop | None, Redis], bool]
    ) -> list[tuple[Redis, Hashable | None, EventLoop | None]]:
        swap_lock: Lock = vars(self).setdefault("_client_swap_lock", Lock())
        with swap_lock:
            parked = self._parked_clients()
            taken = [
                (client, key, loop)
                for loop, (client, key) in parked.items()
                if wanted(loop, client)
            ]
            for _, _, loop in taken:
                del parked[loop]
        return taken

    def _release_parked(
        self, wanted: Callable[[EventLoop | None, Redis], bool]
    ) -> bool:
        taken = self._take_parked(wanted)
        for client, key, loop in taken:
            self._release_client(client, key, loop, keep=None)
        return bool(taken)

    def _release_client(
        self,
        old_redis: Redis | None,
        key: Hashable | None,
        old_loop: EventLoop | None,
        keep: Redis | None,
    ) -> None:
        if old_redis is None or old_redis is keep:
            return
        released = key is None or _redis_shared_clients.release(key, old_redis, self)
        if not released:
            return
        # A client built under another loop cannot be awaited from here: its sockets
        # are dropped on that loop, or from here once that loop is stopped or closed.
        if old_loop in (None, running_loop_or_none()):
            self._safe_aclose(old_redis)
        else:
            close_sync_client(old_redis, old_loop)

    def _start_the_attempt_if_the_window_is_open(self, url: str) -> None:
        if self._reconnect_gate().enter():
            self._spawn_the_attempt(url)

    def _spawn_the_attempt(self, url: str) -> None:
        # The caller holds the gate claim and the attempt releases it.
        try:
            self.register_background_user(self._attempts().stop)
            self._attempts().spawn(lambda: self._attempt_in_background(url))
        except BaseException:
            # No attempt will ever release the claim: do it here, or no caller
            # would ever enter again.
            self._reconnect_gate().leave(False)
            raise

    def _connect_inline(self, url: str) -> None:
        # The first connect and the loop-change reconnect: callers wait for the one
        # attempt, as on v4.4.0, and the ones that waited use its result.
        seen = self._connect_generation
        with self._connection_lock_here():
            recovered = self._connect_holding_the_lock(url, seen)
        if recovered:
            self._report_recovery(url)

    def _connect_holding_the_lock(self, url: str, seen: int) -> bool:
        if self._connect_generation != seen and self._is_bound_to_this_loop():
            return False
        if self._degraded:
            raise GuardRedisError(503, "Redis connection failed")
        gate = self._reconnect_gate()
        gated = self._redis is None
        if gated and not gate.enter():
            raise GuardRedisError(503, "Redis connection failed")
        try:
            self._open_connection(url)
        finally:
            recovered = gated and gate.leave(self._redis is not None)
        return recovered

    def _report_recovery(self, url: str) -> None:
        self._send_redis_event(
            event_type=EVENT_REDIS_CONNECTION,
            action_taken="connection_recovered",
            reason="Redis connection recovered after failed attempts",
            redis_url=_redact_redis_url(url),
        )

    def _is_bound_to_this_loop(self) -> bool:
        return self._client_here() is not None

    def _attempt_in_background(self, url: str) -> None:
        gate = self._reconnect_gate()
        recovered = False
        try:
            with in_app_scope(app_scope_of(self.config)):
                with self._connection_lock_here():
                    try:
                        self._open_connection(url)
                    except GuardRedisError:
                        pass
                    if self._closed:
                        self._discard_client()
        finally:
            recovered = gate.leave(self._redis is not None)
        if recovered:
            self._report_recovery(url)

    def _discard_if_current(self, client: Redis | None) -> bool:
        if client is None or not self._holds(client):
            # Already discarded or replaced: the usual case for the errors of the
            # requests that were in flight when the outage began.
            return False
        with self._connection_lock_here():
            if self._redis is client:
                self._discard_main_client()
                return True
            return self._release_parked(lambda _loop, held: held is client)

    def _holds(self, client: Redis) -> bool:
        return self._redis is client or any(
            held[0] is client for held in self._parked_clients().values()
        )

    def _probe_then_decide(self) -> None:
        # Holds the gate claim while it probes, so no caller connects meanwhile, and
        # never calls a connect: both locks are not reentrant.
        url = configured_redis_url(self.config)
        gate = self._reconnect_gate()
        if url is None or not gate.enter():
            self._degraded = True
            return
        try:
            answered = redis_answers_within_the_deadline(url)
        except BaseException:
            self._degraded = True
            gate.leave(False)
            raise
        if answered:
            gate.leave(True)
            return
        self._degraded = True
        self._spawn_the_attempt(url)

    def _degrade_on_outage(self, client: Redis | None, error: Exception) -> None:
        # D-291. A refusal is cheap to find out about: drop the client and the next
        # caller connects (v4.4.0). A timeout is a possible black hole: drop it, ask
        # once whether Redis answers, and only a silent one degrades the manager.
        error_type = type(error)
        if error_type is RedisConnectionError:
            self._discard_if_current(client)
        elif error_type is RedisTimeoutError and self._discard_if_current(client):
            self._probe_then_decide()

    def _connection_lock_here(self) -> threading.Lock:
        locks: ConnectionLocks = vars(self).setdefault(
            "_connection_locks", ConnectionLocks()
        )
        return locks.here()

    def _attempts(self) -> RedisAttemptSlot:
        slot: RedisAttemptSlot = vars(self).setdefault(
            "_redis_attempt_slot", RedisAttemptSlot()
        )
        return slot

    def _forget_the_parents_attempts(self) -> None:
        gate = vars(self).get("_reconnect_gate_of_this_manager")
        if gate is not None:
            gate.reset_after_fork()
        vars(self).pop("_connection_locks", None)
        vars(self).pop("_client_swap_lock", None)
        vars(self).pop("_redis_attempt_slot", None)
