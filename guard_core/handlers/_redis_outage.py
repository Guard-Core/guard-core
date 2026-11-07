from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Hashable
from threading import Lock
from typing import TYPE_CHECKING

from guard_core._redis_abandoned_client import abandon_client
from guard_core._redis_client_loop import EventLoop, running_loop_or_none
from guard_core._redis_exceptions import RedisConnectionError, RedisTimeoutError
from guard_core._utils.app_scope import app_scope_of, in_app_scope
from guard_core.core.events.event_types import EVENT_REDIS_CONNECTION
from guard_core.exceptions import GuardRedisError
from guard_core.handlers import _redis_shared_clients
from guard_core.handlers._redis_attempt import ConnectionLocks, RedisAttemptSlot
from guard_core.handlers._redis_handler_support import _redact_redis_url
from guard_core.handlers._redis_reconnect_gate import RedisReconnectGate

if TYPE_CHECKING:
    import logging

    from redis.asyncio import Redis

    from guard_core.models import SecurityConfig


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
    config: SecurityConfig
    logger: logging.Logger

    if TYPE_CHECKING:

        async def _open_connection(self, url: str) -> None: ...
        async def _discard_client(self) -> None: ...
        async def _safe_aclose(self, client: Redis) -> None: ...
        async def _send_redis_event(
            self, event_type: str, action_taken: str, reason: str, **kwargs: object
        ) -> None: ...
        def _reconnect_gate(self) -> RedisReconnectGate: ...
        def register_background_user(
            self, stop: Callable[[], Awaitable[None]]
        ) -> None: ...

    def _swap_client(
        self,
        new_redis: Redis | None,
        new_key: Hashable | None,
        new_loop: EventLoop | None,
    ) -> tuple[Redis | None, Hashable | None, EventLoop | None]:
        # No await inside: loops on two threads each swap whole, so a client one
        # thread bound is always the "old" one of the next swap and gets released.
        swap_lock: Lock = vars(self).setdefault("_client_swap_lock", Lock())
        with swap_lock:
            old = (self._redis, self._pool_key, self._client_loop)
            self._redis, self._pool_key, self._client_loop = (
                new_redis,
                new_key,
                new_loop,
            )
        return old

    async def _release_client(
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
            await self._safe_aclose(old_redis)
        else:
            abandon_client(old_redis, old_loop)

    def _start_the_attempt_if_the_window_is_open(self, url: str) -> None:
        gate = self._reconnect_gate()
        if gate.enter():
            try:
                self.register_background_user(self._attempts().stop)
                self._attempts().spawn(lambda: self._attempt_in_background(url))
            except BaseException:
                # No attempt will ever release the claim: do it here, or no caller
                # would ever enter again.
                gate.leave(False)
                raise

    async def _connect_inline(self, url: str) -> None:
        # The first connect and the loop-change reconnect: callers wait for the one
        # attempt, as on v4.4.0, and the ones that waited use its result.
        seen = self._connect_generation
        async with self._connection_lock_here():
            recovered = await self._connect_holding_the_lock(url, seen)
        if recovered:
            await self._report_recovery(url)

    async def _connect_holding_the_lock(self, url: str, seen: int) -> bool:
        if self._connect_generation != seen and self._is_bound_to_this_loop():
            return False
        if self._degraded:
            raise GuardRedisError(503, "Redis connection failed")
        gate = self._reconnect_gate()
        gated = self._redis is None
        if gated and not gate.enter():
            raise GuardRedisError(503, "Redis connection failed")
        try:
            await self._open_connection(url)
        finally:
            recovered = gated and gate.leave(self._redis is not None)
        return recovered

    async def _report_recovery(self, url: str) -> None:
        await self._send_redis_event(
            event_type=EVENT_REDIS_CONNECTION,
            action_taken="connection_recovered",
            reason="Redis connection recovered after failed attempts",
            redis_url=_redact_redis_url(url),
        )

    def _is_bound_to_this_loop(self) -> bool:
        return self._redis is not None and (
            self._client_loop is None or self._client_loop is running_loop_or_none()
        )

    async def _attempt_in_background(self, url: str) -> None:
        gate = self._reconnect_gate()
        recovered = False
        try:
            with in_app_scope(app_scope_of(self.config)):
                async with self._connection_lock_here():
                    try:
                        await self._open_connection(url)
                    except GuardRedisError:
                        pass
                    if self._closed:
                        await self._discard_client()
        finally:
            recovered = gate.leave(self._redis is not None)
        if recovered:
            await self._report_recovery(url)

    async def _mark_degraded(self, client: Redis | None) -> None:
        if client is None or self._redis is not client:
            # Already discarded or replaced: the usual case for the errors of the
            # requests that were in flight when the outage began.
            return
        async with self._connection_lock_here():
            if client is None or self._redis is not client:
                return
            await self._discard_client()
            self._degraded = True
            gate = self._reconnect_gate()
            if gate.enter():
                gate.leave(False)

    async def _degrade_on_outage(self, client: Redis | None, error: Exception) -> None:
        if type(error) in (RedisConnectionError, RedisTimeoutError):
            await self._mark_degraded(client)

    def _connection_lock_here(self) -> asyncio.Lock:
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
