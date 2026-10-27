from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from collections.abc import AsyncIterator, Callable, Hashable, Sequence
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import TYPE_CHECKING, NoReturn, TypeGuard

from guard_core._redis_enablement import configured_redis_url, redis_is_configured
from guard_core._redis_exceptions import (
    NoScriptError,
    RedisConnectionError,
)
from guard_core.core.events.event_types import (
    EVENT_REDIS_CONNECTION,
    EVENT_REDIS_ERROR,
)
from guard_core.exceptions import GuardRedisError
from guard_core.handlers import _redis_handler_support as redis_types
from guard_core.handlers import _redis_shared_clients
from guard_core.handlers._dynamic_rule_persistence import (
    BAN_FLOORS_NAMESPACE,
    DYNAMIC_RULES_REDIS_NAMESPACE,
    OWNED_BANS_KEY,
)
from guard_core.handlers._redis_ban_strike import RedisBanStrikeMixin
from guard_core.handlers._redis_handler_support import (
    _redact_redis_url,
)
from guard_core.handlers._redis_handler_support import (
    _unparseable_redis_url as _unparseable_redis_url,
)
from guard_core.handlers._redis_lean import lean_command, lean_evalsha, reply_counts
from guard_core.models import SecurityConfig
from guard_core.scripts.ban_write_lua import (
    EXTEND_ONLY_BAN_WRITE_SCRIPT,
    PURGE_OWNED_BAN_SCRIPT,
)
from guard_core.scripts.detection_strikes_lua import (
    FORGET_DETECTION_STRIKES_SCRIPT,
    READ_DETECTION_CATEGORIES_SCRIPT,
    RECORD_DETECTION_STRIKES_SCRIPT,
)
from guard_core.scripts.rule_hit_index_lua import SUM_INDEXED_WINDOW_HITS_SCRIPT
from guard_core.scripts.sliding_window_lua import (
    SLIDING_WINDOW_HIT_REFUSAL_SCRIPT,
    SLIDING_WINDOW_HIT_SCRIPT,
)

if TYPE_CHECKING:
    from redis.asyncio import Redis


_REDIS_HANDLER_NAME = "redis"
_DEFAULT_POOL_SIZE = _redis_shared_clients.DEFAULT_POOL_SIZE
_SCAN_BATCH = 500


def _build_redis_client(
    url: str, max_connections: int, pool_timeout: float, **connection_kwargs: object
) -> Redis:
    from redis.asyncio import Redis

    from guard_core.handlers._redis_fast_pool import FastPathConnectionPool

    pool = FastPathConnectionPool.from_url(
        url,
        max_connections=max_connections,
        timeout=pool_timeout,
        decode_responses=True,
        **connection_kwargs,
    )
    return Redis.from_pool(pool)


_SLIDING_WINDOW_SHA = hashlib.sha1(
    SLIDING_WINDOW_HIT_SCRIPT.encode(), usedforsecurity=False
).hexdigest()
_SLIDING_WINDOW_REFUSAL_SHA = hashlib.sha1(
    SLIDING_WINDOW_HIT_REFUSAL_SCRIPT.encode(), usedforsecurity=False
).hexdigest()
_RECORD_DETECTION_STRIKES_SHA = hashlib.sha1(
    RECORD_DETECTION_STRIKES_SCRIPT.encode(), usedforsecurity=False
).hexdigest()
_READ_DETECTION_CATEGORIES_SHA = hashlib.sha1(
    READ_DETECTION_CATEGORIES_SCRIPT.encode(), usedforsecurity=False
).hexdigest()
_FORGET_DETECTION_STRIKES_SHA = hashlib.sha1(
    FORGET_DETECTION_STRIKES_SCRIPT.encode(), usedforsecurity=False
).hexdigest()
_EXTEND_ONLY_BAN_WRITE_SHA = hashlib.sha1(
    EXTEND_ONLY_BAN_WRITE_SCRIPT.encode(), usedforsecurity=False
).hexdigest()
_PURGE_OWNED_BAN_SHA = hashlib.sha1(
    PURGE_OWNED_BAN_SCRIPT.encode(), usedforsecurity=False
).hexdigest()
_DETECTION_NAMESPACE = "detection"
_SUM_INDEXED_WINDOW_HITS_SHA = hashlib.sha1(
    SUM_INDEXED_WINDOW_HITS_SCRIPT.encode(), usedforsecurity=False
).hexdigest()


class RedisManager(RedisBanStrikeMixin):
    _instance = None
    _redis: Redis | None = None
    _pool_key: Hashable | None = None
    _registered = False
    _connection_lock = asyncio.Lock()
    _closed = False
    config: SecurityConfig
    logger: logging.Logger
    agent_handler: redis_types.EventSink | None = None

    def __new__(cls: type[RedisManager], config: SecurityConfig) -> RedisManager:
        manager = _redis_shared_clients.existing_manager(config, cls)
        if manager is None:
            manager = super().__new__(cls)
            manager.logger = logging.getLogger("guard_core.handlers.redis")
            manager.agent_handler = None
            manager.config = config
            manager._registered = True
            _redis_shared_clients.register_manager(config, manager, cls)
        manager._closed = False
        cls._instance = manager
        return manager

    async def initialize_agent(self, agent_handler: redis_types.EventSink) -> None:
        self.agent_handler = agent_handler

    async def _send_redis_event(
        self, event_type: str, action_taken: str, reason: str, **kwargs: object
    ) -> None:
        if not self.agent_handler:
            return

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address="system",
                action_taken=action_taken,
                reason=reason,
                handler_name=_REDIS_HANDLER_NAME,
                metadata=kwargs,
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send Redis event to agent: {e}")

    def _connection_kwargs(
        self, config: SecurityConfig | None = None
    ) -> dict[str, object]:
        """Connection tuning passed to ``Redis.from_url``.

        Without bounded timeouts a partitioned Redis blocks every request that
        touches it indefinitely, so these default to non-None. Any value already
        encoded in ``redis_url`` query params still wins (redis-py applies URL
        params last), so this only sets a floor.
        """
        return _redis_shared_clients.connection_kwargs_of(
            config if config is not None else self.config
        )

    async def _safe_aclose(self, client: Redis) -> None:
        try:
            await client.aclose()
        except Exception as e:
            self.logger.warning(f"Failed to close a Redis client: {e}")

    async def _discard_client(self) -> None:
        old_redis, self._redis = self._redis, None
        key, self._pool_key = self._pool_key, None
        if old_redis is None:
            return
        if key is None or _redis_shared_clients.release(key, old_redis, self):
            await self._safe_aclose(old_redis)

    def _mark_most_recently_initialized(self) -> None:
        if self._registered:
            type(self)._instance = self

    async def initialize(self) -> None:
        config = self.config
        url = configured_redis_url(config)
        if url is None:
            if config.enable_redis:
                self.logger.warning("Redis URL is None, skipping connection")
            async with self._connection_lock:
                await self._discard_client()
            return

        self._closed = False

        async with self._connection_lock:
            await self._discard_client()

            new_redis: Redis | None = None
            key: Hashable | None = None
            shared = False
            try:
                new_redis, key, scope, shared = _redis_shared_clients.open_client(
                    self, url, config, _build_redis_client, _DEFAULT_POOL_SIZE
                )
                if new_redis is not None:
                    await new_redis.ping()
                    if not shared:
                        new_redis = await _redis_shared_clients.register_client(
                            self, new_redis, key, scope
                        )
                        shared = True
                    self._redis = new_redis
                    self._pool_key = key
                    self._mark_most_recently_initialized()
                    self.logger.info("Redis connection established")

                    await self._send_redis_event(
                        event_type=EVENT_REDIS_CONNECTION,
                        action_taken="connection_established",
                        reason="Redis connection successfully established",
                        redis_url=_redact_redis_url(url),
                    )

            except Exception as e:
                self.logger.error(f"Redis connection failed: {str(e)}")

                await self._send_redis_event(
                    event_type=EVENT_REDIS_ERROR,
                    action_taken="connection_failed",
                    reason=f"Redis connection failed: {str(e)}",
                    redis_url=_redact_redis_url(url),
                    error_type="connection_error",
                )

                if new_redis is not None and (
                    not shared
                    or key is None
                    or _redis_shared_clients.release(key, new_redis, self)
                ):
                    await self._safe_aclose(new_redis)
                self._redis = None
                raise GuardRedisError(503, "Redis connection failed") from e

    async def close(self) -> None:
        if self._redis:
            await self._discard_client()
            self.logger.info("Redis connection closed")

            await self._send_redis_event(
                event_type=EVENT_REDIS_CONNECTION,
                action_taken="connection_closed",
                reason="Redis connection closed gracefully",
            )
        self._closed = True

    @asynccontextmanager
    async def get_connection(self) -> AsyncIterator[Redis]:
        try:
            if self._closed:
                await self._send_redis_event(
                    event_type=EVENT_REDIS_ERROR,
                    action_taken="operation_failed",
                    reason="Attempted to use closed Redis connection",
                    error_type="connection_closed",
                )
                raise GuardRedisError(503, "Redis connection closed")

            if not self._redis:
                await self.initialize()

            if self._redis is None:
                await self._send_redis_event(
                    event_type=EVENT_REDIS_ERROR,
                    action_taken="operation_failed",
                    reason="Redis connection is None after initialization",
                    error_type="initialization_failed",
                )
                raise GuardRedisError(503, "Redis connection failed")

            yield self._redis
        except (RedisConnectionError, AttributeError) as e:
            self.logger.error(f"Redis operation failed: {str(e)}")

            await self._send_redis_event(
                event_type=EVENT_REDIS_ERROR,
                action_taken="operation_failed",
                reason=f"Redis operation failed: {str(e)}",
                error_type="operation_error",
            )

            raise GuardRedisError(503, "Redis connection failed") from e

    async def _raise_operation_failure(self, error: Exception, name: str) -> NoReturn:
        self.logger.error(f"Redis operation failed: {str(error)}")

        await self._send_redis_event(
            event_type=EVENT_REDIS_ERROR,
            action_taken="safe_operation_failed",
            reason=f"Redis safe operation failed: {str(error)}",
            error_type="safe_operation_error",
            function_name=name,
        )

        raise GuardRedisError(503, "Redis operation failed") from error

    async def safe_operation(
        self,
        func: redis_types.RedisOperation[
            redis_types.OperationParams, redis_types.OperationResult
        ],
        *args: redis_types.OperationParams.args,
        **kwargs: redis_types.OperationParams.kwargs,
    ) -> redis_types.OperationResult | None:
        if not redis_is_configured(self.config):
            return None

        try:
            async with self.get_connection() as conn:
                return await func(conn, *args, **kwargs)
        except Exception as e:
            await self._raise_operation_failure(e, getattr(func, "__name__", "unknown"))

    async def get_key(self, namespace: str, key: str) -> str | None:
        if not redis_is_configured(self.config):
            return None

        async def _get(conn: Redis) -> str | None:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            value: str | None = await conn.get(full_key)
            return value

        return await self.safe_operation(_get)

    async def get_many(self, pairs: Sequence[tuple[str, str]]) -> list[str | None]:
        if not redis_is_configured(self.config):
            return [None] * len(pairs)

        prefix = self.config.redis_prefix
        try:
            async with self.get_connection() as conn:
                return list(
                    await lean_command(
                        conn,
                        "MGET",
                        *[f"{prefix}{namespace}:{key}" for namespace, key in pairs],
                    )
                )
        except Exception as e:
            await self._raise_operation_failure(e, "_get_many")

    async def set_key(
        self,
        namespace: str,
        key: str,
        value: redis_types.RedisValue,
        ttl: int | None = None,
    ) -> bool | None:
        if not redis_is_configured(self.config):
            return None

        async def _set(conn: Redis) -> bool:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            if ttl:
                return bool(await conn.set(full_key, value, ex=ttl))
            return bool(await conn.set(full_key, value))

        result = await self.safe_operation(_set)
        return False if result is None else bool(result)

    async def set_key_if_absent(
        self,
        namespace: str,
        key: str,
        value: redis_types.RedisValue,
        ttl: int | None = None,
    ) -> bool:
        if not redis_is_configured(self.config):
            return False

        async def _set(conn: Redis) -> bool:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            return bool(await conn.set(full_key, value, nx=True, ex=ttl))

        return bool(await self.safe_operation(_set))

    async def incr(
        self, namespace: str, key: str, ttl: int | None = None
    ) -> int | None:
        # NOTE: when redis_retries > 0, the client-level retry can re-send this
        # non-idempotent INCR if a reply is lost after the server already
        # committed it, over-counting by one. For the counter use here that
        # fails closed (mildly over-restrictive, self-heals next window). A
        # caller needing exactly-once semantics should not build on incr().
        if not redis_is_configured(self.config):
            return None

        async def _incr(conn: Redis) -> int:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            async with conn.pipeline() as pipe:
                await pipe.incr(full_key)
                if ttl:
                    await pipe.expire(full_key, ttl)
                result = await pipe.execute()
                return int(result[0]) if result else 0

        result = await self.safe_operation(_incr)
        return int(result) if result is not None else 0

    async def write_atomically(
        self,
        *,
        sets: Sequence[tuple[str, str, redis_types.RedisValue, int | None]] = (),
        deletes: Sequence[tuple[str, str]] = (),
        increment: tuple[str, str] | None = None,
    ) -> None:
        """Apply sets, deletes and one counter increment in one MULTI/EXEC.

        Either all of it lands or none of it does, and no other command runs in
        between, so a worker that sees the new counter sees the writes.
        """
        if not redis_is_configured(self.config):
            return

        async def _write(conn: Redis) -> None:
            prefix = self.config.redis_prefix
            async with conn.pipeline(transaction=True) as pipe:
                for namespace, key, value, ttl in sets:
                    await pipe.set(f"{prefix}{namespace}:{key}", value, ex=ttl)
                for namespace, key in deletes:
                    await pipe.delete(f"{prefix}{namespace}:{key}")
                if increment is not None:
                    await pipe.incr(f"{prefix}{increment[0]}:{increment[1]}")
                await pipe.execute()

        await self.safe_operation(_write)

    async def write_ban_extending_only(
        self,
        namespace: str,
        key: str,
        expiry: str,
        duration: int,
        *,
        version: tuple[str, str],
        advance_version: bool = False,
        rule_owned: bool = False,
    ) -> float:
        """Write the ban only when it outlasts the live one, in one script call,
        and return the expiry the ban key holds afterwards. The value is the
        expiry text the caller formatted once. advance_version increments the
        version counter in the same call when the ban was written; rule_owned
        records the ban in the owned set with that same text as its score."""
        if not redis_is_configured(self.config):
            return float(expiry)

        prefix = self.config.redis_prefix
        keys = [
            f"{prefix}{namespace}:{key}",
            f"{prefix}{version[0]}:{version[1]}",
            self._owned_bans_key(),
            self.ban_floor_key(namespace, key),
        ]
        args: list[str | int] = [
            expiry,
            duration,
            "1" if advance_version else "0",
            "1" if rule_owned else "0",
        ]

        async def _write(conn: Redis) -> float:
            try:
                answer = await conn.evalsha(
                    _EXTEND_ONLY_BAN_WRITE_SHA, len(keys), *keys, *args
                )
            except NoScriptError:
                await conn.script_load(EXTEND_ONLY_BAN_WRITE_SCRIPT)
                answer = await conn.evalsha(
                    _EXTEND_ONLY_BAN_WRITE_SHA, len(keys), *keys, *args
                )
            return float(answer[1])

        expiry_held = await self.safe_operation(_write)
        if expiry_held is None:
            raise TypeError(redis_types.NO_OPERATION_RESULT)
        return expiry_held

    def ban_floor_key(self, namespace: str, key: str) -> str:
        return f"{self.config.redis_prefix}{BAN_FLOORS_NAMESPACE}:{namespace}:{key}"

    async def owned_ban_members(self) -> list[str]:
        """The full ban keys the dynamic rules own, as the owned set holds them."""
        if not redis_is_configured(self.config):
            return []

        async def _members(conn: Redis) -> list[str]:
            return [str(m) for m in await conn.zrange(self._owned_bans_key(), 0, -1)]

        return list(await self.safe_operation(_members) or [])

    async def owned_ban_state(
        self, namespace: str, key: str
    ) -> tuple[float | None, float | None]:
        """The expiry the rule wrote for one ban (its score in the owned set)
        and the expiry the ban holds now, read in one round trip."""
        if not redis_is_configured(self.config):
            return None, None
        prefix = self.config.redis_prefix
        member = f"{prefix}{namespace}:{key}"

        async def _state(conn: Redis) -> tuple[float | None, float | None]:
            async with conn.pipeline(transaction=False) as pipe:
                await pipe.zscore(self._owned_bans_key(), member)
                await pipe.get(member)
                score, stored = await pipe.execute()
            return (
                None if score is None else float(score),
                None if not stored else float(stored),
            )

        state: tuple[float | None, float | None] | None = await self.safe_operation(
            _state
        )
        return state if state is not None else (None, None)

    async def purge_owned_ban(self, member: str) -> int:
        """Lift one owned ban down to its floor, or off, in one script call, and
        drop it from the owned set. Returns 0 (already gone), 1 (deleted),
        2 (rewritten to its floor) or 3 (a longer ban replaced it, left alone)."""
        prefix = self.config.redis_prefix
        floor = f"{prefix}{BAN_FLOORS_NAMESPACE}:{member[len(prefix) :]}"
        keys = [member, self._owned_bans_key(), floor]

        async def _purge(conn: Redis) -> int:
            try:
                return int(await conn.evalsha(_PURGE_OWNED_BAN_SHA, len(keys), *keys))
            except NoScriptError:
                await conn.script_load(PURGE_OWNED_BAN_SCRIPT)
                return int(await conn.evalsha(_PURGE_OWNED_BAN_SHA, len(keys), *keys))

        return int(await self.safe_operation(_purge) or 0)

    def _owned_bans_key(self) -> str:
        return (
            f"{self.config.redis_prefix}{DYNAMIC_RULES_REDIS_NAMESPACE}:"
            f"{OWNED_BANS_KEY}"
        )

    async def disown_ban(self, namespace: str, key: str) -> None:
        """Remove the ban from the set of bans a dynamic rule owns."""
        if not redis_is_configured(self.config):
            return

        member = f"{self.config.redis_prefix}{namespace}:{key}"

        async def _disown(conn: Redis) -> None:
            await conn.zrem(self._owned_bans_key(), member)

        await self.safe_operation(_disown)

    async def record_sliding_window_hit(
        self,
        namespace: str,
        key: str,
        timestamp: float,
        window_start: float,
        ttl: int,
        *,
        index: tuple[str, int] | None = None,
        index_refused: list[bool] | None = None,
    ) -> int:
        """Record one hit and return the key's count in the window. index
        (index key, max members) also adds the key to that set of the namespace,
        with the key's ttl, in the same round trip. At the index's cap the key is
        not indexed (the hit still counts here); when index_refused is given, True
        is appended to it in that case."""
        if not redis_is_configured(self.config):
            return 0

        prefix = f"{self.config.redis_prefix}{namespace}:"
        keys = [f"{prefix}{key}"]
        args: list[str | int] = [
            repr(timestamp),
            uuid.uuid4().hex,
            repr(window_start),
            ttl,
        ]
        if index is not None:
            index_key, max_members = index
            keys.append(f"{prefix}{index_key}")
            args.append(max_members)
        script, sha = (
            (SLIDING_WINDOW_HIT_SCRIPT, _SLIDING_WINDOW_SHA)
            if index_refused is None
            else (SLIDING_WINDOW_HIT_REFUSAL_SCRIPT, _SLIDING_WINDOW_REFUSAL_SHA)
        )

        async def _record(conn: Redis) -> int:
            try:
                count = await conn.evalsha(sha, len(keys), *keys, *args)
            except NoScriptError:
                await conn.script_load(script)
                count = await conn.evalsha(sha, len(keys), *keys, *args)
            if index_refused is not None and count.__class__ is list:
                count = count[0]
                index_refused.append(True)
            return int(count)

        result = await self.safe_operation(_record)
        return int(result) if result is not None else 0

    def _detection_strike_keys(self, client_ip: str) -> tuple[str, str, str]:
        prefix = f"{self.config.redis_prefix}{_DETECTION_NAMESPACE}:"
        total = f"{prefix}strikes:{client_ip}"
        return f"{prefix}strikes_index:{client_ip}", total, f"{total}|"

    def detection_correlation_keys(self, client_ip: str) -> list[str]:
        """The keys a script reads to learn whether the IP has strikes: the
        category index and the shared rate-limit violations."""
        index, _, _ = self._detection_strike_keys(client_ip)
        return [index, self._rate_limit_violations_key(client_ip)]

    def _rate_limit_violations_key(self, client_ip: str) -> str:
        return f"{self.config.redis_prefix}rate_limit:violations:{client_ip}"

    async def record_detection_strikes(
        self,
        client_ip: str,
        categories: Sequence[str],
        timestamp: float,
        window_start: float,
        ttl: int,
        cap: int,
    ) -> tuple[int, int, dict[str, int]]:
        """Record one detection strike for the IP under every category in one
        round trip. Returns the IP's total over all categories, the IP's shared
        rate-limit violations in the window, and the count of each category of
        this strike, all inside the sliding window and each key bounded to cap
        members."""
        if not redis_is_configured(self.config):
            return 0, 0, {}

        index, total, category_prefix = self._detection_strike_keys(client_ip)
        keys = [
            index,
            total,
            self._rate_limit_violations_key(client_ip),
            *(f"{category_prefix}{name}" for name in categories),
        ]
        args: list[str | int] = [
            repr(timestamp),
            uuid.uuid4().hex,
            repr(window_start),
            ttl,
            cap,
        ]

        async def _record(conn: Redis) -> list[int]:
            counts = await lean_evalsha(
                conn,
                RECORD_DETECTION_STRIKES_SCRIPT,
                _RECORD_DETECTION_STRIKES_SHA,
                keys,
                args,
            )
            return reply_counts(counts)

        result = await self.safe_operation(_record)
        if result is None:
            raise TypeError(redis_types.NO_OPERATION_RESULT)
        return result[0], result[1], dict(zip(categories, result[2:], strict=True))

    async def read_detection_categories(
        self, client_ip: str, window_start: float
    ) -> list[str]:
        """The detection categories (and "rate_limit" for shared rate-limit
        violations) the IP has strikes in since window_start, in one round trip."""
        if not redis_is_configured(self.config):
            return []

        _, _, category_prefix = self._detection_strike_keys(client_ip)
        keys = self.detection_correlation_keys(client_ip)

        async def _read(conn: Redis) -> list[str]:
            try:
                found = await conn.evalsha(
                    _READ_DETECTION_CATEGORIES_SHA, 2, *keys, repr(window_start)
                )
            except NoScriptError:
                await conn.script_load(READ_DETECTION_CATEGORIES_SCRIPT)
                found = await conn.evalsha(
                    _READ_DETECTION_CATEGORIES_SHA, 2, *keys, repr(window_start)
                )
            return [str(name).removeprefix(category_prefix) for name in found]

        categories = await self.safe_operation(_read)
        if categories is None:
            raise TypeError(redis_types.NO_OPERATION_RESULT)
        return sorted(categories)

    async def forget_detection_strikes(self, client_ip: str) -> None:
        """Delete every detection strike counter of the IP in one round trip."""
        if not redis_is_configured(self.config):
            return

        index, total, _ = self._detection_strike_keys(client_ip)

        async def _forget(conn: Redis) -> None:
            try:
                await conn.evalsha(_FORGET_DETECTION_STRIKES_SHA, 2, index, total)
            except NoScriptError:
                await conn.script_load(FORGET_DETECTION_STRIKES_SCRIPT)
                await conn.evalsha(_FORGET_DETECTION_STRIKES_SHA, 2, index, total)

        await self.safe_operation(_forget)

    async def count_sliding_window_hits(
        self, namespace: str, key: str, window_start: float
    ) -> int:
        """The key's hits at or after window_start, without recording one."""
        if not redis_is_configured(self.config):
            return 0

        full_key = f"{self.config.redis_prefix}{namespace}:{key}"

        async def _count(conn: Redis) -> int:
            return int(await conn.zcount(full_key, window_start, "+inf"))

        result = await self.safe_operation(_count)
        return int(result) if result is not None else 0

    async def sum_indexed_window_hits(
        self, namespace: str, index_key: str, window_start: float
    ) -> int:
        """Sum the hits at or after window_start over every key in the index set,
        dropping members whose key has expired, in one round trip."""
        if not redis_is_configured(self.config):
            return 0

        full_index = f"{self.config.redis_prefix}{namespace}:{index_key}"

        async def _sum(conn: Redis) -> int:
            try:
                total = await conn.evalsha(
                    _SUM_INDEXED_WINDOW_HITS_SHA, 1, full_index, repr(window_start)
                )
            except NoScriptError:
                await conn.script_load(SUM_INDEXED_WINDOW_HITS_SCRIPT)
                total = await conn.evalsha(
                    _SUM_INDEXED_WINDOW_HITS_SHA, 1, full_index, repr(window_start)
                )
            return int(total)

        result = await self.safe_operation(_sum)
        return int(result) if result is not None else 0

    async def exists(self, namespace: str, key: str) -> bool | None:
        if not redis_is_configured(self.config):
            return None

        async def _exists(conn: Redis) -> bool:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            return bool(await conn.exists(full_key))

        result = await self.safe_operation(_exists)
        return False if result is None else bool(result)

    async def delete(self, namespace: str, key: str) -> int | None:
        if not redis_is_configured(self.config):
            return None

        async def _delete(conn: Redis) -> int:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            delete_result = await conn.delete(full_key)
            return int(delete_result) if delete_result is not None else 0

        result = await self.safe_operation(_delete)
        return int(result) if result is not None else 0

    async def keys(self, pattern: str) -> list[str] | None:
        if not redis_is_configured(self.config):
            return None

        async def _keys(conn: Redis) -> list[str]:
            full_pattern = f"{self.config.redis_prefix}{pattern}"
            found = [
                str(key)
                async for key in conn.scan_iter(match=full_pattern, count=_SCAN_BATCH)
            ]
            return list(dict.fromkeys(found))

        result = await self.safe_operation(_keys)
        return result if result is not None else []

    async def delete_pattern(self, pattern: str) -> int | None:
        if not redis_is_configured(self.config):
            return None

        async def _delete_pattern(conn: Redis) -> int:
            return await scan_unlink(conn, f"{self.config.redis_prefix}{pattern}")

        result = await self.safe_operation(_delete_pattern)
        return int(result) if result is not None else 0


class RedisHandlerBase(RedisManager):
    """Public base for a custom Redis handler: RedisManager's own implementation.

    WHAT: every method of ``RedisHandlerProtocol`` as ``RedisManager`` has it, so
    the Lua scripts and the key layout exist once. Unlike ``RedisManager`` it is
    not a singleton: each instance keeps its own ``config`` and client.
    WHEN: subclass it to plug your own connection handling (a custom pool, a
    cluster client, a wrapper that traces calls) into the engine.
    HOW: override ``initialize`` and ``get_connection``; ``get_connection`` must
    yield a redis-py-compatible asyncio client (the engine runs pipelines,
    ``evalsha``, ``scan_iter``, ``zrange`` and ``execute_command("MGET")`` on
    it). Set ``config`` before the first call. Override any other method to
    change it.
    """

    logger = logging.getLogger("guard_core.handlers.redis")

    def __new__(cls, *args: object, **kwargs: object) -> RedisHandlerBase:
        return object.__new__(cls)

    def __init__(self, config: SecurityConfig) -> None:
        self.config = config


async def scan_unlink(
    conn: Redis, full_pattern: str, select: Callable[[str], bool] | None = None
) -> int:
    """Delete every key matching full_pattern (and select, when given): one SCAN
    cursor walk, UNLINK in batches. Never KEYS, which walks the whole keyspace in
    one blocking command."""
    removed = 0
    batch: list[str] = []
    async for key in conn.scan_iter(match=full_pattern, count=_SCAN_BATCH):
        if select is not None and not select(key):
            continue
        batch.append(key)
        if len(batch) >= _SCAN_BATCH:
            removed += int(await conn.unlink(*batch))
            batch.clear()
    if batch:
        removed += int(await conn.unlink(*batch))
    return removed


async def scan_unlink_through_new_client(url: str, full_pattern: str) -> int:
    """scan_unlink on a short-lived client of its own, for a caller that holds no
    handler of the Redis it must clear (never the RedisManager singleton)."""
    from redis.asyncio import Redis

    client = Redis.from_url(url, decode_responses=True)
    try:
        return await scan_unlink(client, full_pattern)
    finally:
        await client.aclose()


def is_connected_redis_manager(handler: object) -> TypeGuard[RedisManager]:
    return isinstance(handler, RedisManager) and handler._redis is not None


redis_handler = RedisManager
