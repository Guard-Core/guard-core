import asyncio
import hashlib
import logging
import uuid
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from redis.asyncio import BlockingConnectionPool, Redis
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialBackoff
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import NoScriptError
from redis.exceptions import TimeoutError as RedisTimeoutError

from guard_core.core.events.event_types import (
    EVENT_REDIS_CONNECTION,
    EVENT_REDIS_ERROR,
)
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.scripts.detection_strikes_lua import (
    FORGET_DETECTION_STRIKES_SCRIPT,
    READ_DETECTION_CATEGORIES_SCRIPT,
    RECORD_DETECTION_STRIKES_SCRIPT,
)
from guard_core.scripts.rule_hit_index_lua import SUM_INDEXED_WINDOW_HITS_SCRIPT
from guard_core.scripts.sliding_window_lua import SLIDING_WINDOW_HIT_SCRIPT


def _unparseable_redis_url(url: str, scheme: str = "") -> str:
    scheme = scheme or url.partition("://")[0]
    return f"{scheme}://<unparseable>" if scheme and "://" in url else "<unparseable>"


def _redact_redis_url(url: str | None) -> str | None:
    if url is None:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return _unparseable_redis_url(url)
    if not parts.netloc:
        return url
    try:
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return _unparseable_redis_url(url, parts.scheme)
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


_REDIS_HANDLER_NAME = "redis"
_DEFAULT_POOL_SIZE = 100
_SCAN_BATCH = 500


def _build_redis_client(
    url: str, max_connections: int, pool_timeout: float, **connection_kwargs: Any
) -> Redis:
    pool = BlockingConnectionPool.from_url(
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
_RECORD_DETECTION_STRIKES_SHA = hashlib.sha1(
    RECORD_DETECTION_STRIKES_SCRIPT.encode(), usedforsecurity=False
).hexdigest()
_READ_DETECTION_CATEGORIES_SHA = hashlib.sha1(
    READ_DETECTION_CATEGORIES_SCRIPT.encode(), usedforsecurity=False
).hexdigest()
_FORGET_DETECTION_STRIKES_SHA = hashlib.sha1(
    FORGET_DETECTION_STRIKES_SCRIPT.encode(), usedforsecurity=False
).hexdigest()
_DETECTION_NAMESPACE = "detection"
_SUM_INDEXED_WINDOW_HITS_SHA = hashlib.sha1(
    SUM_INDEXED_WINDOW_HITS_SCRIPT.encode(), usedforsecurity=False
).hexdigest()


class RedisManager:
    _instance = None
    _redis: Redis | None = None
    _connection_lock = asyncio.Lock()
    _closed = False
    config: SecurityConfig
    logger: logging.Logger
    agent_handler: Any = None

    def __new__(cls: type["RedisManager"], config: SecurityConfig) -> "RedisManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.logger = logging.getLogger("guard_core.handlers.redis")
            cls._instance.agent_handler = None
        cls._instance.config = config
        cls._instance._closed = False
        return cls._instance

    async def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    async def _send_redis_event(
        self, event_type: str, action_taken: str, reason: str, **kwargs: Any
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
    ) -> dict[str, Any]:
        """Connection tuning passed to ``Redis.from_url``.

        Without bounded timeouts a partitioned Redis blocks every request that
        touches it indefinitely, so these default to non-None. Any value already
        encoded in ``redis_url`` query params still wins (redis-py applies URL
        params last), so this only sets a floor.
        """
        cfg = config if config is not None else self.config
        kwargs: dict[str, Any] = {
            "socket_connect_timeout": cfg.redis_socket_connect_timeout,
            "socket_timeout": cfg.redis_socket_timeout,
            "health_check_interval": cfg.redis_health_check_interval,
        }
        if cfg.redis_retries > 0:
            kwargs["retry"] = Retry(ExponentialBackoff(), cfg.redis_retries)
            kwargs["retry_on_error"] = [RedisConnectionError, RedisTimeoutError]
        return kwargs

    async def _safe_aclose(self, client: Redis) -> None:
        try:
            await client.aclose()
        except Exception as e:
            self.logger.warning(f"Failed to close a Redis client: {e}")

    async def _discard_client(self) -> None:
        if self._redis is not None:
            old_redis, self._redis = self._redis, None
            await self._safe_aclose(old_redis)

    async def initialize(self) -> None:
        config = self.config
        if not config.enable_redis:
            async with self._connection_lock:
                await self._discard_client()
            return

        self._closed = False

        async with self._connection_lock:
            await self._discard_client()

            new_redis: Redis | None = None
            try:
                if config.redis_url is not None:
                    new_redis = _build_redis_client(
                        config.redis_url,
                        config.redis_max_connections or _DEFAULT_POOL_SIZE,
                        config.redis_pool_timeout,
                        **self._connection_kwargs(config),
                    )
                    if new_redis is not None:
                        await new_redis.ping()
                        self._redis = new_redis
                        self.logger.info("Redis connection established")

                        await self._send_redis_event(
                            event_type=EVENT_REDIS_CONNECTION,
                            action_taken="connection_established",
                            reason="Redis connection successfully established",
                            redis_url=_redact_redis_url(config.redis_url),
                        )
                else:
                    self.logger.warning("Redis URL is None, skipping connection")

            except Exception as e:
                self.logger.error(f"Redis connection failed: {str(e)}")

                await self._send_redis_event(
                    event_type=EVENT_REDIS_ERROR,
                    action_taken="connection_failed",
                    reason=f"Redis connection failed: {str(e)}",
                    redis_url=_redact_redis_url(config.redis_url),
                    error_type="connection_error",
                )

                if new_redis is not None:
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

    async def safe_operation(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        if not self.config.enable_redis:
            return None

        try:
            async with self.get_connection() as conn:
                return await func(conn, *args, **kwargs)
        except Exception as e:
            self.logger.error(f"Redis operation failed: {str(e)}")

            await self._send_redis_event(
                event_type=EVENT_REDIS_ERROR,
                action_taken="safe_operation_failed",
                reason=f"Redis safe operation failed: {str(e)}",
                error_type="safe_operation_error",
                function_name=getattr(func, "__name__", "unknown"),
            )

            raise GuardRedisError(503, "Redis operation failed") from e

    async def get_key(self, namespace: str, key: str) -> Any:
        if not self.config.enable_redis:
            return None

        async def _get(conn: Redis) -> Any:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            return await conn.get(full_key)

        return await self.safe_operation(_get)

    async def get_many(self, pairs: Sequence[tuple[str, str]]) -> list[Any]:
        if not self.config.enable_redis:
            return [None] * len(pairs)

        async def _get_many(conn: Redis) -> list[Any]:
            prefix = self.config.redis_prefix
            return list(
                await conn.mget(
                    [f"{prefix}{namespace}:{key}" for namespace, key in pairs]
                )
            )

        return list(await self.safe_operation(_get_many))

    async def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool | None:
        if not self.config.enable_redis:
            return None

        async def _set(conn: Redis) -> bool:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            if ttl:
                return bool(await conn.set(full_key, value, ex=ttl))
            return bool(await conn.set(full_key, value))

        result = await self.safe_operation(_set)
        return False if result is None else bool(result)

    async def set_key_if_absent(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool:
        if not self.config.enable_redis:
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
        if not self.config.enable_redis:
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

    async def record_sliding_window_hit(
        self,
        namespace: str,
        key: str,
        timestamp: float,
        window_start: float,
        ttl: int,
        *,
        index: tuple[str, int] | None = None,
    ) -> int:
        """Record one hit and return the key's count in the window. index
        (index key, max members) also adds the key to that set of the namespace,
        with the key's ttl, in the same round trip."""
        if not self.config.enable_redis:
            return 0

        prefix = f"{self.config.redis_prefix}{namespace}:"
        keys = [f"{prefix}{key}"]
        args: list[Any] = [repr(timestamp), uuid.uuid4().hex, repr(window_start), ttl]
        if index is not None:
            index_key, max_members = index
            keys.append(f"{prefix}{index_key}")
            args.append(max_members)

        async def _record(conn: Redis) -> int:
            try:
                count = await conn.evalsha(_SLIDING_WINDOW_SHA, len(keys), *keys, *args)
            except NoScriptError:
                await conn.script_load(SLIDING_WINDOW_HIT_SCRIPT)
                count = await conn.evalsha(_SLIDING_WINDOW_SHA, len(keys), *keys, *args)
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
        if not self.config.enable_redis:
            return 0, 0, {}

        index, total, category_prefix = self._detection_strike_keys(client_ip)
        keys = [
            index,
            total,
            self._rate_limit_violations_key(client_ip),
            *(f"{category_prefix}{name}" for name in categories),
        ]
        args: list[Any] = [
            repr(timestamp),
            uuid.uuid4().hex,
            repr(window_start),
            ttl,
            cap,
        ]

        async def _record(conn: Redis) -> list[int]:
            try:
                counts = await conn.evalsha(
                    _RECORD_DETECTION_STRIKES_SHA, len(keys), *keys, *args
                )
            except NoScriptError:
                await conn.script_load(RECORD_DETECTION_STRIKES_SCRIPT)
                counts = await conn.evalsha(
                    _RECORD_DETECTION_STRIKES_SHA, len(keys), *keys, *args
                )
            return [int(count) for count in counts]

        result = await self.safe_operation(_record)
        return result[0], result[1], dict(zip(categories, result[2:], strict=True))

    async def read_detection_categories(
        self, client_ip: str, window_start: float
    ) -> list[str]:
        """The detection categories (and "rate_limit" for shared rate-limit
        violations) the IP has strikes in since window_start, in one round trip."""
        if not self.config.enable_redis:
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

        categories: list[str] = await self.safe_operation(_read)
        return sorted(categories)

    async def forget_detection_strikes(self, client_ip: str) -> None:
        """Delete every detection strike counter of the IP in one round trip."""
        if not self.config.enable_redis:
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
        if not self.config.enable_redis:
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
        if not self.config.enable_redis:
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
        if not self.config.enable_redis:
            return None

        async def _exists(conn: Redis) -> bool:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            return bool(await conn.exists(full_key))

        result = await self.safe_operation(_exists)
        return False if result is None else bool(result)

    async def delete(self, namespace: str, key: str) -> int | None:
        if not self.config.enable_redis:
            return None

        async def _delete(conn: Redis) -> int:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            delete_result = await conn.delete(full_key)
            return int(delete_result) if delete_result is not None else 0

        result = await self.safe_operation(_delete)
        return int(result) if result is not None else 0

    async def keys(self, pattern: str) -> list[str] | None:
        if not self.config.enable_redis:
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
        if not self.config.enable_redis:
            return None

        async def _delete_pattern(conn: Redis) -> int:
            return await scan_unlink(conn, f"{self.config.redis_prefix}{pattern}")

        result = await self.safe_operation(_delete_pattern)
        return int(result) if result is not None else 0


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
    client = Redis.from_url(url, decode_responses=True)
    try:
        return await scan_unlink(client, full_pattern)
    finally:
        await client.aclose()


def is_connected_redis_manager(handler: Any) -> bool:
    return isinstance(handler, RedisManager) and handler._redis is not None


redis_handler = RedisManager
