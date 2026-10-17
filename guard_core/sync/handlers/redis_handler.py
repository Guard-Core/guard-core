import hashlib
import logging
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from redis import Redis
from redis.backoff import ExponentialBackoff
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import NoScriptError
from redis.exceptions import TimeoutError as RedisTimeoutError
from redis.retry import Retry

from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.scripts.sliding_window_lua import SLIDING_WINDOW_HIT_SCRIPT
from guard_core.sync.core.events.event_types import (
    EVENT_REDIS_CONNECTION,
    EVENT_REDIS_ERROR,
)


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
_SLIDING_WINDOW_SHA = hashlib.sha1(
    SLIDING_WINDOW_HIT_SCRIPT.encode(), usedforsecurity=False
).hexdigest()


class RedisManager:
    _instance = None
    _redis: Redis | None = None
    _connection_lock = threading.Lock()
    _closed = False
    config: SecurityConfig
    logger: logging.Logger
    agent_handler: Any = None

    def __new__(cls: type["RedisManager"], config: SecurityConfig) -> "RedisManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.logger = logging.getLogger("guard_core.sync.handlers.redis")
            cls._instance.agent_handler = None
        cls._instance.config = config
        cls._instance._closed = False
        return cls._instance

    def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    def _send_redis_event(
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
            self.agent_handler.send_event(event)
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
        if cfg.redis_max_connections is not None:
            kwargs["max_connections"] = cfg.redis_max_connections
        if cfg.redis_retries > 0:
            kwargs["retry"] = Retry(ExponentialBackoff(), cfg.redis_retries)
            kwargs["retry_on_error"] = [RedisConnectionError, RedisTimeoutError]
        return kwargs

    def _safe_aclose(self, client: Redis) -> None:
        try:
            client.close()
        except Exception as e:
            self.logger.warning(f"Failed to close a Redis client: {e}")

    def _discard_client(self) -> None:
        if self._redis is not None:
            old_redis, self._redis = self._redis, None
            self._safe_aclose(old_redis)

    def initialize(self) -> None:
        config = self.config
        if not config.enable_redis:
            with self._connection_lock:
                self._discard_client()
            return

        self._closed = False

        with self._connection_lock:
            self._discard_client()

            new_redis: Redis | None = None
            try:
                if config.redis_url is not None:
                    new_redis = Redis.from_url(
                        config.redis_url,
                        decode_responses=True,
                        **self._connection_kwargs(config),
                    )
                    if new_redis is not None:
                        new_redis.ping()
                        self._redis = new_redis
                        self.logger.info("Redis connection established")

                        self._send_redis_event(
                            event_type=EVENT_REDIS_CONNECTION,
                            action_taken="connection_established",
                            reason="Redis connection successfully established",
                            redis_url=_redact_redis_url(config.redis_url),
                        )
                else:
                    self.logger.warning("Redis URL is None, skipping connection")

            except Exception as e:
                self.logger.error(f"Redis connection failed: {str(e)}")

                self._send_redis_event(
                    event_type=EVENT_REDIS_ERROR,
                    action_taken="connection_failed",
                    reason=f"Redis connection failed: {str(e)}",
                    redis_url=_redact_redis_url(config.redis_url),
                    error_type="connection_error",
                )

                if new_redis is not None:
                    self._safe_aclose(new_redis)
                self._redis = None
                raise GuardRedisError(503, "Redis connection failed") from e

    def close(self) -> None:
        if self._redis:
            self._discard_client()
            self.logger.info("Redis connection closed")

            self._send_redis_event(
                event_type=EVENT_REDIS_CONNECTION,
                action_taken="connection_closed",
                reason="Redis connection closed gracefully",
            )
        self._closed = True

    @contextmanager
    def get_connection(self) -> Iterator[Redis]:
        try:
            if self._closed:
                self._send_redis_event(
                    event_type=EVENT_REDIS_ERROR,
                    action_taken="operation_failed",
                    reason="Attempted to use closed Redis connection",
                    error_type="connection_closed",
                )
                raise GuardRedisError(503, "Redis connection closed")

            if not self._redis:
                self.initialize()

            if self._redis is None:
                self._send_redis_event(
                    event_type=EVENT_REDIS_ERROR,
                    action_taken="operation_failed",
                    reason="Redis connection is None after initialization",
                    error_type="initialization_failed",
                )
                raise GuardRedisError(503, "Redis connection failed")

            yield self._redis
        except (RedisConnectionError, AttributeError) as e:
            self.logger.error(f"Redis operation failed: {str(e)}")

            self._send_redis_event(
                event_type=EVENT_REDIS_ERROR,
                action_taken="operation_failed",
                reason=f"Redis operation failed: {str(e)}",
                error_type="operation_error",
            )

            raise GuardRedisError(503, "Redis connection failed") from e

    def safe_operation(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        if not self.config.enable_redis:
            return None

        try:
            with self.get_connection() as conn:
                return func(conn, *args, **kwargs)
        except Exception as e:
            self.logger.error(f"Redis operation failed: {str(e)}")

            self._send_redis_event(
                event_type=EVENT_REDIS_ERROR,
                action_taken="safe_operation_failed",
                reason=f"Redis safe operation failed: {str(e)}",
                error_type="safe_operation_error",
                function_name=getattr(func, "__name__", "unknown"),
            )

            raise GuardRedisError(503, "Redis operation failed") from e

    def get_key(self, namespace: str, key: str) -> Any:
        if not self.config.enable_redis:
            return None

        def _get(conn: Redis) -> Any:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            return conn.get(full_key)

        return self.safe_operation(_get)

    def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool | None:
        if not self.config.enable_redis:
            return None

        def _set(conn: Redis) -> bool:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            if ttl:
                return bool(conn.set(full_key, value, ex=ttl))
            return bool(conn.set(full_key, value))

        result = self.safe_operation(_set)
        return False if result is None else bool(result)

    def incr(self, namespace: str, key: str, ttl: int | None = None) -> int | None:
        # NOTE: when redis_retries > 0, the client-level retry can re-send this
        # non-idempotent INCR if a reply is lost after the server already
        # committed it, over-counting by one. For the counter use here that
        # fails closed (mildly over-restrictive, self-heals next window). A
        # caller needing exactly-once semantics should not build on incr().
        if not self.config.enable_redis:
            return None

        def _incr(conn: Redis) -> int:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            with conn.pipeline() as pipe:
                pipe.incr(full_key)
                if ttl:
                    pipe.expire(full_key, ttl)
                result = pipe.execute()
                return int(result[0]) if result else 0

        result = self.safe_operation(_incr)
        return int(result) if result is not None else 0

    def record_sliding_window_hit(
        self,
        namespace: str,
        key: str,
        timestamp: float,
        window_start: float,
        ttl: int,
        *,
        extra_window: tuple[str, float, int] | None = None,
    ) -> int:
        """Record one hit and return the key's count in the window. extra_window
        (key, window_start, ttl) records the same hit in a second key of the
        namespace in the same round trip; its count is not returned."""
        if not self.config.enable_redis:
            return 0

        prefix = f"{self.config.redis_prefix}{namespace}:"
        keys = [f"{prefix}{key}"]
        args: list[Any] = [repr(timestamp), uuid.uuid4().hex, repr(window_start), ttl]
        if extra_window is not None:
            extra_key, extra_start, extra_ttl = extra_window
            keys.append(f"{prefix}{extra_key}")
            args += [repr(extra_start), extra_ttl]

        def _record(conn: Redis) -> int:
            try:
                count = conn.evalsha(_SLIDING_WINDOW_SHA, len(keys), *keys, *args)
            except NoScriptError:
                conn.script_load(SLIDING_WINDOW_HIT_SCRIPT)
                count = conn.evalsha(_SLIDING_WINDOW_SHA, len(keys), *keys, *args)
            return int(count)

        result = self.safe_operation(_record)
        return int(result) if result is not None else 0

    def count_sliding_window_hits(
        self, namespace: str, key: str, window_start: float
    ) -> int:
        if not self.config.enable_redis:
            return 0

        def _count(conn: Redis) -> int:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            return int(conn.zcount(full_key, window_start, "+inf"))

        result = self.safe_operation(_count)
        return int(result) if result is not None else 0

    def exists(self, namespace: str, key: str) -> bool | None:
        if not self.config.enable_redis:
            return None

        def _exists(conn: Redis) -> bool:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            return bool(conn.exists(full_key))

        result = self.safe_operation(_exists)
        return False if result is None else bool(result)

    def delete(self, namespace: str, key: str) -> int | None:
        if not self.config.enable_redis:
            return None

        def _delete(conn: Redis) -> int:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            delete_result = conn.delete(full_key)
            return int(delete_result) if delete_result is not None else 0

        result = self.safe_operation(_delete)
        return int(result) if result is not None else 0

    def keys(self, pattern: str) -> list[str] | None:
        if not self.config.enable_redis:
            return None

        def _keys(conn: Redis) -> list[str]:
            full_pattern = f"{self.config.redis_prefix}{pattern}"
            keys = conn.keys(full_pattern)
            return [str(k) for k in keys] if keys else []

        result = self.safe_operation(_keys)
        return result if result is not None else []

    def delete_pattern(self, pattern: str) -> int | None:
        if not self.config.enable_redis:
            return None

        def _delete_pattern(conn: Redis) -> int:
            full_pattern = f"{self.config.redis_prefix}{pattern}"
            keys = conn.keys(full_pattern)
            if not keys:
                return 0
            result = conn.delete(*keys)
            return int(result) if result is not None else 0

        result = self.safe_operation(_delete_pattern)
        return int(result) if result is not None else 0


redis_handler = RedisManager
