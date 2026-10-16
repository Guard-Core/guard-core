import ipaddress
import logging
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any, Optional

from redis.exceptions import NoScriptError, RedisError

from guard_core._utils.identity_hash import _hash_identity_segment
from guard_core._utils.lru_store import _lru_pop_or_create
from guard_core._utils.request_logging import redact_endpoint_for_display
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.scripts.rate_lua import RATE_LIMIT_SCRIPT
from guard_core.utils import log_activity

_by_ip_logger = logging.getLogger("guard_core.handlers.ratelimit")
_RATE_LIMIT_HANDLER_NAME = "rate_limit"
_by_ip_request_timestamps: defaultdict[str, deque[float]] = defaultdict(deque)
_by_ip_autoban_counts: dict[str, Any] = {}
_MAX_TRACKED_RATE_LIMIT_KEYS = 10_000
_redis_fail_open_warned = False


def _warn_redis_fail_open_in_memory_fallback() -> None:
    global _redis_fail_open_warned
    if _redis_fail_open_warned:
        return
    _redis_fail_open_warned = True
    _by_ip_logger.warning(
        "Redis unavailable for rate limiting; using the in-memory window "
        "(redis_fail_open=True); with several workers the effective limit "
        "is workers x rate_limit"
    )


def _resolve_redis_rate_limit_failure(
    error: Exception,
    redis_fail_open: bool,
    logger: logging.Logger,
    context: str,
) -> None:
    if redis_fail_open:
        _warn_redis_fail_open_in_memory_fallback()
        return
    logger.error(f"{context}: {error}")
    raise GuardRedisError(503, "Redis rate limiting unavailable") from error


async def _redis_request_count(
    redis_handler: Any,
    logger: logging.Logger,
    client_ip: str,
    current_time: float,
    window_start: float,
    rate_limit_window: int,
    rate_limit: int,
    rate_limit_script_sha: str | None,
    on_script_reloaded: Callable[[], Awaitable[None]] | None = None,
    endpoint_path: str = "",
    redis_fail_open: bool = False,
) -> tuple[int | None, str | None]:
    if not redis_handler:
        return None, rate_limit_script_sha

    rate_key = (
        f"rate:{client_ip}:{_hash_identity_segment(endpoint_path)}"
        if endpoint_path
        else f"rate:{client_ip}"
    )
    key_name = f"{redis_handler.config.redis_prefix}rate_limit:{rate_key}"

    try:
        if rate_limit_script_sha:
            async with redis_handler.get_connection() as conn:
                try:
                    count = await conn.evalsha(
                        rate_limit_script_sha,
                        1,
                        key_name,
                        current_time,
                        rate_limit_window,
                        rate_limit,
                    )
                except NoScriptError:
                    rate_limit_script_sha = await conn.script_load(RATE_LIMIT_SCRIPT)
                    logger.info("Rate limit Lua script reloaded after NOSCRIPT")
                    if on_script_reloaded is not None:
                        await on_script_reloaded()
                    count = await conn.evalsha(
                        rate_limit_script_sha,
                        1,
                        key_name,
                        current_time,
                        rate_limit_window,
                        rate_limit,
                    )
            return int(count), rate_limit_script_sha
        else:
            async with redis_handler.get_connection() as conn:
                pipeline = conn.pipeline()
                pipeline.zadd(key_name, {str(current_time): current_time})
                pipeline.zremrangebyscore(key_name, 0, window_start)
                pipeline.zcard(key_name)
                pipeline.expire(key_name, rate_limit_window * 2)
                results = await pipeline.execute()
                return int(results[2]), rate_limit_script_sha

    except RedisError as e:
        _resolve_redis_rate_limit_failure(
            e, redis_fail_open, logger, "Redis rate limiting error"
        )
    except Exception as e:
        _resolve_redis_rate_limit_failure(
            e, redis_fail_open, logger, "Unexpected error in rate limiting"
        )

    return None, rate_limit_script_sha


def _in_memory_request_count(
    request_timestamps: defaultdict[str, deque[float]],
    client_ip: str,
    window_start: float,
    current_time: float,
    endpoint_path: str = "",
) -> int:
    key = (
        f"{client_ip}:{_hash_identity_segment(endpoint_path)}"
        if endpoint_path
        else client_ip
    )

    timestamps = _lru_pop_or_create(
        request_timestamps, key, _MAX_TRACKED_RATE_LIMIT_KEYS, deque
    )

    while timestamps and timestamps[0] <= window_start:
        timestamps.popleft()

    request_count = len(timestamps)
    timestamps.append(current_time)
    request_timestamps[key] = timestamps

    return request_count


async def _feed_rate_limit_autoban(ip: str, config: SecurityConfig) -> None:
    """Feed a rate-limited call into the shared auto-ban engine.

    Increments a dedicated, per-process, in-memory violation counter keyed by
    ``ip`` (``_by_ip_autoban_counts`` in this module) over a sliding
    ``SUSPICIOUS_COUNT_WINDOW_SECONDS`` window, separate from and never
    merged with ``middleware.suspicious_request_counts``: the primitive has no
    middleware/request, so it cannot share that store. No-ops unless both
    ``config.enable_rate_limit_auto_ban`` and ``config.enable_ip_banning`` are
    set, and unless ``config.passive_mode`` is False. It also no-ops when ``ip``
    is already banned, short-circuiting before the counter increment, so a
    repeatedly rate-limited banned ip neither refreshes the ban TTL nor grows the
    counter. Resolution and the actual ``ban_ip`` call are delegated to the same
    pure helper the middleware auto-ban path uses, so there is one threshold
    implementation, not two.
    """
    if not (config.enable_rate_limit_auto_ban and config.enable_ip_banning):
        return
    if config.passive_mode:
        return

    from guard_core.core.checks.helpers import (
        _MAX_RETAINED_EVENTS_PER_CATEGORY,
        SUSPICIOUS_COUNT_WINDOW_SECONDS,
        _resolve_and_apply_threshold_ban,
        _WindowedCategoryCounts,
    )
    from guard_core.handlers.ipban_handler import IPBanManager

    ip_ban_manager = IPBanManager()
    if await ip_ban_manager.is_ip_banned(ip):
        return

    now = time.monotonic()
    ip_counts = _lru_pop_or_create(
        _by_ip_autoban_counts, ip, _MAX_TRACKED_RATE_LIMIT_KEYS, _WindowedCategoryCounts
    )
    ip_counts.expire_before(now - SUSPICIOUS_COUNT_WINDOW_SECONDS)
    ip_counts.record("rate_limit", now, _MAX_RETAINED_EVENTS_PER_CATEGORY)
    _by_ip_autoban_counts[ip] = ip_counts
    result = await _resolve_and_apply_threshold_ban(
        ip_counts,
        config,
        ip_ban_manager,
        ip,
        ("rate_limit",),
        "rate_limit_exceeded",
    )
    if result is not None:
        _by_ip_autoban_counts.pop(ip, None)
        _by_ip_logger.warning(
            "check_rate_limit_by_ip: auto-banned %s (rate_limit_exceeded)", ip
        )


async def check_rate_limit_by_ip(
    ip: str,
    config: SecurityConfig,
    redis_handler: Any = None,
    endpoint_path: str = "",
) -> bool:
    """Check and record a rate-limit hit for a raw IP, outside the HTTP pipeline.

    Returns True when the call is allowed (under limit), False when rate-limited.
    Every call records a hit in the sliding window, exactly like the pipeline path,
    so calling this to "just check" also consumes one slot of the budget. Does not
    construct or mutate the ``RateLimitManager`` singleton: it calls the same
    module-level counting functions the pipeline uses, against a store dedicated
    to this primitive. With ``endpoint_path=""`` (the default) the Redis key
    collapses to ``{prefix}rate_limit:rate:{ip}``, the same bucket the HTTP
    pipeline's global rate limit uses for that IP, so the two share one budget by
    design. Pass a non-empty ``endpoint_path`` (e.g. "ws") for an isolated budget,
    keyed apart from that default bucket: isolation is guaranteed by the input
    validation below, since ``ip`` must parse as a canonical IP address and
    ``endpoint_path`` can never itself contain a ``:``, the joined key can never
    collide with a different endpoint_path's bucket. The in-memory fallback is
    process-local and never shares counts with the pipeline singleton's own
    in-memory store, Redis-backed deployments do.

    When the call is rate-limited (returns False) and both
    ``config.enable_rate_limit_auto_ban`` and ``config.enable_ip_banning`` are set,
    the violation feeds the same auto-ban engine ``RateLimitCheck`` uses in the
    HTTP pipeline (``threat_ban_config["rate_limit"]`` first, then the flat
    ``auto_ban_threshold``/``auto_ban_duration``), reason ``"rate_limit_exceeded"``.
    The violation count backing that decision is a dedicated, per-process,
    in-memory counter private to this primitive: it is never merged with the
    pipeline's ``middleware.suspicious_request_counts``, so auto-ban here and
    auto-ban on the HTTP pipeline are counted independently even for the same IP.
    ``config.passive_mode`` suppresses this counting entirely, matching the
    pipeline's passive-mode behavior. Once the ip is already banned, further
    over-limit calls neither count nor re-ban nor refresh the ban TTL: the first
    threshold-crossing ban fires once and later violations short-circuit.

    Raises:
        ValueError: if ``ip`` does not parse via ``ipaddress.ip_address``, or if
            ``endpoint_path`` contains a ``:``. Validation runs before any
            counting side effect and before the ``enable_rate_limiting`` early
            return, so rejected input never records a hit and never feeds auto-ban.
        GuardRedisError: if Redis is enabled and the Redis call fails while
            ``config.redis_fail_open`` is ``False`` (the default); the caller
            decides how to handle it, since this primitive has no pipeline
            ``fail_secure`` handling to fall back on. With
            ``redis_fail_open=True``, the same failure instead falls back to the
            in-memory window and does not raise.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"check_rate_limit_by_ip: invalid ip {ip!r}") from exc
    if ":" in endpoint_path:
        safe_endpoint_path = redact_endpoint_for_display(
            endpoint_path,
            config.log_sensitive_params,
            config.log_sensitive_body_fields,
            config.log_sensitive_headers,
        )
        raise ValueError(
            f"check_rate_limit_by_ip: endpoint_path must not contain ':' "
            f"(got {safe_endpoint_path!r})"
        )

    if not config.enable_rate_limiting:
        return True

    current_time = time.time()
    window_start = current_time - config.rate_limit_window

    allowed: bool | None = None
    if config.enable_redis and redis_handler:
        count, _ = await _redis_request_count(
            redis_handler,
            _by_ip_logger,
            ip,
            current_time,
            window_start,
            config.rate_limit_window,
            config.rate_limit,
            None,
            None,
            endpoint_path,
            config.redis_fail_open,
        )
        if count is not None:
            allowed = count <= config.rate_limit

    if allowed is None:
        request_count = _in_memory_request_count(
            _by_ip_request_timestamps,
            ip,
            window_start,
            current_time,
            endpoint_path=endpoint_path,
        )
        allowed = request_count < config.rate_limit

    if not allowed:
        await _feed_rate_limit_autoban(ip, config)

    return allowed


class RateLimitManager:
    _instance: Optional["RateLimitManager"] = None
    config: SecurityConfig
    request_timestamps: defaultdict[str, deque[float]]
    logger: logging.Logger
    redis_handler: Any = None
    agent_handler: Any = None
    rate_limit_script_sha: str | None = None

    def __new__(
        cls: type["RateLimitManager"], config: SecurityConfig
    ) -> "RateLimitManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.config = config
            cls._instance.request_timestamps = defaultdict(deque)
            cls._instance.logger = logging.getLogger("guard_core.handlers.ratelimit")
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
            cls._instance.rate_limit_script_sha = None

        cls._instance.config = config
        return cls._instance

    async def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler

        if self.redis_handler and self.config.enable_redis:
            try:
                async with self.redis_handler.get_connection() as conn:
                    self.rate_limit_script_sha = await conn.script_load(
                        RATE_LIMIT_SCRIPT
                    )
                    self.logger.info("Rate limiting Lua script loaded successfully")
            except Exception as e:
                self.logger.error(f"Failed to load rate limiting Lua script: {str(e)}")

    async def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    async def _emit_script_reloaded_event(self) -> None:
        if not self.agent_handler:
            return
        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model
            from guard_core.core.events.event_types import (
                EVENT_RATE_LIMIT_SCRIPT_RELOADED,
            )

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_RATE_LIMIT_SCRIPT_RELOADED,
                ip_address="system",
                action_taken="script_reloaded",
                reason="NOSCRIPT recovery: Lua script re-cached on Redis",
                handler_name=_RATE_LIMIT_HANDLER_NAME,
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send script-reload event: {e}")

    async def _get_redis_request_count(
        self,
        client_ip: str,
        current_time: float,
        window_start: float,
        endpoint_path: str = "",
        rate_limit_window: int | None = None,
        rate_limit: int | None = None,
        redis_fail_open: bool | None = None,
    ) -> int | None:
        count, self.rate_limit_script_sha = await _redis_request_count(
            self.redis_handler,
            self.logger,
            client_ip,
            current_time,
            window_start,
            rate_limit_window or self.config.rate_limit_window,
            rate_limit if rate_limit is not None else self.config.rate_limit,
            self.rate_limit_script_sha,
            self._emit_script_reloaded_event,
            endpoint_path,
            redis_fail_open
            if redis_fail_open is not None
            else self.config.redis_fail_open,
        )
        return count

    async def _handle_rate_limit_exceeded(
        self,
        request: GuardRequest,
        client_ip: str,
        count: int,
        create_error_response: Callable[[int, str], Awaitable[GuardResponse]],
        rate_limit_window: int | None = None,
        config: SecurityConfig | None = None,
    ) -> GuardResponse:
        display_config = config or self.config
        window = rate_limit_window or display_config.rate_limit_window
        message = "Rate limit exceeded for IP:"
        detail = f"requests in {window}s window)"
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"{message} {client_ip} ({count} {detail}",
            level=display_config.log_suspicious_level,
            passive_mode=display_config.passive_mode,
            check_name="rate_limit",
            muted_check_logs=display_config.muted_check_logs,
            on_block=display_config.on_block,
            sensitive_headers=display_config.log_sensitive_headers,
            sensitive_params=display_config.log_sensitive_params,
            sensitive_body_fields=display_config.log_sensitive_body_fields,
        )

        if self.agent_handler:
            await self._send_rate_limit_event(
                request, client_ip, count, config=display_config
            )

        response = await create_error_response(
            429,
            "Too many requests",
        )
        response.headers["Retry-After"] = str(window)
        return response

    def _get_in_memory_request_count(
        self,
        client_ip: str,
        window_start: float,
        current_time: float,
        endpoint_path: str = "",
    ) -> int:
        return _in_memory_request_count(
            self.request_timestamps,
            client_ip,
            window_start,
            current_time,
            endpoint_path=endpoint_path,
        )

    async def check_rate_limit(
        self,
        request: GuardRequest,
        client_ip: str,
        create_error_response: Callable[[int, str], Awaitable[GuardResponse]],
        endpoint_path: str = "",
        rate_limit: int | None = None,
        rate_limit_window: int | None = None,
        config: SecurityConfig | None = None,
    ) -> GuardResponse | None:
        display_config = config or self.config
        if not display_config.enable_rate_limiting:
            return None

        effective_limit = (
            rate_limit if rate_limit is not None else display_config.rate_limit
        )
        effective_window = (
            rate_limit_window
            if rate_limit_window is not None
            else display_config.rate_limit_window
        )

        current_time = time.time()
        window_start = current_time - effective_window

        if display_config.enable_redis and self.redis_handler:
            count = await self._get_redis_request_count(
                client_ip,
                current_time,
                window_start,
                endpoint_path=endpoint_path,
                rate_limit_window=effective_window,
                rate_limit=effective_limit,
                redis_fail_open=display_config.redis_fail_open,
            )

            if count is not None:
                if count > effective_limit:
                    return await self._handle_rate_limit_exceeded(
                        request,
                        client_ip,
                        count,
                        create_error_response,
                        rate_limit_window=effective_window,
                        config=display_config,
                    )
                return None

        request_count = self._get_in_memory_request_count(
            client_ip, window_start, current_time, endpoint_path=endpoint_path
        )

        if request_count >= effective_limit:
            return await self._handle_rate_limit_exceeded(
                request,
                client_ip,
                request_count + 1,
                create_error_response,
                rate_limit_window=effective_window,
                config=display_config,
            )

        return None

    async def _send_rate_limit_event(
        self,
        request: GuardRequest,
        client_ip: str,
        request_count: int,
        config: SecurityConfig | None = None,
    ) -> None:
        display_config = config or self.config
        try:
            message = "Rate limit exceeded"
            details = (
                f"{request_count} requests in "
                f"{display_config.rate_limit_window}s window"
            )

            from guard_core._pydantic_plugin_mute import get_telemetry_model
            from guard_core.core.events.event_types import EVENT_RATE_LIMITED
            from guard_core.utils import get_pipeline_response_time

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_RATE_LIMITED,
                ip_address=client_ip,
                action_taken="request_blocked",
                reason=f"{message}: {details}",
                endpoint=redact_endpoint_for_display(
                    str(request.url_path),
                    display_config.log_sensitive_params,
                    display_config.log_sensitive_body_fields,
                    display_config.log_sensitive_headers,
                ),
                method=request.method,
                response_time=get_pipeline_response_time(request),
                handler_name=_RATE_LIMIT_HANDLER_NAME,
                metadata={
                    "request_count": request_count,
                    "rate_limit": display_config.rate_limit,
                    "window": display_config.rate_limit_window,
                },
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send rate limit event to agent: {e}")

    async def reset(self) -> None:
        self.request_timestamps.clear()

        if self.config.enable_redis and self.redis_handler:
            try:
                keys = await self.redis_handler.keys("rate_limit:rate:*")
                if keys and len(keys) > 0:
                    await self.redis_handler.delete_pattern("rate_limit:rate:*")
            except Exception as e:
                self.logger.error(f"Failed to reset Redis rate limits: {str(e)}")

        self.redis_handler = None
        self.agent_handler = None


rate_limit_handler = RateLimitManager
