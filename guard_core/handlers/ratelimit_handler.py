import ipaddress
import logging
import math
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, NamedTuple, Optional

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

if TYPE_CHECKING:
    from guard_core.core.checks.helpers import _WindowedCategoryCounts

_by_ip_logger = logging.getLogger("guard_core.handlers.ratelimit")
_RATE_LIMIT_HANDLER_NAME = "rate_limit"
_by_ip_request_timestamps: defaultdict[str, deque[float]] = defaultdict(deque)
_by_ip_autoban_counts: dict[str, "_WindowedCategoryCounts"] = {}
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


class RateLimitTier(NamedTuple):
    kind: str
    limit: int
    window: int
    bucket: str = ""


class RateLimitVerdict(NamedTuple):
    tier_index: int | None
    request_count: int = 0
    retry_after: int = 0


class RateLimitBlock(NamedTuple):
    tier_index: int
    request_count: int
    response: GuardResponse


_ALLOWED = RateLimitVerdict(None)
_KINDS_IN_KEY = frozenset({"endpoint", "route", "geo"})


def _tier_key(client_ip: str, tier: RateLimitTier) -> str:
    if tier.kind in _KINDS_IN_KEY:
        return f"{client_ip}:{tier.kind}:{_hash_identity_segment(tier.bucket)}"
    if tier.bucket:
        return f"{client_ip}:{_hash_identity_segment(tier.bucket)}"
    return client_ip


def _retry_after_seconds(oldest: float | None, window: int, now: float) -> int:
    if oldest is None:
        return window
    return max(1, math.ceil(oldest + window - now))


def _script_arguments(tiers: Sequence[RateLimitTier]) -> list[int]:
    return [value for tier in tiers for value in (tier.limit, tier.window)]


def _verdict_from_script_result(result: Sequence[Any]) -> RateLimitVerdict:
    tier_number, count, retry_after = (int(value) for value in result)
    if tier_number == 0:
        return _ALLOWED
    return RateLimitVerdict(tier_number - 1, count + 1, retry_after)


async def _evalsha_tiers(
    conn: Any,
    logger: logging.Logger,
    script_sha: str,
    keys: list[str],
    tiers: Sequence[RateLimitTier],
    on_script_reloaded: Callable[[], Awaitable[None]] | None,
) -> tuple[Sequence[Any], str]:
    arguments = _script_arguments(tiers)
    try:
        return await conn.evalsha(script_sha, len(keys), *keys, *arguments), script_sha
    except NoScriptError:
        script_sha = await conn.script_load(RATE_LIMIT_SCRIPT)
        logger.info("Rate limit Lua script reloaded after NOSCRIPT")
        if on_script_reloaded is not None:
            await on_script_reloaded()
        return await conn.evalsha(script_sha, len(keys), *keys, *arguments), script_sha


async def _pipeline_tiers_verdict(
    conn: Any, keys: list[str], tiers: Sequence[RateLimitTier]
) -> RateLimitVerdict:
    seconds, microseconds = await conn.time()
    now = int(seconds) + int(microseconds) / 1_000_000
    inspect = conn.pipeline()
    for key, tier in zip(keys, tiers, strict=True):
        inspect.zremrangebyscore(key, 0, now - tier.window)
        inspect.zcard(key)
        inspect.zrange(key, 0, 0, withscores=True)
    results = await inspect.execute()
    for index, tier in enumerate(tiers):
        count = int(results[index * 3 + 1])
        if count >= tier.limit:
            oldest = results[index * 3 + 2]
            oldest_hit = float(oldest[0][1]) if oldest else None
            retry_after = _retry_after_seconds(oldest_hit, tier.window, now)
            return RateLimitVerdict(index, count + 1, retry_after)
    record = conn.pipeline()
    for key, tier in zip(keys, tiers, strict=True):
        record.zadd(key, {str(now): now})
        record.expire(key, tier.window * 2)
    await record.execute()
    return _ALLOWED


async def _redis_tier_verdict(
    redis_handler: Any,
    logger: logging.Logger,
    client_ip: str,
    tiers: Sequence[RateLimitTier],
    rate_limit_script_sha: str | None,
    on_script_reloaded: Callable[[], Awaitable[None]] | None = None,
    redis_fail_open: bool = False,
) -> tuple[RateLimitVerdict | None, str | None]:
    if not redis_handler:
        return None, rate_limit_script_sha

    prefix = f"{redis_handler.config.redis_prefix}rate_limit:rate:"
    keys = [f"{prefix}{_tier_key(client_ip, tier)}" for tier in tiers]

    try:
        async with redis_handler.get_connection() as conn:
            if rate_limit_script_sha:
                result, rate_limit_script_sha = await _evalsha_tiers(
                    conn, logger, rate_limit_script_sha, keys, tiers, on_script_reloaded
                )
                return _verdict_from_script_result(result), rate_limit_script_sha
            return await _pipeline_tiers_verdict(conn, keys, tiers), None

    except RedisError as e:
        _resolve_redis_rate_limit_failure(
            e, redis_fail_open, logger, "Redis rate limiting error"
        )
    except Exception as e:
        _resolve_redis_rate_limit_failure(
            e, redis_fail_open, logger, "Unexpected error in rate limiting"
        )

    return None, rate_limit_script_sha


def _in_memory_tier_verdict(
    request_timestamps: defaultdict[str, deque[float]],
    client_ip: str,
    tiers: Sequence[RateLimitTier],
    current_time: float,
) -> RateLimitVerdict:
    windows = []
    for index, tier in enumerate(tiers):
        key = _tier_key(client_ip, tier)
        timestamps = _lru_pop_or_create(
            request_timestamps, key, _MAX_TRACKED_RATE_LIMIT_KEYS, deque
        )
        window_start = current_time - tier.window
        while timestamps and timestamps[0] <= window_start:
            timestamps.popleft()
        request_timestamps[key] = timestamps
        if len(timestamps) >= tier.limit:
            oldest = timestamps[0] if timestamps else None
            retry_after = _retry_after_seconds(oldest, tier.window, current_time)
            return RateLimitVerdict(index, len(timestamps) + 1, retry_after)
        windows.append(timestamps)
    for timestamps in windows:
        timestamps.append(current_time)
    return _ALLOWED


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

    tiers = [
        RateLimitTier("", config.rate_limit, config.rate_limit_window, endpoint_path)
    ]

    verdict: RateLimitVerdict | None = None
    if config.enable_redis and redis_handler:
        verdict, _ = await _redis_tier_verdict(
            redis_handler,
            _by_ip_logger,
            ip,
            tiers,
            None,
            None,
            config.redis_fail_open,
        )

    if verdict is None:
        verdict = _in_memory_tier_verdict(
            _by_ip_request_timestamps, ip, tiers, time.time()
        )

    allowed = verdict.tier_index is None

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

    async def _handle_rate_limit_exceeded(
        self,
        request: GuardRequest,
        client_ip: str,
        count: int,
        create_error_response: Callable[[int, str], Awaitable[GuardResponse]],
        rate_limit_window: int | None = None,
        config: SecurityConfig | None = None,
        retry_after: int | None = None,
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

        response = await create_error_response(
            429,
            "Too many requests",
        )
        response.headers["Retry-After"] = str(
            window if retry_after is None else retry_after
        )
        return response

    async def _tier_verdict(
        self,
        client_ip: str,
        tiers: Sequence[RateLimitTier],
        config: SecurityConfig,
    ) -> RateLimitVerdict:
        if config.enable_redis and self.redis_handler:
            verdict, self.rate_limit_script_sha = await _redis_tier_verdict(
                self.redis_handler,
                self.logger,
                client_ip,
                tiers,
                self.rate_limit_script_sha,
                self._emit_script_reloaded_event,
                config.redis_fail_open,
            )
            if verdict is not None:
                return verdict
        return _in_memory_tier_verdict(
            self.request_timestamps, client_ip, tiers, time.time()
        )

    async def check_rate_limit_tiers(
        self,
        request: GuardRequest,
        client_ip: str,
        create_error_response: Callable[[int, str], Awaitable[GuardResponse]],
        tiers: Sequence[RateLimitTier],
        config: SecurityConfig | None = None,
    ) -> RateLimitBlock | None:
        display_config = config or self.config
        verdict = await self._tier_verdict(client_ip, tiers, display_config)
        if verdict.tier_index is None:
            return None
        response = await self._handle_rate_limit_exceeded(
            request,
            client_ip,
            verdict.request_count,
            create_error_response,
            rate_limit_window=tiers[verdict.tier_index].window,
            config=display_config,
            retry_after=verdict.retry_after,
        )
        return RateLimitBlock(verdict.tier_index, verdict.request_count, response)

    async def report_rate_limit_block(
        self,
        request: GuardRequest,
        client_ip: str,
        block: RateLimitBlock,
        tier: RateLimitTier,
        config: SecurityConfig | None = None,
    ) -> None:
        if self.agent_handler:
            await self._send_rate_limit_event(
                request, client_ip, block.request_count, config=config, tier=tier
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

        tier = RateLimitTier(
            "endpoint" if endpoint_path else "global",
            rate_limit if rate_limit is not None else display_config.rate_limit,
            rate_limit_window
            if rate_limit_window is not None
            else display_config.rate_limit_window,
            endpoint_path,
        )
        block = await self.check_rate_limit_tiers(
            request, client_ip, create_error_response, [tier], display_config
        )
        if block is None:
            return None
        await self.report_rate_limit_block(
            request, client_ip, block, tier, display_config
        )
        return block.response

    async def _send_rate_limit_event(
        self,
        request: GuardRequest,
        client_ip: str,
        request_count: int,
        config: SecurityConfig | None = None,
        tier: RateLimitTier | None = None,
    ) -> None:
        display_config = config or self.config
        limit = tier.limit if tier else display_config.rate_limit
        window = tier.window if tier else display_config.rate_limit_window
        try:
            from guard_core.core.events.event_types import EVENT_RATE_LIMITED

            if EVENT_RATE_LIMITED in display_config.muted_event_types:
                return
            message = "Rate limit exceeded"
            details = f"{request_count} requests in {window}s window"

            from guard_core._pydantic_plugin_mute import get_telemetry_model
            from guard_core.utils import get_pipeline_response_time

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_RATE_LIMITED,
                ip_address=client_ip,
                action_taken=(
                    "logged_only" if display_config.passive_mode else "request_blocked"
                ),
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
                    "rate_limit": limit,
                    "window": window,
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
