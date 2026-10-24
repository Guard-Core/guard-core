import ipaddress
import logging
import math
import threading
import time
import weakref
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, NamedTuple

from guard_core._redis_enablement import configured_redis_url, redis_is_configured
from guard_core._redis_exceptions import NoScriptError, RedisError
from guard_core._tracking_caps import (
    _MAX_TRACKED_RATE_LIMIT_KEYS as _MAX_TRACKED_RATE_LIMIT_KEYS,
)
from guard_core._utils.identity_hash import _hash_identity_segment
from guard_core._utils.ip_extraction import _client_identity
from guard_core._utils.lru_store import DEFAULT_MAX_TRACKED_KEYS, _lru_pop_or_create
from guard_core._utils.request_logging import redact_endpoint_for_display
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.redis_handler import scan_unlink_through_new_client
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.scripts.rate_lua import RATE_LIMIT_SCRIPT
from guard_core.utils import _canonicalize_ip, _ip_in_list, log_activity

if TYPE_CHECKING:
    from guard_core.core.checks.helpers import _WindowedCategoryCounts

_by_ip_logger = logging.getLogger("guard_core.handlers.ratelimit")
_RATE_LIMIT_HANDLER_NAME = "rate_limit"
_by_ip_request_timestamps: defaultdict[str, deque[float]] = defaultdict(deque)
_by_ip_autoban_counts: dict[str, "_WindowedCategoryCounts"] = {}
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
_VIOLATIONS_NAMESPACE = "rate_limit"
_RATE_WINDOWS_PATTERN = "rate_limit:rate:*"
_VIOLATIONS_PATTERN = "rate_limit:violations:*"
_KINDS_IN_KEY = frozenset({"endpoint", "route", "geo"})


def _by_ip_window_identity(ip: str, prefix_length: int) -> str:
    return _client_identity(ip, prefix_length) if ":" in ip else ip


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
    max_tracked_keys: int = DEFAULT_MAX_TRACKED_KEYS,
) -> RateLimitVerdict:
    windows = []
    for index, tier in enumerate(tiers):
        key = _tier_key(client_ip, tier)
        timestamps = _lru_pop_or_create(
            request_timestamps, key, max_tracked_keys, deque
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


def _violations_key(client_ip: str) -> str:
    return f"violations:{client_ip}"


async def record_shared_violation(redis_handler: Any, client_ip: str) -> int:
    from guard_core.core.checks.helpers import SUSPICIOUS_COUNT_WINDOW_SECONDS

    now = time.time()
    count: int = await redis_handler.record_sliding_window_hit(
        _VIOLATIONS_NAMESPACE,
        _violations_key(client_ip),
        now,
        now - SUSPICIOUS_COUNT_WINDOW_SECONDS,
        SUSPICIOUS_COUNT_WINDOW_SECONDS,
    )
    return count


async def forget_shared_violations(redis_handler: Any, client_ip: str) -> None:
    await redis_handler.delete(_VIOLATIONS_NAMESPACE, _violations_key(client_ip))


def forget_by_ip_strikes(client_ip: str) -> None:
    _by_ip_autoban_counts.pop(client_ip, None)


def clear_by_ip_strikes() -> None:
    _by_ip_autoban_counts.clear()


def clear_by_ip_request_windows() -> None:
    _by_ip_request_timestamps.clear()


def forget_by_ip_strikes_inside(covers: Callable[[str], bool]) -> None:
    for client_ip in tuple(_by_ip_autoban_counts):
        if covers(client_ip):
            del _by_ip_autoban_counts[client_ip]


async def _shared_primitive_counts(
    ip: str, config: SecurityConfig, redis_handler: Any
) -> dict[str, int] | None:
    if not (redis_is_configured(config) and redis_handler):
        return None
    try:
        return {"rate_limit": await record_shared_violation(redis_handler, ip)}
    except Exception as error:
        _by_ip_logger.warning(
            "Shared rate-limit violation counter unavailable, counting this "
            "violation in this process only: %s",
            error,
        )
        return None


async def _feed_rate_limit_autoban(
    ip: str, config: SecurityConfig, redis_handler: Any = None
) -> None:
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
    counter. With Redis enabled the decision uses the Redis violation counter the
    pipeline path shares across workers instead, and a landed ban clears it.
    Resolution and the actual ``ban_ip`` call are delegated to the same pure helper
    the middleware auto-ban path uses, so there is one threshold implementation,
    not two.
    """
    if not (config.enable_rate_limit_auto_ban and config.enable_ip_banning):
        return
    if config.passive_mode:
        return

    from guard_core.core.checks.helpers import (
        SUSPICIOUS_COUNT_WINDOW_SECONDS,
        _resolve_and_apply_threshold_ban,
        _retained_strike_cap,
        _WindowedCategoryCounts,
    )
    from guard_core.handlers.ipban_handler import IPBanManager, ip_ban_manager_for

    ip_ban_manager = ip_ban_manager_for(config, unbound=IPBanManager())
    if await ip_ban_manager._is_ip_banned_under(ip, config):
        return

    identity = _by_ip_window_identity(ip, config.ipv6_prefix_length)
    now = time.monotonic()
    ip_counts = _lru_pop_or_create(
        _by_ip_autoban_counts,
        identity,
        config.ban_counters_max_tracked_ips,
        _WindowedCategoryCounts,
    )
    ip_counts.expire_before(now - SUSPICIOUS_COUNT_WINDOW_SECONDS)
    ip_counts.record("rate_limit", now, _retained_strike_cap(config))
    _by_ip_autoban_counts[identity] = ip_counts
    shared = await _shared_primitive_counts(identity, config, redis_handler)
    result = await _resolve_and_apply_threshold_ban(
        ip_counts if shared is None else shared,
        config,
        ip_ban_manager,
        identity,
        ("rate_limit",),
        "rate_limit_exceeded",
    )
    if result is not None:
        _by_ip_autoban_counts.pop(identity, None)
        if shared is not None:
            await forget_shared_violations(redis_handler, identity)
        _by_ip_logger.warning(
            "check_rate_limit_by_ip: auto-banned %s (rate_limit_exceeded)", ip
        )


async def _report_by_ip_block(
    ip: str,
    config: SecurityConfig,
    request_count: int,
    tier: RateLimitTier,
    agent_handler: Any,
) -> None:
    reason = (
        f"Rate limit exceeded for IP: {ip} "
        f"({request_count} requests in {tier.window}s window)"
    )
    if config.log_suspicious_level and "rate_limit" not in config.muted_check_logs:
        _by_ip_logger.log(getattr(logging, config.log_suspicious_level), reason)
    if agent_handler is None:
        return
    await _send_by_ip_event(ip, config, reason, request_count, tier, agent_handler)


async def _send_by_ip_event(
    ip: str,
    config: SecurityConfig,
    reason: str,
    request_count: int,
    tier: RateLimitTier,
    agent_handler: Any,
) -> None:
    try:
        from guard_core._pydantic_plugin_mute import get_telemetry_model
        from guard_core.core.events.event_types import EVENT_RATE_LIMITED

        if EVENT_RATE_LIMITED in config.muted_event_types:
            return
        SecurityEvent = get_telemetry_model("SecurityEvent")
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=EVENT_RATE_LIMITED,
            ip_address=ip,
            action_taken="logged_only" if config.passive_mode else "request_blocked",
            reason=reason,
            endpoint=redact_endpoint_for_display(
                tier.bucket,
                config.log_sensitive_params,
                config.log_sensitive_body_fields,
                config.log_sensitive_headers,
            )
            or None,
            handler_name=_RATE_LIMIT_HANDLER_NAME,
            metadata={
                "request_count": request_count,
                "rate_limit": tier.limit,
                "window": tier.window,
            },
        )
        await agent_handler.send_event(event)
    except Exception as e:
        _by_ip_logger.error(f"Failed to send rate limit event to agent: {e}")


async def check_rate_limit_by_ip(
    ip: str,
    config: SecurityConfig,
    redis_handler: Any = None,
    endpoint_path: str = "",
    agent_handler: Any = None,
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

    ``ip`` is canonicalized first (every spelling of one IPv6 address, and an
    IPv4-mapped address and its IPv4 form, share one budget), and an address in
    ``config.exempt_ips`` is never limited. ``config.whitelist`` grants access
    only, so a whitelisted address is still limited. A blocked call is logged like
    the pipeline logs a block (``log_suspicious_level``, silenced by
    ``muted_check_logs``) and sends one ``rate_limited`` event with the limit and
    window it hit, ``logged_only`` in passive mode and skipped when
    ``rate_limited`` is in ``muted_event_types``. The event goes to
    ``agent_handler`` when given, else to the agent of ``redis_handler``; with
    neither there is no event.

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

    ip = _canonicalize_ip(ip)
    if _ip_in_list(ipaddress.ip_address(ip), ip, config.exempt_ips):
        return True

    tier = RateLimitTier("", config.rate_limit, config.rate_limit_window, endpoint_path)
    tiers = [tier]
    window_identity = _by_ip_window_identity(ip, config.ipv6_prefix_length)

    verdict: RateLimitVerdict | None = None
    if redis_is_configured(config) and redis_handler:
        verdict, _ = await _redis_tier_verdict(
            redis_handler,
            _by_ip_logger,
            window_identity,
            tiers,
            None,
            None,
            config.redis_fail_open,
        )

    if verdict is None:
        verdict = _in_memory_tier_verdict(
            _by_ip_request_timestamps,
            window_identity,
            tiers,
            time.time(),
            config.rate_limit_max_tracked_keys,
        )

    allowed = verdict.tier_index is None

    if not allowed:
        agent = agent_handler or getattr(redis_handler, "agent_handler", None)
        await _report_by_ip_block(ip, config, verdict.request_count, tier, agent)
        await _feed_rate_limit_autoban(ip, config, redis_handler)

    return allowed


_managers: weakref.WeakValueDictionary[tuple[type, int], "RateLimitManager"] = (
    weakref.WeakValueDictionary()
)
_managers_lock = threading.RLock()


def _configs_equal(first: SecurityConfig, second: SecurityConfig) -> bool:
    try:
        return bool(first == second)
    except Exception:
        return False


class RateLimitManager:
    config: SecurityConfig
    request_timestamps: defaultdict[str, deque[float]]
    logger: logging.Logger
    redis_handler: Any = None
    agent_handler: Any = None
    rate_limit_script_sha: str | None = None
    bound_to_app: bool = False

    def __new__(
        cls: type["RateLimitManager"], config: SecurityConfig
    ) -> "RateLimitManager":
        with _managers_lock:
            existing = _managers.get((cls, id(config)))
            if existing is not None:
                return existing
            instance = cls._build(config)
            _managers[(cls, id(config))] = instance
            return instance

    @classmethod
    def _build(cls, config: SecurityConfig) -> "RateLimitManager":
        instance = super().__new__(cls)
        instance.config = config
        instance.request_timestamps = defaultdict(deque)
        instance.logger = logging.getLogger("guard_core.handlers.ratelimit")
        instance.redis_handler = None
        instance.agent_handler = None
        instance.rate_limit_script_sha = None
        return instance

    def mark_bound_to_app(self) -> None:
        self.bound_to_app = True

    async def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler

        if self.redis_handler and redis_is_configured(self.config):
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
        window_identity: str | None = None,
    ) -> RateLimitVerdict:
        identity = window_identity or (
            _client_identity(client_ip, config.ipv6_prefix_length)
            if ":" in client_ip
            else client_ip
        )
        if redis_is_configured(config) and self.redis_handler:
            verdict, self.rate_limit_script_sha = await _redis_tier_verdict(
                self.redis_handler,
                self.logger,
                identity,
                tiers,
                self.rate_limit_script_sha,
                self._emit_script_reloaded_event,
                config.redis_fail_open,
            )
            if verdict is not None:
                return verdict
        return _in_memory_tier_verdict(
            self.request_timestamps,
            identity,
            tiers,
            time.time(),
            config.rate_limit_max_tracked_keys,
        )

    async def check_rate_limit_tiers(
        self,
        request: GuardRequest,
        client_ip: str,
        create_error_response: Callable[[int, str], Awaitable[GuardResponse]],
        tiers: Sequence[RateLimitTier],
        config: SecurityConfig | None = None,
        window_identity: str | None = None,
    ) -> RateLimitBlock | None:
        display_config = config or self.config
        verdict = await self._tier_verdict(
            client_ip, tiers, display_config, window_identity
        )
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
        attribution: dict[str, Any] | None = None,
    ) -> None:
        if self.agent_handler:
            attributed = {"attribution": attribution} if attribution else {}
            await self._send_rate_limit_event(
                request,
                client_ip,
                block.request_count,
                config=config,
                tier=tier,
                **attributed,
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
        attribution: dict[str, Any] | None = None,
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
                    **(attribution or {}),
                },
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send rate limit event to agent: {e}")

    def _guarded_apps_to_reset(self) -> list["RateLimitManager"]:
        if self.bound_to_app:
            return [self]
        with _managers_lock:
            equal = [
                manager
                for manager in _managers.values()
                if manager is not self
                and manager.bound_to_app
                and _configs_equal(manager.config, self.config)
            ]
        if equal:
            self.logger.warning(
                "reset() was called on a config object no guarded app was built "
                "with; resetting the %d guarded app(s) built with an equal "
                "config: %s",
                len(equal),
                ", ".join(f"config {id(manager.config):#x}" for manager in equal),
            )
        return equal

    async def _clear_redis_state(
        self, apps: list["RateLimitManager"], patterns: list[str]
    ) -> bool:
        handler = next(
            (
                app.redis_handler
                for app in (self, *apps)
                if redis_is_configured(app.config) and app.redis_handler
            ),
            None,
        )
        try:
            if handler is not None:
                for pattern in patterns:
                    await handler.delete_pattern(pattern)
                return True
            url = configured_redis_url(self.config)
            if url is not None:
                for pattern in patterns:
                    await scan_unlink_through_new_client(
                        url, f"{self.config.redis_prefix}{pattern}"
                    )
                return True
        except Exception as e:
            self.logger.error(f"Failed to reset Redis rate limits: {str(e)}")
        return False

    def _process_state_to_clear(self) -> list[str]:
        from guard_core.core.checks._strike_forget import has_category_strikes

        parts = []
        if self.request_timestamps:
            parts.append("this config object's own request windows")
        if _by_ip_request_timestamps:
            parts.append("the by-IP primitive's request windows")
        if _by_ip_autoban_counts or has_category_strikes("rate_limit"):
            parts.append("the process-wide rate-limit strikes")
        return parts

    async def reset(self) -> None:
        apps = self._guarded_apps_to_reset()
        cleared = self._process_state_to_clear()
        self.request_timestamps.clear()
        for app in apps:
            app.request_timestamps.clear()
        clear_by_ip_request_windows()
        redis_cleared = await self._clear_redis_state(
            apps, [_RATE_WINDOWS_PATTERN, _VIOLATIONS_PATTERN]
        )
        if redis_cleared:
            cleared.append("the Redis rate-limit windows and strikes")
        if not apps:
            self._warn_unbound_reset(cleared)
        from guard_core.core.checks._strike_forget import forget_category_strikes

        clear_by_ip_strikes()
        forget_category_strikes("rate_limit")
        if redis_cleared:
            self.logger.info(
                "reset() also cleared the rate-limit auto-ban strikes (process "
                "memory and Redis); detection strikes and active bans are kept"
            )
        else:
            self.logger.info(
                "reset() also cleared the rate-limit auto-ban strikes (process "
                "memory); detection strikes and active bans are kept"
            )

    def _warn_unbound_reset(self, cleared: list[str]) -> None:
        if not cleared:
            self.logger.warning(
                "this config object is not the one any guarded app was built "
                "with; reset() cleared nothing"
            )
            return
        self.logger.warning(
            "this config object is not the one any guarded app was built "
            "with; no in-process request window of a guarded app was cleared "
            "(cleared: %s)",
            ", ".join(cleared),
        )


rate_limit_handler = RateLimitManager
