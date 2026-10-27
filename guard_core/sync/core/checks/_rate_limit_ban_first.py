import hashlib
import logging
import os
import time
from collections.abc import Sequence
from typing import TYPE_CHECKING, TypedDict

from guard_core._redis_enablement import redis_is_configured
from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.scripts.rate_lua import (
    BAN_FIRST_RATE_LIMIT_SCRIPT,
    BAN_RATE_STRIKE_SCRIPT,
)
from guard_core.sync._utils.ip_extraction import _client_identity
from guard_core.sync.core.checks._ban_flow import NO_BAN_FLOW, BanFlow
from guard_core.sync.core.checks._pending_ban import PendingBan
from guard_core.sync.core.checks._shared_strikes import FusedStrike
from guard_core.sync.handlers._redis_lean import ReplyValue, lean_evalsha, reply_counts
from guard_core.sync.handlers.ratelimit_handler import (
    RateLimitTier,
    RateLimitVerdict,
    _resolve_redis_rate_limit_failure,
    _script_arguments,
    _tier_key,
    _verdict_from_script_result,
)
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

if TYPE_CHECKING:
    from redis import Redis

    from guard_core.sync.core.checks._rate_limit_plans import TierPlan
    from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck

_logger = logging.getLogger("guard_core.sync.handlers.ratelimit")
_SHA = hashlib.sha1(
    BAN_FIRST_RATE_LIMIT_SCRIPT.encode(), usedforsecurity=False
).hexdigest()
_STRIKE_SHA = hashlib.sha1(
    BAN_RATE_STRIKE_SCRIPT.encode(), usedforsecurity=False
).hexdigest()
_VERSION_KEY = "ban_version:counter"
NO_STATUS_REPLY = "the ban-first script replied with no status"
NO_RATE_LIMIT_HANDLER = "the middleware has no rate_limit_handler to count the request"


def can_read_ban_with_rate_limit(
    pending: PendingBan, redis_handler: RedisManager | None, config: SyncSecurityConfig
) -> bool:
    return (
        redis_handler is not None
        and redis_is_configured(config)
        and pending.check.ip_ban_manager.redis_handler is redis_handler
    )


def _identity(
    client_ip: str, config: SyncSecurityConfig, window_identity: str | None
) -> str:
    return window_identity or (
        _client_identity(client_ip, config.ipv6_prefix_length)
        if ":" in client_ip
        else client_ip
    )


def _evalsha(
    conn: "Redis", script: str, sha: str, keys: list[bytes], arguments: list[bytes]
) -> list[ReplyValue]:
    return lean_evalsha(conn, script, sha, keys, arguments)


def _strike_keys_and_meta(
    redis_handler: RedisManager, strike: FusedStrike, now: float
) -> tuple[list[str], list[str]]:
    index, total, category_prefix = redis_handler._detection_strike_keys(
        strike.client_ip
    )
    keys = [
        index,
        total,
        redis_handler._rate_limit_violations_key(strike.client_ip),
        *(f"{category_prefix}{name}" for name in strike.categories),
    ]
    meta = [
        repr(now),
        os.urandom(16).hex(),
        repr(now - strike.window_seconds),
        str(strike.window_seconds),
        str(strike.cap),
    ]
    return keys, meta


def _script_input(
    pending: PendingBan,
    redis_handler: RedisManager,
    pairs: list[tuple[str, str]],
    seen: str | None,
    now: float,
    client_ip: str,
    tiers: Sequence[RateLimitTier],
    config: SyncSecurityConfig,
    window_identity: str | None,
    strike: FusedStrike | None,
) -> tuple[str, str, list[str], str]:
    prefix = config.redis_prefix
    identity = _identity(client_ip, config, window_identity)
    keys = [
        *(f"{prefix}{namespace}:{key}" for namespace, key in pairs),
        f"{prefix}{_VERSION_KEY}",
        *(f"{prefix}rate_limit:rate:{_tier_key(identity, tier)}" for tier in tiers),
    ]
    meta = [str(len(pairs)), "" if seen is None else seen, repr(now)]
    if strike is None:
        return BAN_FIRST_RATE_LIMIT_SCRIPT, _SHA, keys, "|".join(meta)
    strike_keys, strike_meta = _strike_keys_and_meta(redis_handler, strike, now)
    meta += [str(len(tiers)), *strike_meta]
    return BAN_RATE_STRIKE_SCRIPT, _STRIKE_SHA, keys + strike_keys, "|".join(meta)


def ban_first_rate_limit(
    pending: PendingBan,
    redis_handler: RedisManager,
    client_ip: str,
    tiers: Sequence[RateLimitTier],
    config: SyncSecurityConfig,
    window_identity: str | None,
    strike: FusedStrike | None = None,
) -> tuple[bool, RateLimitVerdict | None]:
    """The pending ban read and the rate-limit tiers in one script, ban first: a
    banned client touches no counter. With a ``strike`` the same script records it
    after the tiers when the request is not limited. Returns whether the client is
    banned and the rate-limit verdict, ``None`` when the script did not evaluate the
    tiers (the caller then evaluates them on its own)."""
    manager = pending.check.ip_ban_manager
    pairs = manager.ban_key_pairs(pending.read)
    seen = manager._ban_version_seen
    now = time.time()
    script, sha, keys, meta = _script_input(
        pending,
        redis_handler,
        pairs,
        seen,
        now,
        client_ip,
        tiers,
        config,
        window_identity,
        strike,
    )
    arguments = [meta, *map(str, _script_arguments(tiers))]
    try:
        with redis_handler.get_connection() as conn:
            reply = _evalsha(
                conn,
                script,
                sha,
                [key.encode() for key in keys],
                [a.encode() for a in arguments],
            )
    except Exception as error:
        _resolve_redis_rate_limit_failure(
            error, config.redis_fail_open, _logger, "Redis rate limiting error"
        )
        pending.check.warn_ban_lookup_skipped(pending.client_ip)
        return False, None
    read = len(pairs) + 1
    first = reply[0]
    if first is None:
        raise TypeError(NO_STATUS_REPLY)
    status = int(first)
    values: list[str | bytes | float | None] = (
        [*([None] * len(pairs)), seen] if status == 1 else [*reply[1 : read + 1]]
    )
    banned = manager.decide_from_ban_values(pairs, values, now)
    if status == 0:
        return banned, None
    offset = 1 if status == 1 else 1 + read
    verdict = _verdict_from_script_result(reply_counts(reply[offset : offset + 3]))
    counts = reply[offset + 3 :]
    if strike is not None and counts:
        numbers = reply_counts(counts)
        strike.record(
            (
                numbers[0],
                numbers[1],
                dict(zip(strike.categories, numbers[2:], strict=True)),
            )
        )
    return banned, verdict


def finish_tiers(
    check: "RateLimitCheck",
    request: SyncGuardRequest,
    client_ip: str,
    plans: Sequence["TierPlan"],
    verdict: RateLimitVerdict | None,
) -> GuardResponse | None:
    """The rate-limit check's verdict step: evaluate the tiers (or take the verdict
    a combined script reached), report the block, count the auto-ban strike and
    return the 429."""
    rate_limit_handler = check.middleware.rate_limit_handler
    if rate_limit_handler is None:
        raise AttributeError(NO_RATE_LIMIT_HANDLER)
    block = rate_limit_handler.check_rate_limit_tiers(
        request,
        client_ip,
        check.middleware.create_error_response,
        [plan.tier for plan in plans],
        config=check.config,
        **tier_kwargs(check, request, client_ip, verdict),
    )
    if block is None:
        return None
    plan = plans[block.tier_index]
    check._report_block(request, client_ip, plan, block)
    if check.config.passive_mode:
        return None
    check._record_rate_limit_autoban(request, client_ip, plan.trigger_info)
    response: GuardResponse = block.response
    return response


class TierKwargs(TypedDict, total=False):
    window_identity: str
    verdict: RateLimitVerdict


def tier_kwargs(
    check: "RateLimitCheck",
    request: SyncGuardRequest,
    client_ip: str,
    verdict: RateLimitVerdict | None,
) -> TierKwargs:
    """The handler call's optional arguments: the carved window identity and the
    verdict a combined script already reached."""
    kwargs: TierKwargs = {}
    if check.config.whitelist_access_only:
        kwargs["window_identity"] = check._strike_identity(request, client_ip)
    if verdict:
        kwargs["verdict"] = verdict
    return kwargs


class PendingRate:
    """The rate-limit count the rate-limit check left pending beside the ban read:
    both resolve in one script at the first check that needs either."""

    def __init__(
        self,
        check: "RateLimitCheck",
        client_ip: str,
        plans: Sequence["TierPlan"],
        redis_handler: RedisManager,
    ) -> None:
        self.check = check
        self.client_ip = client_ip
        self.plans = plans
        self.redis_handler = redis_handler


def defer_rate_limit(
    check: "RateLimitCheck",
    pending: object,
    client_ip: str | None,
    plans: Sequence["TierPlan"],
) -> bool:
    """Leave the rate-limit count pending with the ban read when one script can
    settle both (Redis tiers, not passive mode)."""
    if (
        not isinstance(pending, PendingBan)
        or not client_ip
        or not plans
        or check.config.passive_mode
        or not isinstance(
            redis_handler := getattr(
                check.middleware.rate_limit_handler, "redis_handler", None
            ),
            RedisManager,
        )
        or not can_read_ban_with_rate_limit(pending, redis_handler, check.config)
    ):
        return False
    pending.rate = PendingRate(check, client_ip, plans, redis_handler)
    return True


def resolve_ban_and_rate(
    request: SyncGuardRequest,
    pending: PendingBan,
    rate: PendingRate,
    category: str | None,
) -> GuardResponse | None:
    """The pending ban read, the rate-limit count and the strike of ``category`` in
    one script, in the order of the checks: the banned response first, then the
    rate-limit response, else the strike is recorded for the denial that asked."""
    check = rate.check
    config = check.config
    strike = pending.check.strike_for(request, pending.client_ip, category)
    carve = check._strike_identity(request, rate.client_ip)
    banned, verdict = ban_first_rate_limit(
        pending,
        rate.redis_handler,
        rate.client_ip,
        [plan.tier for plan in rate.plans],
        config,
        carve if config.whitelist_access_only else None,
        strike,
    )
    if banned:
        flow = getattr(request.state, "guard_ban_flow", None)
        if not isinstance(flow, BanFlow):
            raise AttributeError(NO_BAN_FLOW)
        flow.banned_by = pending.check
        return pending.check.banned_response(request, pending.client_ip)
    response = finish_tiers(check, request, rate.client_ip, rate.plans, verdict)
    if response is not None:
        flow = getattr(request.state, "guard_ban_flow", None)
        if not isinstance(flow, BanFlow):
            raise AttributeError(NO_BAN_FLOW)
        flow.banned_by = check
    return response
