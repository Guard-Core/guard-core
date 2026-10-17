import logging
import math
import threading
import uuid
from collections import OrderedDict, defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from redis.exceptions import NoScriptError

from guard_core._utils.identity_hash import _hash_identity_segment
from guard_core._utils.lru_store import _lru_pop_or_create
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.scripts.behavior_throttle_lua import BEHAVIOR_THROTTLE_SCRIPT

if TYPE_CHECKING:
    from guard_core.handlers.behavior_handler import BehaviorRule

USAGE_NAMESPACE = "behavior_usage"
RETURN_NAMESPACE = "behavior_returns"
TRIP_NAMESPACE = "behavior_throttle"
MAX_TRIP_MARKERS = 10_000
MAX_TRACKED_BUCKETS = 10_000
MAX_TRACKED_CLIENTS_PER_BUCKET = 10_000

_logger = logging.getLogger("guard_core.handlers.behavior")
_redis_fail_open_warned = False


def _warn_throttle_fail_open() -> None:
    global _redis_fail_open_warned
    if _redis_fail_open_warned:
        return
    _redis_fail_open_warned = True
    _logger.warning(
        "Redis unavailable for behavior throttle rules; using the in-memory "
        "window (redis_fail_open=True); with several workers the effective "
        "limit is workers x threshold"
    )


def _identity_suffix(scope_id: str, client_ip: str, rule: "BehaviorRule") -> str:
    return (
        f"{_hash_identity_segment(scope_id)}:{_hash_identity_segment(client_ip)}:"
        f"{_hash_identity_segment(rule.discriminator())}"
    )


def usage_hits_key(scope_id: str, client_ip: str, rule: "BehaviorRule") -> str:
    return f"behavior:usage:{_identity_suffix(scope_id, client_ip, rule)}"


def return_hits_key(scope_id: str, client_ip: str, rule: "BehaviorRule") -> str:
    return f"behavior:return:{_identity_suffix(scope_id, client_ip, rule)}"


def trip_marker_key(scope_id: str, client_ip: str, rule: "BehaviorRule") -> str:
    return f"behavior:throttle:{_identity_suffix(scope_id, client_ip, rule)}"


def bucket_key(scope_id: str, rule: "BehaviorRule") -> str:
    return f"{rule.discriminator()}|{scope_id}"


@dataclass(frozen=True)
class ThrottleCheck:
    rule: "BehaviorRule"
    scope_id: str
    records: bool
    refuse_at: int


@dataclass(frozen=True)
class ThrottleTrip:
    check: ThrottleCheck
    retry_after: int
    first_of_episode: bool


def _retry_after(oldest_needed: float, window: int, now: float) -> int:
    return min(window, max(1, math.ceil(oldest_needed + window - now)))


def _record_hits(
    checks: list[ThrottleCheck], hit_lists: list[list[float]], now: float
) -> None:
    for check, hits in zip(checks, hit_lists, strict=True):
        if check.records:
            hits.append(now)


class BehaviorThrottleMixin:
    config: SecurityConfig
    redis_handler: Any
    usage_counts: dict[str, dict[str, list[float]]]
    return_patterns: dict[str, dict[str, list[float]]]
    _lock: threading.Lock
    _trip_markers: "OrderedDict[str, float]"
    _throttle_script_sha: str | None
    _recent_rule_hits_window: Callable[[str, float], tuple[str, float, int]]

    async def check_throttle(
        self,
        client_ip: str,
        checks: list[ThrottleCheck],
        now: float,
        record_when_over: bool,
    ) -> list[ThrottleTrip]:
        if self.redis_handler and self.redis_handler.config.enable_redis:
            trips = await self._redis_throttle(client_ip, checks, now, record_when_over)
            if trips is not None:
                return trips
        return self._memory_throttle(client_ip, checks, now, record_when_over)

    async def _redis_throttle(
        self,
        client_ip: str,
        checks: list[ThrottleCheck],
        now: float,
        record_when_over: bool,
    ) -> list[ThrottleTrip] | None:
        prefix = self.redis_handler.config.redis_prefix
        keys = [
            f"{prefix}{USAGE_NAMESPACE}:{usage_hits_key(c.scope_id, client_ip, c.rule)}"
            if c.records
            else f"{prefix}{RETURN_NAMESPACE}:"
            f"{return_hits_key(c.scope_id, client_ip, c.rule)}"
            for c in checks
        ] + [
            f"{prefix}{TRIP_NAMESPACE}:{trip_marker_key(c.scope_id, client_ip, c.rule)}"
            for c in checks
        ]
        args: list[Any] = [repr(now), uuid.uuid4().hex, int(record_when_over), "", ""]
        if any(c.records for c in checks):
            recent_key, recent_start, recent_ttl = self._recent_rule_hits_window(
                client_ip, now
            )
            keys.append(f"{prefix}{USAGE_NAMESPACE}:{recent_key}")
            args[3:5] = [repr(recent_start), recent_ttl]
        for check in checks:
            args += [
                int(check.records),
                repr(now - check.rule.window),
                check.rule.window,
                check.refuse_at,
            ]
        try:
            raw = await self._eval_throttle_script(keys, args)
        except Exception as error:
            if self.config.redis_fail_open:
                _warn_throttle_fail_open()
                return None
            raise GuardRedisError(
                503, "Redis behavior throttling unavailable"
            ) from error
        return [
            ThrottleTrip(
                check=checks[int(raw[i]) - 1],
                retry_after=_retry_after(
                    float(raw[i + 1]), checks[int(raw[i]) - 1].rule.window, now
                ),
                first_of_episode=int(raw[i + 2]) == 1,
            )
            for i in range(0, len(raw), 3)
        ]

    async def _eval_throttle_script(self, keys: list[str], args: list[Any]) -> Any:
        async with self.redis_handler.get_connection() as conn:
            if self._throttle_script_sha is None:
                self._throttle_script_sha = await conn.script_load(
                    BEHAVIOR_THROTTLE_SCRIPT
                )
            try:
                return await conn.evalsha(
                    self._throttle_script_sha, len(keys), *keys, *args
                )
            except NoScriptError:
                self._throttle_script_sha = await conn.script_load(
                    BEHAVIOR_THROTTLE_SCRIPT
                )
                return await conn.evalsha(
                    self._throttle_script_sha, len(keys), *keys, *args
                )

    def _memory_hits(
        self, client_ip: str, check: ThrottleCheck, cutoff: float
    ) -> list[float]:
        key = bucket_key(check.scope_id, check.rule)
        if not check.records:
            stored = self.return_patterns.get(key, {}).get(client_ip, [])
            return [ts for ts in stored if ts >= cutoff]
        bucket = _lru_pop_or_create(
            self.usage_counts, key, MAX_TRACKED_BUCKETS, lambda: defaultdict(list)
        )
        self.usage_counts[key] = bucket
        hits = _lru_pop_or_create(
            bucket, client_ip, MAX_TRACKED_CLIENTS_PER_BUCKET, list
        )
        hits[:] = [ts for ts in hits if ts >= cutoff]
        bucket[client_ip] = hits
        return hits

    def _memory_throttle(
        self,
        client_ip: str,
        checks: list[ThrottleCheck],
        now: float,
        record_when_over: bool,
    ) -> list[ThrottleTrip]:
        with self._lock:
            hit_lists = [
                self._memory_hits(client_ip, check, now - check.rule.window)
                for check in checks
            ]
            counts = [len(hits) for hits in hit_lists]
            over = [
                count >= c.refuse_at for count, c in zip(counts, checks, strict=True)
            ]
            if record_when_over or not any(over):
                _record_hits(checks, hit_lists, now)
            return [
                ThrottleTrip(
                    check=check,
                    retry_after=_retry_after(
                        hits[count - check.refuse_at], check.rule.window, now
                    ),
                    first_of_episode=self._mark_trip(client_ip, check, now),
                )
                for check, hits, count, is_over in zip(
                    checks, hit_lists, counts, over, strict=True
                )
                if is_over
            ]

    def _mark_trip(self, client_ip: str, check: ThrottleCheck, now: float) -> bool:
        key = trip_marker_key(check.scope_id, client_ip, check.rule)
        expires_at = self._trip_markers.pop(key, None)
        first = expires_at is None or expires_at <= now
        if expires_at is None and len(self._trip_markers) >= MAX_TRIP_MARKERS:
            self._trip_markers.popitem(last=False)
        self._trip_markers[key] = now + check.rule.window
        return first
