import logging
import math
import threading
import uuid
from collections import OrderedDict, defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from redis.exceptions import NoScriptError

from guard_core._redis_enablement import redis_is_configured
from guard_core._utils.identity_hash import _hash_identity_segment
from guard_core._utils.ip_extraction import _client_identity
from guard_core._utils.lru_store import _lru_pop_or_create
from guard_core.exceptions import GuardRedisError
from guard_core.handlers._behavior_evictions import BehaviorEvictionMixin
from guard_core.models import SecurityConfig
from guard_core.scripts.behavior_throttle_lua import BEHAVIOR_THROTTLE_SCRIPT

if TYPE_CHECKING:
    from guard_core.handlers.behavior_handler import BehaviorRule

USAGE_NAMESPACE = "behavior_usage"
RECENT_RULE_HITS_WINDOW_SECONDS = 300
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


def behavior_client_identity(config: SecurityConfig, client_ip: str) -> str:
    """The client every behavior counter, key and ban is kept under: the address
    for IPv4 and ``ipv6_prefix_length`` 128, the network's CIDR text otherwise."""
    if ":" not in client_ip:
        return client_ip
    return _client_identity(client_ip, config.ipv6_prefix_length)


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


def rule_hit_ttl(rule: "BehaviorRule") -> int:
    # Keeps every hit the recent rule-hit count can still read (D-36).
    return max(rule.window, RECENT_RULE_HITS_WINDOW_SECONDS)


def bucket_key(scope_id: str, rule: "BehaviorRule") -> str:
    return f"{rule.discriminator()}|{scope_id}"


@dataclass(frozen=True)
class ThrottleCheck:
    rule: "BehaviorRule"
    scope_id: str
    records: bool
    refuse_at: int
    # The rule's hit list already holds this request's hit (a custom_action copy of
    # the rule recorded it): count it, do not add a second one.
    hit_recorded: bool = False
    # A global return rule with correlate_with_detection: the refuse_at that
    # applies instead of refuse_at while the IP has detection strikes (0 = none).
    correlated_refuse_at: int = 0

    @property
    def writes(self) -> bool:
        return self.records and not self.hit_recorded


@dataclass(frozen=True)
class ThrottleTrip:
    check: ThrottleCheck
    retry_after: int
    first_of_episode: bool


class ReturnCorrelation:
    """A return rule whose threshold drops while the IP has detection strikes.

    The categories are asked for only when the rule's count is above the
    correlated threshold, the one place they can change the outcome.
    """

    def __init__(
        self, threshold: int, lookup: Callable[[], Awaitable[list[str]]]
    ) -> None:
        self.threshold = threshold
        self.lookup = lookup
        self.categories: list[str] = []

    @property
    def active(self) -> bool:
        return bool(self.categories)

    async def threshold_for(self, count: int, default: int) -> int:
        if count <= self.threshold:
            return default
        self.categories = await self.lookup()
        return self.threshold if self.active else default


def _retry_after(oldest_needed: float, window: int, now: float) -> int:
    return min(window, max(1, math.ceil(oldest_needed + window - now)))


def _record_hits(
    checks: list[ThrottleCheck], hit_lists: list[list[float]], now: float
) -> None:
    recorded: set[int] = set()
    for check, hits in zip(checks, hit_lists, strict=True):
        if check.writes and id(hits) not in recorded:
            recorded.add(id(hits))
            hits.append(now)


def _with_correlation(
    checks: list[ThrottleCheck],
    counts: list[int],
    process_categories: Callable[[], list[str]] | None,
) -> list[ThrottleCheck]:
    # The categories are asked for only when a correlated rule's count sits
    # where they can change its outcome, and at most once.
    active: bool | None = None
    resolved = []
    for check, count in zip(checks, counts, strict=True):
        if (
            process_categories is not None
            and check.correlated_refuse_at
            and check.correlated_refuse_at <= count < check.refuse_at
        ):
            if active is None:
                active = bool(process_categories())
            if active:
                check = replace(check, refuse_at=check.correlated_refuse_at)
        resolved.append(check)
    return resolved


class BehaviorThrottleMixin(BehaviorEvictionMixin):
    config: SecurityConfig
    redis_handler: Any
    usage_counts: dict[str, dict[str, list[float]]]
    return_patterns: dict[str, dict[str, list[float]]]
    _lock: threading.Lock
    _trip_markers: "OrderedDict[str, float]"
    _throttle_script_sha: str | None
    _rule_hit_index: Callable[[str], tuple[str, int]]

    async def check_throttle(
        self,
        client_ip: str,
        checks: list[ThrottleCheck],
        now: float,
        record_when_over: bool,
        process_categories: Callable[[], list[str]] | None = None,
    ) -> list[ThrottleTrip]:
        client_ip = behavior_client_identity(self.config, client_ip)
        trips = None
        if self.redis_handler and redis_is_configured(self.redis_handler.config):
            trips = await self._redis_throttle(client_ip, checks, now, record_when_over)
        if trips is None:
            trips = self._memory_throttle(
                client_ip, checks, now, record_when_over, process_categories
            )
        if self._evicted_values:
            await self._report_evictions(client_ip)
        return trips

    def _throttle_script_input(
        self,
        client_ip: str,
        checks: list[ThrottleCheck],
        now: float,
        record_when_over: bool,
    ) -> tuple[list[str], list[Any]]:
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
        args: list[Any] = [
            repr(now),
            uuid.uuid4().hex,
            int(record_when_over),
            "",
            "",
            len(checks),
            "",
        ]
        if any(c.writes for c in checks):
            index_key, max_members = self._rule_hit_index(client_ip)
            keys.append(f"{prefix}{USAGE_NAMESPACE}:{index_key}")
            args[3:5] = [max_members, RECENT_RULE_HITS_WINDOW_SECONDS]
        if any(c.correlated_refuse_at for c in checks):
            from guard_core.core.checks.helpers import SUSPICIOUS_COUNT_WINDOW_SECONDS

            keys += self.redis_handler.detection_correlation_keys(client_ip)
            args[6] = repr(now - SUSPICIOUS_COUNT_WINDOW_SECONDS)
        for check in checks:
            args += [
                int(check.writes),
                repr(now - check.rule.window),
                check.rule.window,
                check.refuse_at,
                check.correlated_refuse_at,
            ]
        return keys, args

    async def _redis_throttle(
        self,
        client_ip: str,
        checks: list[ThrottleCheck],
        now: float,
        record_when_over: bool,
    ) -> list[ThrottleTrip] | None:
        keys, args = self._throttle_script_input(
            client_ip, checks, now, record_when_over
        )
        try:
            raw = await self._eval_throttle_script(keys, args)
        except Exception as error:
            if self.config.redis_fail_open:
                _warn_throttle_fail_open()
                return None
            raise GuardRedisError(
                503, "Redis behavior throttling unavailable"
            ) from error
        # The script appends one extra element when the rule-hit index refused a key.
        raw_length = len(raw)
        index_refused = raw_length % 4
        if index_refused:
            self._evicted_values.append(("rule_hit_index", True))
        return [
            ThrottleTrip(
                check=replace(checks[int(raw[i]) - 1], refuse_at=int(raw[i + 3])),
                retry_after=_retry_after(
                    float(raw[i + 1]), checks[int(raw[i]) - 1].rule.window, now
                ),
                first_of_episode=int(raw[i + 2]) == 1,
            )
            for i in range(0, raw_length - index_refused, 4)
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
            self.usage_counts,
            key,
            self.config.behavior_throttle_max_tracked_buckets,
            lambda: defaultdict(list),
            self._evicted_values,
            "throttle_bucket",
        )
        self.usage_counts[key] = bucket
        hits: list[float] = _lru_pop_or_create(
            bucket,
            client_ip,
            self.config.behavior_throttle_max_tracked_clients_per_bucket,
            list,
            self._evicted_values,
            "throttle_client",
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
        process_categories: Callable[[], list[str]] | None = None,
    ) -> list[ThrottleTrip]:
        with self._lock:
            hit_lists = [
                self._memory_hits(client_ip, check, now - check.rule.window)
                for check in checks
            ]
            counts = [len(hits) for hits in hit_lists]
            checks = _with_correlation(checks, counts, process_categories)
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
        if (
            expires_at is None
            and len(self._trip_markers)
            >= self.config.behavior_throttle_max_trip_markers
        ):
            _, dropped_expiry = self._trip_markers.popitem(last=False)
            self._evicted_values.append(("trip_marker", dropped_expiry > now))
        self._trip_markers[key] = now + check.rule.window
        return first
