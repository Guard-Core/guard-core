import json
import logging
import threading
import time
import uuid
from collections import OrderedDict, defaultdict
from collections.abc import Callable
from typing import Any, Literal

from cachetools import TTLCache

from guard_core._tracking_caps import (
    _MAX_TRACKED_CLIENTS_PER_ENDPOINT as _MAX_TRACKED_CLIENTS_PER_ENDPOINT,
)
from guard_core._tracking_caps import (
    _MAX_TRACKED_ENDPOINTS as _MAX_TRACKED_ENDPOINTS,
)
from guard_core._utils.identity_hash import _hash_identity_segment
from guard_core._utils.lru_store import _lru_pop_or_create
from guard_core.handlers._behavior_action_dispatch import BehaviorActionDispatchMixin
from guard_core.handlers._behavior_response_pattern import (
    BehaviorResponsePatternMixin,
    _BoundedResponseBodyReader,
)
from guard_core.handlers._behavior_throttle import (
    RECENT_RULE_HITS_WINDOW_SECONDS,
    RETURN_NAMESPACE,
    USAGE_NAMESPACE,
    BehaviorThrottleMixin,
    ReturnCorrelation,
    behavior_client_identity,
    bucket_key,
    return_hits_key,
    rule_hit_ttl,
    usage_hits_key,
)
from guard_core.models import BehaviorRuleConfig, SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import _log_at_level, _safe_read

__all__ = [
    "RECENT_RULE_HITS_WINDOW_SECONDS",
    "_BoundedResponseBodyReader",
    "_log_at_level",
    "_safe_read",
]


_RULE_ID_PREFIX = "guard-core:behavior-rule:"


class BehaviorRule:
    def __init__(
        self,
        rule_type: Literal["usage", "return_pattern", "frequency"],
        threshold: int,
        window: int = 3600,
        pattern: str | None = None,
        action: Literal["ban", "log", "throttle", "alert"] = "log",
        custom_action: Callable | None = None,
        ban_duration: int | None = None,
        correlate_with_detection: bool = False,
    ):
        self.rule_type = rule_type
        self.threshold = threshold
        self.window = window
        self.pattern = pattern
        self.action = action
        self.custom_action = custom_action
        self.ban_duration = ban_duration
        self.correlate_with_detection = correlate_with_detection
        self._discriminator_fields: tuple[Any, ...] | None = None
        self._discriminator = ""

    def discriminator(self) -> str:
        # Cached per field values: it keys every hit list a request touches.
        fields = (
            self.rule_type,
            self.pattern if self.rule_type == "return_pattern" else None,
            self.window,
            self.threshold,
            self.action,
        )
        if fields != self._discriminator_fields:
            self._discriminator = json.dumps(
                fields, separators=(",", ":"), ensure_ascii=False
            )
            self._discriminator_fields = fields
        return self._discriminator

    def matched_rule_id(self) -> str:
        return str(
            uuid.uuid5(uuid.NAMESPACE_URL, _RULE_ID_PREFIX + self.discriminator())
        )

    def matched_rule_metadata(self) -> dict[str, str]:
        return {
            "matched_rule_type": "behavioral",
            "matched_rule_id": self.matched_rule_id(),
        }


_RECENT_ENDPOINT_ID = "recent"


class BehaviorTracker(
    BehaviorResponsePatternMixin, BehaviorActionDispatchMixin, BehaviorThrottleMixin
):
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.logger = logging.getLogger("guard_core.handlers.behavior")
        self.usage_counts: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.return_patterns: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.redis_handler: Any | None = None
        self.agent_handler: Any | None = None
        self._body_unavailable_log_cache: TTLCache[str, bool] = TTLCache(
            maxsize=1000, ttl=300
        )
        self._lock = threading.Lock()
        self._trip_markers: OrderedDict[str, float] = OrderedDict()
        self._throttle_script_sha: str | None = None
        self._init_eviction_reporting()

    async def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler

    async def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    def _rule_hit_index(self, ip: str) -> tuple[str, int]:
        key = (
            f"behavior:usage:{_hash_identity_segment(_RECENT_ENDPOINT_ID)}:"
            f"{_hash_identity_segment(ip)}"
        )
        return key, self.config.behavior_max_tracked_endpoints

    def get_recent_event_count(self, ip: str, window_seconds: int) -> int:
        if not ip:
            return 0
        ip = behavior_client_identity(self.config, ip)
        cutoff = time.time() - window_seconds
        count = 0
        with self._lock:
            for endpoint_bucket in self.usage_counts.values():
                for ts in endpoint_bucket.get(ip, []):
                    if ts >= cutoff:
                        count += 1
        return count

    async def count_recent_rule_hits(self, ip: str, window_seconds: int) -> int:
        """Each usage or frequency rule's hits from the IP that are still inside
        that rule's own window, summed across all endpoints, counting only hits in
        the last window_seconds (at most 300, the shortest TTL of a rule's Redis
        key). In memory this is get_recent_event_count; with Redis it is the same
        sum over the IP's indexed rule keys. Remaining difference: at its caps
        memory evicts the least recently used endpoint bucket
        (behavior_max_tracked_endpoints) or client
        (behavior_max_tracked_clients_per_endpoint per bucket), while Redis keeps at
        most behavior_max_tracked_endpoints rule keys per IP."""
        if window_seconds > RECENT_RULE_HITS_WINDOW_SECONDS:
            raise ValueError(
                f"window_seconds must be at most {RECENT_RULE_HITS_WINDOW_SECONDS}"
            )
        if not self.redis_handler:
            return self.get_recent_event_count(ip, window_seconds)
        if not ip:
            return 0
        ip = behavior_client_identity(self.config, ip)
        count: int = await self.redis_handler.sum_indexed_window_hits(
            USAGE_NAMESPACE, self._rule_hit_index(ip)[0], time.time() - window_seconds
        )
        return count

    async def track_endpoint_usage(
        self,
        endpoint_id: str,
        client_ip: str,
        rule: BehaviorRule,
        record: bool = True,
    ) -> bool:
        client_ip = behavior_client_identity(self.config, client_ip)
        current_time = time.time()
        window_start = current_time - rule.window

        if self.redis_handler:
            key = usage_hits_key(endpoint_id, client_ip, rule)
            if record:
                index_refused: list[bool] = []
                valid_count: int = await self.redis_handler.record_sliding_window_hit(
                    USAGE_NAMESPACE,
                    key,
                    current_time,
                    window_start,
                    rule_hit_ttl(rule),
                    index=self._rule_hit_index(client_ip),
                    index_refused=index_refused,
                )
                if index_refused:
                    self._evicted_values.append(("rule_hit_index", True))
                    await self._report_evictions(client_ip)
            else:
                valid_count = await self.redis_handler.count_sliding_window_hits(
                    USAGE_NAMESPACE, key, window_start
                )

            return valid_count > rule.threshold

        usage_key = bucket_key(endpoint_id, rule)
        with self._lock:
            bucket = _lru_pop_or_create(
                self.usage_counts,
                usage_key,
                self.config.behavior_max_tracked_endpoints,
                lambda: defaultdict(list),
                self._evicted_values,
                "endpoint",
            )
            self.usage_counts[usage_key] = bucket
            timestamps = _lru_pop_or_create(
                bucket,
                client_ip,
                self.config.behavior_max_tracked_clients_per_endpoint,
                list,
                self._evicted_values,
                "endpoint_client",
            )

            timestamps[:] = [ts for ts in timestamps if ts >= window_start]

            if record:
                timestamps.append(current_time)
            bucket[client_ip] = timestamps

            exceeded = len(timestamps) > rule.threshold
        if self._evicted_values:
            await self._report_evictions(client_ip)
        return exceeded

    async def track_return_pattern(
        self,
        endpoint_id: str,
        client_ip: str,
        response: GuardResponse,
        rule: BehaviorRule,
        effective_threshold: int | None = None,
        record: bool = True,
        correlation: ReturnCorrelation | None = None,
    ) -> bool:
        if not rule.pattern:
            return False

        client_ip = behavior_client_identity(self.config, client_ip)
        threshold = (
            effective_threshold if effective_threshold is not None else rule.threshold
        )
        current_time = time.time()
        window_start = current_time - rule.window

        pattern_matched = await self._check_response_pattern(response, rule.pattern)

        if not pattern_matched:
            return False

        if self.redis_handler:
            key = return_hits_key(endpoint_id, client_ip, rule)
            if record:
                valid_count: int = await self.redis_handler.record_sliding_window_hit(
                    RETURN_NAMESPACE, key, current_time, window_start, rule.window
                )
            else:
                valid_count = await self.redis_handler.count_sliding_window_hits(
                    RETURN_NAMESPACE, key, window_start
                )

            return valid_count > await self._correlated_threshold(
                correlation, valid_count, threshold
            )

        pattern_key = bucket_key(endpoint_id, rule)
        with self._lock:
            bucket = _lru_pop_or_create(
                self.return_patterns,
                pattern_key,
                self.config.behavior_max_tracked_endpoints,
                lambda: defaultdict(list),
                self._evicted_values,
                "endpoint",
            )
            self.return_patterns[pattern_key] = bucket
            timestamps = _lru_pop_or_create(
                bucket,
                client_ip,
                self.config.behavior_max_tracked_clients_per_endpoint,
                list,
                self._evicted_values,
                "endpoint_client",
            )

            timestamps[:] = [ts for ts in timestamps if ts >= window_start]

            if record:
                timestamps.append(current_time)
            bucket[client_ip] = timestamps
            valid_count = len(timestamps)

        if self._evicted_values:
            await self._report_evictions(client_ip)
        return valid_count > await self._correlated_threshold(
            correlation, valid_count, threshold
        )

    @staticmethod
    async def _correlated_threshold(
        correlation: ReturnCorrelation | None, count: int, threshold: int
    ) -> int:
        if correlation is None:
            return threshold
        return await correlation.threshold_for(count, threshold)


def config_to_rule(cfg: BehaviorRuleConfig) -> BehaviorRule:
    return BehaviorRule(
        rule_type=cfg.rule_type,
        threshold=cfg.threshold,
        window=cfg.window,
        pattern=cfg.pattern,
        action=cfg.action,
        ban_duration=cfg.ban_duration,
        correlate_with_detection=cfg.correlate_with_detection,
    )
