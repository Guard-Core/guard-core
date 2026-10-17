import json
import logging
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from typing import Any, Literal

from cachetools import TTLCache

from guard_core._utils.identity_hash import _hash_identity_segment
from guard_core._utils.lru_store import _lru_pop_or_create
from guard_core.handlers._behavior_action_dispatch import BehaviorActionDispatchMixin
from guard_core.handlers._behavior_response_pattern import (
    BehaviorResponsePatternMixin,
    _BoundedResponseBodyReader,
)
from guard_core.models import BehaviorRuleConfig, SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import _log_at_level, _safe_read

__all__ = [
    "_BoundedResponseBodyReader",
    "_log_at_level",
    "_safe_read",
]


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

    def discriminator(self) -> str:
        return json.dumps(
            [self.rule_type, self.pattern, self.window, self.threshold, self.action]
        )


RECENT_REQUEST_WINDOW_SECONDS = 300
_RECENT_ENDPOINT_ID = "recent"
_MAX_RECENT_REQUESTS_PER_CLIENT = 10_000
_MAX_TRACKED_ENDPOINTS = 10_000
_MAX_TRACKED_CLIENTS_PER_ENDPOINT = 10_000


class BehaviorTracker(BehaviorResponsePatternMixin, BehaviorActionDispatchMixin):
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.logger = logging.getLogger("guard_core.handlers.behavior")
        self.usage_counts: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.return_patterns: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.recent_requests: dict[str, list[float]] = {}
        self.redis_handler: Any | None = None
        self.agent_handler: Any | None = None
        self._body_unavailable_log_cache: TTLCache[str, bool] = TTLCache(
            maxsize=1000, ttl=300
        )
        self._lock = threading.Lock()

    async def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler

    async def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    def _recent_requests_key(self, ip: str) -> str:
        return (
            f"behavior:usage:{_hash_identity_segment(_RECENT_ENDPOINT_ID)}:"
            f"{_hash_identity_segment(ip)}"
        )

    async def record_recent_request(self, ip: str) -> None:
        current_time = time.time()
        window_start = current_time - RECENT_REQUEST_WINDOW_SECONDS

        if self.redis_handler:
            await self.redis_handler.record_sliding_window_hit(
                "behavior_usage",
                self._recent_requests_key(ip),
                current_time,
                window_start,
                RECENT_REQUEST_WINDOW_SECONDS,
            )
            return

        with self._lock:
            timestamps = _lru_pop_or_create(
                self.recent_requests, ip, _MAX_TRACKED_CLIENTS_PER_ENDPOINT, list
            )
            kept = [ts for ts in timestamps if ts >= window_start]
            kept.append(current_time)
            self.recent_requests[ip] = kept[-_MAX_RECENT_REQUESTS_PER_CLIENT:]

    async def get_recent_event_count(self, ip: str, window_seconds: int) -> int:
        if not ip:
            return 0
        window_start = time.time() - window_seconds

        if self.redis_handler:
            count: int = await self.redis_handler.count_sliding_window_hits(
                "behavior_usage", self._recent_requests_key(ip), window_start
            )
            return count

        with self._lock:
            return sum(
                1 for ts in self.recent_requests.get(ip, []) if ts >= window_start
            )

    async def track_endpoint_usage(
        self, endpoint_id: str, client_ip: str, rule: BehaviorRule
    ) -> bool:
        current_time = time.time()
        window_start = current_time - rule.window
        discriminator = rule.discriminator()

        if self.redis_handler:
            key = (
                f"behavior:usage:{_hash_identity_segment(endpoint_id)}:"
                f"{_hash_identity_segment(client_ip)}:"
                f"{_hash_identity_segment(discriminator)}"
            )

            valid_count: int = await self.redis_handler.record_sliding_window_hit(
                "behavior_usage", key, current_time, window_start, rule.window
            )

            return valid_count > rule.threshold

        bucket_key = f"{discriminator}|{endpoint_id}"
        with self._lock:
            bucket = _lru_pop_or_create(
                self.usage_counts,
                bucket_key,
                _MAX_TRACKED_ENDPOINTS,
                lambda: defaultdict(list),
            )
            self.usage_counts[bucket_key] = bucket
            timestamps = _lru_pop_or_create(
                bucket, client_ip, _MAX_TRACKED_CLIENTS_PER_ENDPOINT, list
            )

            timestamps[:] = [ts for ts in timestamps if ts >= window_start]

            timestamps.append(current_time)
            bucket[client_ip] = timestamps

            return len(timestamps) > rule.threshold

    async def track_return_pattern(
        self,
        endpoint_id: str,
        client_ip: str,
        response: GuardResponse,
        rule: BehaviorRule,
        effective_threshold: int | None = None,
    ) -> bool:
        if not rule.pattern:
            return False

        threshold = (
            effective_threshold if effective_threshold is not None else rule.threshold
        )
        current_time = time.time()
        window_start = current_time - rule.window

        pattern_matched = await self._check_response_pattern(response, rule.pattern)

        if not pattern_matched:
            return False

        if self.redis_handler:
            key = (
                f"behavior:return:{_hash_identity_segment(endpoint_id)}:"
                f"{_hash_identity_segment(client_ip)}:"
                f"{_hash_identity_segment(rule.discriminator())}"
            )

            valid_count: int = await self.redis_handler.record_sliding_window_hit(
                "behavior_returns", key, current_time, window_start, rule.window
            )

            return valid_count > threshold

        pattern_key = f"{rule.discriminator()}|{endpoint_id}"
        with self._lock:
            bucket = _lru_pop_or_create(
                self.return_patterns,
                pattern_key,
                _MAX_TRACKED_ENDPOINTS,
                lambda: defaultdict(list),
            )
            self.return_patterns[pattern_key] = bucket
            timestamps = _lru_pop_or_create(
                bucket, client_ip, _MAX_TRACKED_CLIENTS_PER_ENDPOINT, list
            )

            timestamps[:] = [ts for ts in timestamps if ts >= window_start]

            timestamps.append(current_time)
            bucket[client_ip] = timestamps

            return len(timestamps) > threshold


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
