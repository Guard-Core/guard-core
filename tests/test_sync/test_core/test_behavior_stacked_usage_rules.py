from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers import behavior_handler
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.sync.handlers.redis_handler import RedisHandlerBase
from tests.test_sync.conftest import MockGuardResponse


class _HitListRedis(RedisHandlerBase):
    def __init__(self) -> None:
        super().__init__(SyncSecurityConfig(enable_redis=False))
        self.lists: dict[str, list[float]] = {}

    def record_sliding_window_hit(
        self,
        namespace: str,
        key: str,
        timestamp: float,
        window_start: float,
        ttl: int,
        *,
        index: tuple[str, int] | None = None,
        index_refused: list[bool] | None = None,
    ) -> int:
        hits = self.lists.setdefault(f"{namespace}:{key}", [])
        hits.append(timestamp)
        hits[:] = [ts for ts in hits if ts >= window_start]
        return len(hits)


def _track_stacked(tracker: BehaviorTracker) -> list[bool]:
    long_rule = BehaviorRule(rule_type="usage", threshold=5, window=3600)
    short_rule = BehaviorRule(rule_type="frequency", threshold=100, window=1)
    long_results = []
    for _ in range(6):
        long_results.append(
            tracker.track_endpoint_usage("route", "203.0.113.6", long_rule)
        )
        tracker.track_endpoint_usage("route", "203.0.113.6", short_rule)
    return long_results


def test_stacked_rules_count_each_request_once_in_memory() -> None:
    tracker = BehaviorTracker(SyncSecurityConfig(enable_redis=False))
    assert _track_stacked(tracker) == [False] * 5 + [True]


def test_stacked_rules_count_each_request_once_with_redis() -> None:
    tracker = BehaviorTracker(SyncSecurityConfig(enable_redis=False))
    redis = _HitListRedis()
    tracker.initialize_redis(redis)
    assert _track_stacked(tracker) == [False] * 5 + [True]
    assert len(redis.lists) == 2


def test_rules_differing_only_in_threshold_do_not_share_a_hit_list() -> None:
    tracker = BehaviorTracker(SyncSecurityConfig(enable_redis=False))
    first = BehaviorRule(rule_type="usage", threshold=2, window=60)
    second = BehaviorRule(rule_type="usage", threshold=3, window=60)
    for _ in range(3):
        tracker.track_endpoint_usage("route", "203.0.113.6", first)
    assert tracker.track_endpoint_usage("route", "203.0.113.6", second) is False


def _return_rule(**overrides: Any) -> BehaviorRule:
    fields: dict[str, Any] = {
        "rule_type": "return_pattern",
        "threshold": 3,
        "window": 300,
        "pattern": "status:404",
        "action": "log",
    }
    fields.update(overrides)
    return BehaviorRule(**fields)


def _fire_sequences_for_equal_rules_with_different_actions(
    tracker: BehaviorTracker,
) -> tuple[list[bool], list[bool]]:
    response = MockGuardResponse("not found", status_code=404)
    first = _return_rule(action="log")
    second = _return_rule(action="ban")
    first_fired = []
    second_fired = []
    for _ in range(4):
        first_fired.append(
            tracker.track_return_pattern("route", "1.2.3.4", response, first)
        )
        second_fired.append(
            tracker.track_return_pattern("route", "1.2.3.4", response, second)
        )
    return first_fired, second_fired


def test_return_rules_with_one_pattern_count_each_response_once_in_memory() -> None:
    tracker = BehaviorTracker(SyncSecurityConfig(enable_redis=False))
    first, second = _fire_sequences_for_equal_rules_with_different_actions(tracker)
    assert first == [False, False, False, True]
    assert second == [False, False, False, True]


def test_return_rules_with_one_pattern_count_each_response_once_with_redis() -> None:
    tracker = BehaviorTracker(SyncSecurityConfig(enable_redis=False))
    redis = _HitListRedis()
    tracker.initialize_redis(redis)
    first, second = _fire_sequences_for_equal_rules_with_different_actions(tracker)
    assert first == [False, False, False, True]
    assert second == [False, False, False, True]
    assert len(redis.lists) == 2


def test_short_window_return_rule_does_not_trim_the_long_window_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [1_000_000.0]
    monkeypatch.setattr(behavior_handler.time, "time", lambda: clock[0])
    tracker = BehaviorTracker(SyncSecurityConfig(enable_redis=False))
    response = MockGuardResponse("not found", status_code=404)
    short = _return_rule(threshold=10, window=1)
    long = _return_rule(threshold=5, window=300)
    long_fired = []
    for _ in range(8):
        tracker.track_return_pattern("route", "1.2.3.4", response, short)
        long_fired.append(
            tracker.track_return_pattern("route", "1.2.3.4", response, long)
        )
        clock[0] += 1.2
    assert long_fired == [False] * 5 + [True] * 3
