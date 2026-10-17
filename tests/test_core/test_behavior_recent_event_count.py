import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.behavioral.context import BehavioralContext
from guard_core.core.behavioral.processor import BehavioralProcessor
from guard_core.decorators.base import RouteConfig
from guard_core.handlers import behavior_handler
from guard_core.handlers._behavior_throttle import ThrottleCheck, usage_hits_key
from guard_core.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.handlers.redis_handler import redis_handler
from guard_core.models import SecurityConfig

_IP = "203.0.113.9"


def _processor(tracker: BehaviorTracker, config: SecurityConfig) -> BehavioralProcessor:
    decorator: Any = MagicMock()
    decorator.behavior_tracker = tracker
    decorator.send_decorator_event = AsyncMock()
    event_bus = MagicMock()
    event_bus.send_middleware_event = AsyncMock()
    middleware = MagicMock(suspicious_request_counts={})
    middleware.create_error_response = AsyncMock(
        side_effect=lambda *_: MagicMock(headers={})
    )
    context = BehavioralContext(
        config=config,
        logger=logging.getLogger("test_recent_event_count"),
        event_bus=event_bus,
        guard_decorator=decorator,
        middleware=middleware,
    )
    return BehavioralProcessor(context)


def _request() -> MagicMock:
    request = MagicMock()
    request.method = "GET"
    request.url_path = "/x"
    request.state = MagicMock()
    request.state.guard_endpoint_id = "route"
    request.state.guard_route_id = None
    request.state.guard_decorator = None
    return request


def _usage(action: Any = "log", threshold: int = 100) -> BehaviorRule:
    return BehaviorRule(
        rule_type="usage", threshold=threshold, window=60, action=action
    )


def _route(*rules: BehaviorRule) -> RouteConfig:
    route_config = RouteConfig()
    route_config.behavior_rules = list(rules)
    return route_config


def _two_rule_route() -> RouteConfig:
    return _route(
        BehaviorRule(rule_type="usage", threshold=100, window=60),
        BehaviorRule(rule_type="frequency", threshold=100, window=30),
    )


async def _one_request(
    processor: BehavioralProcessor,
    route_config: RouteConfig,
    global_rules: list[BehaviorRule] | None = None,
) -> Any:
    request = _request()
    response = await processor.process_usage_rules(request, _IP, route_config)
    if global_rules:
        await processor.process_global_rules(request, MagicMock(), _IP, global_rules)
    return response


async def _redis_tracker(config: SecurityConfig) -> tuple[Any, BehaviorTracker]:
    redis_mgr = redis_handler(config)
    await redis_mgr.initialize()
    tracker = BehaviorTracker(config)
    await tracker.initialize_redis(redis_mgr)
    return redis_mgr, tracker


async def test_recent_count_counts_every_rule_hit_in_memory() -> None:
    config = SecurityConfig(enable_redis=False)
    tracker = BehaviorTracker(config)
    processor = _processor(tracker, config)
    for _ in range(3):
        await _one_request(processor, _two_rule_route())
    assert await tracker.count_recent_rule_hits(_IP, 300) == 6
    assert tracker.get_recent_event_count(_IP, 300) == 6
    assert await tracker.count_recent_rule_hits("198.51.100.1", 300) == 0


async def test_recent_count_is_backed_by_redis(
    security_config_redis: SecurityConfig,
) -> None:
    redis_mgr, tracker = await _redis_tracker(security_config_redis)
    processor = _processor(tracker, security_config_redis)
    try:
        for _ in range(3):
            await _one_request(processor, _two_rule_route())
        assert await tracker.count_recent_rule_hits(_IP, 300) == 6
        other = BehaviorTracker(security_config_redis)
        await other.initialize_redis(redis_mgr)
        assert await other.count_recent_rule_hits(_IP, 300) == 6
        assert await other.count_recent_rule_hits("", 300) == 0
    finally:
        await redis_mgr.delete_pattern("behavior_*")
        await redis_mgr.close()


async def _send_mixed_sequence(
    tracker: BehaviorTracker, config: SecurityConfig
) -> list[int]:
    processor = _processor(tracker, config)
    counts = []
    await _one_request(processor, _two_rule_route())
    counts.append(await tracker.count_recent_rule_hits(_IP, 300))
    await _one_request(processor, _route(_usage()), [_usage(threshold=50)])
    counts.append(await tracker.count_recent_rule_hits(_IP, 300))
    two_throttles = _route(
        _usage("throttle"),
        BehaviorRule(
            rule_type="frequency", threshold=100, window=30, action="throttle"
        ),
    )
    await _one_request(processor, two_throttles)
    counts.append(await tracker.count_recent_rule_hits(_IP, 300))
    refusing = _route(_usage("throttle", threshold=1))
    assert await _one_request(processor, refusing) is None
    assert await _one_request(processor, refusing) is not None
    counts.append(await tracker.count_recent_rule_hits(_IP, 300))
    return counts


async def test_recent_count_is_the_same_in_memory_and_in_redis(
    security_config_redis: SecurityConfig,
) -> None:
    memory_config = SecurityConfig(enable_redis=False)
    memory_tracker = BehaviorTracker(memory_config)
    memory_counts = await _send_mixed_sequence(memory_tracker, memory_config)
    redis_mgr, redis_tracker = await _redis_tracker(security_config_redis)
    try:
        redis_counts = await _send_mixed_sequence(redis_tracker, security_config_redis)
    finally:
        await redis_mgr.delete_pattern("behavior_*")
        await redis_mgr.close()
    assert memory_counts == redis_counts == [2, 4, 6, 7]


async def test_two_rule_hits_at_one_timestamp_count_two_in_redis(
    security_config_redis: SecurityConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    frozen = behavior_handler.time.time()
    monkeypatch.setattr(behavior_handler.time, "time", lambda: frozen)
    redis_mgr, tracker = await _redis_tracker(security_config_redis)
    try:
        await _one_request(
            _processor(tracker, security_config_redis), _two_rule_route()
        )
        assert await tracker.count_recent_rule_hits(_IP, 300) == 2
    finally:
        await redis_mgr.delete_pattern("behavior_*")
        await redis_mgr.close()


async def test_recent_count_excludes_hits_outside_the_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [1_000_000.0]
    monkeypatch.setattr(behavior_handler.time, "time", lambda: clock[0])
    tracker = BehaviorTracker(SecurityConfig(enable_redis=False))
    rule = BehaviorRule(rule_type="usage", threshold=100, window=600)
    await tracker.track_endpoint_usage("route", _IP, rule)
    clock[0] += 400
    await tracker.track_endpoint_usage("route", _IP, rule)
    assert await tracker.count_recent_rule_hits(_IP, 300) == 1


async def test_recent_count_is_zero_for_an_empty_ip() -> None:
    tracker = BehaviorTracker(SecurityConfig(enable_redis=False))
    assert await tracker.count_recent_rule_hits("", 300) == 0


@pytest.mark.parametrize(
    ("route_rules", "global_rules", "redis_calls", "hits"),
    [
        ([_usage()], [], 1, 2),
        ([_usage("throttle")], [], 1, 2),
        ([], [_usage()], 1, 2),
        ([_usage(), _usage("throttle")], [], 2, 4),
    ],
    ids=["usage", "throttle", "global-usage", "usage-and-throttle"],
)
async def test_recent_rule_hit_rides_on_the_behavior_redis_call(
    security_config_redis: SecurityConfig,
    route_rules: list[BehaviorRule],
    global_rules: list[BehaviorRule],
    redis_calls: int,
    hits: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redis_mgr, tracker = await _redis_tracker(security_config_redis)
    processor = _processor(tracker, security_config_redis)
    route_config = _route(*route_rules)
    real_connection = redis_mgr.get_connection
    calls: list[int] = []

    def counting_connection() -> Any:
        calls.append(1)
        return real_connection()

    try:
        await _one_request(processor, route_config, global_rules)
        monkeypatch.setattr(redis_mgr, "get_connection", counting_connection)
        await _one_request(processor, route_config, global_rules)
        assert len(calls) == redis_calls
        assert await tracker.count_recent_rule_hits(_IP, 300) == hits
    finally:
        await redis_mgr.delete_pattern("behavior_*")
        await redis_mgr.close()


_PARITY_HITS = [10.0 * n for n in range(30)]
_PARITY_CASES: dict[str, tuple[list[BehaviorRule], list[float], float, int]] = {
    "60s-rule-hit-every-10s-for-290s": (
        [BehaviorRule("usage", threshold=1000, window=60)],
        _PARITY_HITS,
        295.0,
        7,
    ),
    "600s-rule-same-hits": (
        [BehaviorRule("usage", threshold=1000, window=600)],
        _PARITY_HITS,
        295.0,
        30,
    ),
    "two-rules-three-hits": (
        [
            BehaviorRule("usage", threshold=1000, window=60),
            BehaviorRule("frequency", threshold=1000, window=120),
        ],
        [1.0, 2.0, 3.0],
        4.0,
        6,
    ),
}


@pytest.mark.parametrize("backend", ["memory", "redis"])
@pytest.mark.parametrize("case", list(_PARITY_CASES))
async def test_recent_count_mirrors_the_in_memory_sum_on_both_backends(
    security_config_redis: SecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    case: str,
) -> None:
    rules, hits, counted_at, expected = _PARITY_CASES[case]
    clock = [0.0]
    monkeypatch.setattr(
        behavior_handler, "time", SimpleNamespace(time=lambda: clock[0])
    )
    redis_mgr = None
    tracker = BehaviorTracker(SecurityConfig(enable_redis=False))
    if backend == "redis":
        redis_mgr, tracker = await _redis_tracker(security_config_redis)
    try:
        for hit_at in hits:
            clock[0] = hit_at
            for rule in rules:
                await tracker.track_endpoint_usage("ep1", _IP, rule)
        clock[0] = counted_at
        assert await tracker.count_recent_rule_hits(_IP, 300) == expected
    finally:
        if redis_mgr is not None:
            await redis_mgr.delete_pattern("behavior_*")
            await redis_mgr.close()


@pytest.mark.parametrize("backend", ["memory", "redis"])
async def test_recent_count_refuses_a_window_beyond_300_seconds(
    security_config_redis: SecurityConfig, backend: str
) -> None:
    tracker = BehaviorTracker(SecurityConfig(enable_redis=False))
    if backend == "redis":
        tracker = BehaviorTracker(security_config_redis)
        await tracker.initialize_redis(redis_handler(security_config_redis))
    with pytest.raises(ValueError, match="at most 300"):
        await tracker.count_recent_rule_hits(_IP, 600)


async def test_rule_keys_and_the_index_live_at_least_300_seconds(
    security_config_redis: SecurityConfig,
) -> None:
    redis_mgr, tracker = await _redis_tracker(security_config_redis)
    prefix = f"{security_config_redis.redis_prefix}behavior_usage:"
    index = f"{prefix}{tracker._rule_hit_index(_IP)[0]}"
    short = BehaviorRule("usage", threshold=1000, window=60)
    throttle = BehaviorRule("frequency", threshold=1000, window=30, action="throttle")
    long = BehaviorRule("usage", threshold=1000, window=600)
    ttls = []
    try:
        await tracker.track_endpoint_usage("ep1", _IP, short)
        await tracker.check_throttle(
            _IP, [ThrottleCheck(throttle, "ep1", True, 1000)], 1.0, False
        )
        async with redis_mgr.get_connection() as conn:
            for rule in (short, throttle):
                ttls.append(
                    await conn.ttl(f"{prefix}{usage_hits_key('ep1', _IP, rule)}")
                )
            ttls.append(await conn.ttl(index))
            await tracker.track_endpoint_usage("ep1", _IP, long)
            ttls.append(await conn.ttl(f"{prefix}{usage_hits_key('ep1', _IP, long)}"))
            ttls.append(await conn.ttl(index))
            assert len(await conn.smembers(index)) == 3
    finally:
        await redis_mgr.delete_pattern("behavior_*")
        await redis_mgr.close()
    assert all(290 < ttl <= 300 for ttl in ttls[:3])
    assert all(590 < ttl <= 600 for ttl in ttls[3:])
