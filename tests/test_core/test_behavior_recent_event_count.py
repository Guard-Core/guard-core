import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.behavioral.context import BehavioralContext
from guard_core.core.behavioral.processor import BehavioralProcessor
from guard_core.decorators.base import RouteConfig
from guard_core.handlers import behavior_handler
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
