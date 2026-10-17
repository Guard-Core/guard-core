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
    event_bus = MagicMock()
    event_bus.send_middleware_event = AsyncMock()
    context = BehavioralContext(
        config=config,
        logger=logging.getLogger("test_recent_event_count"),
        event_bus=event_bus,
        guard_decorator=decorator,
        middleware=MagicMock(suspicious_request_counts={}),
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
    request.state.guard_behavior_request_recorded = False
    return request


def _usage(action: Any = "log") -> BehaviorRule:
    return BehaviorRule(rule_type="usage", threshold=100, window=60, action=action)


def _stacked_route_config() -> RouteConfig:
    route_config = RouteConfig()
    route_config.behavior_rules = [
        BehaviorRule(rule_type="usage", threshold=100, window=60),
        BehaviorRule(rule_type="frequency", threshold=100, window=30),
    ]
    return route_config


async def test_recent_count_is_one_per_request_not_one_per_rule_in_memory() -> None:
    config = SecurityConfig(enable_redis=False)
    tracker = BehaviorTracker(config)
    processor = _processor(tracker, config)
    for _ in range(3):
        await processor.process_usage_rules(_request(), _IP, _stacked_route_config())
    assert await tracker.get_recent_event_count(_IP, 300) == 3
    assert await tracker.get_recent_event_count("198.51.100.1", 300) == 0


async def test_recent_count_is_backed_by_redis(
    security_config_redis: SecurityConfig,
) -> None:
    redis_mgr = redis_handler(security_config_redis)
    await redis_mgr.initialize()
    tracker = BehaviorTracker(security_config_redis)
    await tracker.initialize_redis(redis_mgr)
    processor = _processor(tracker, security_config_redis)
    try:
        for _ in range(3):
            await processor.process_usage_rules(
                _request(), _IP, _stacked_route_config()
            )
        assert await tracker.get_recent_event_count(_IP, 300) == 3
        other = BehaviorTracker(security_config_redis)
        await other.initialize_redis(redis_mgr)
        assert await other.get_recent_event_count(_IP, 300) == 3
    finally:
        await redis_mgr.delete_pattern("behavior_usage:*")
        await redis_mgr.close()


async def test_recent_count_excludes_requests_outside_the_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [1_000_000.0]
    monkeypatch.setattr(behavior_handler.time, "time", lambda: clock[0])
    tracker = BehaviorTracker(SecurityConfig(enable_redis=False))
    await tracker.track_endpoint_usage("route", _IP, _usage(), record_recent=True)
    clock[0] += 400
    await tracker.track_endpoint_usage("route", _IP, _usage(), record_recent=True)
    assert await tracker.get_recent_event_count(_IP, 300) == 1


async def test_recent_count_is_zero_for_an_empty_ip() -> None:
    tracker = BehaviorTracker(SecurityConfig(enable_redis=False))
    assert await tracker.get_recent_event_count("", 300) == 0


async def test_request_reaching_route_and_global_rules_is_counted_once() -> None:
    config = SecurityConfig(enable_redis=False)
    tracker = BehaviorTracker(config)
    processor = _processor(tracker, config)
    request = _request()
    await processor.process_usage_rules(request, _IP, _stacked_route_config())
    await processor.process_global_rules(
        request,
        MagicMock(),
        _IP,
        [BehaviorRule(rule_type="usage", threshold=100, window=60)],
    )
    assert await tracker.get_recent_event_count(_IP, 300) == 1


async def test_in_memory_recent_requests_stay_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(behavior_handler, "_MAX_RECENT_REQUESTS_PER_CLIENT", 5)
    tracker = BehaviorTracker(SecurityConfig(enable_redis=False))
    for _ in range(12):
        await tracker.track_endpoint_usage("route", _IP, _usage(), record_recent=True)
    assert await tracker.get_recent_event_count(_IP, 300) == 5


@pytest.mark.parametrize(
    ("route_rules", "global_rules", "redis_calls"),
    [
        ([_usage()], [], 1),
        ([_usage("throttle")], [], 1),
        ([], [_usage()], 1),
        ([_usage(), _usage("throttle")], [], 2),
    ],
    ids=["usage", "throttle", "global-usage", "usage-and-throttle"],
)
async def test_recent_request_rides_on_the_behavior_redis_call(
    security_config_redis: SecurityConfig,
    route_rules: list[BehaviorRule],
    global_rules: list[BehaviorRule],
    redis_calls: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redis_mgr = redis_handler(security_config_redis)
    await redis_mgr.initialize()
    tracker = BehaviorTracker(security_config_redis)
    await tracker.initialize_redis(redis_mgr)
    processor = _processor(tracker, security_config_redis)
    route_config = RouteConfig()
    route_config.behavior_rules = route_rules
    real_connection = redis_mgr.get_connection
    calls: list[int] = []

    def counting_connection() -> Any:
        calls.append(1)
        return real_connection()

    async def one_request() -> None:
        request = _request()
        await processor.process_usage_rules(request, _IP, route_config)
        await processor.process_global_rules(request, MagicMock(), _IP, global_rules)

    try:
        await one_request()
        monkeypatch.setattr(redis_mgr, "get_connection", counting_connection)
        await one_request()
        assert len(calls) == redis_calls
        assert await tracker.get_recent_event_count(_IP, 300) == 2
    finally:
        await redis_mgr.delete_pattern("behavior_*")
        await redis_mgr.close()
