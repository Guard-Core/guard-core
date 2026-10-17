import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from guard_core.core.behavioral.context import BehavioralContext
from guard_core.core.behavioral.processor import BehavioralProcessor
from guard_core.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.models import SecurityConfig


def _global_processor() -> tuple[BehavioralProcessor, MagicMock]:
    config = SecurityConfig(enable_redis=False)
    event_bus = MagicMock()
    event_bus.send_middleware_event = AsyncMock()
    tracker = BehaviorTracker(config)
    decorator: Any = MagicMock()
    decorator.behavior_tracker = tracker
    context = BehavioralContext(
        config=config,
        logger=logging.getLogger("test_global_usage"),
        event_bus=event_bus,
        guard_decorator=decorator,
        middleware=MagicMock(suspicious_request_counts={}),
    )
    return BehavioralProcessor(context), event_bus


def _request_for(path: str) -> MagicMock:
    request = MagicMock()
    request.method = "GET"
    request.url_path = path
    request.state = MagicMock()
    request.state.guard_endpoint_id = None
    request.state.guard_route_id = None
    request.state.guard_decorator = None
    return request


async def test_global_usage_rule_counts_one_ip_across_all_endpoints() -> None:
    processor, event_bus = _global_processor()
    rule = BehaviorRule(rule_type="usage", threshold=2, window=60, action="log")
    for path in ("/a", "/b", "/c"):
        await processor.process_global_rules(
            _request_for(path), MagicMock(), "1.2.3.4", [rule]
        )
    events = event_bus.send_middleware_event.call_args_list
    assert [c.kwargs["violation_type"] for c in events] == ["usage"]
    assert events[0].kwargs["decorator_type"] == "behavioral_global"


async def test_global_frequency_rule_fires_and_other_ip_does_not() -> None:
    processor, event_bus = _global_processor()
    rule = BehaviorRule(rule_type="frequency", threshold=1, window=60, action="log")
    await processor.process_global_rules(
        _request_for("/a"), MagicMock(), "1.2.3.4", [rule]
    )
    await processor.process_global_rules(
        _request_for("/a"), MagicMock(), "5.6.7.8", [rule]
    )
    assert event_bus.send_middleware_event.call_count == 0
    await processor.process_global_rules(
        _request_for("/b"), MagicMock(), "1.2.3.4", [rule]
    )
    events = event_bus.send_middleware_event.call_args_list
    assert [c.kwargs["violation_type"] for c in events] == ["frequency"]
