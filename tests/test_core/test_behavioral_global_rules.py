import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from guard_core.core.behavioral.context import BehavioralContext
from guard_core.core.behavioral.processor import BehavioralProcessor
from guard_core.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardResponse


def _build_processor(
    suspicious_counts: dict[str, dict[str, int]] | None = None,
    *,
    guard_decorator: Any = "default",
    middleware_tracker: BehaviorTracker | None = None,
    middleware: Any = "default",
) -> tuple[BehavioralProcessor, MagicMock, BehaviorTracker]:
    config = SecurityConfig()
    event_bus = MagicMock()
    event_bus.send_middleware_event = AsyncMock()
    tracker = middleware_tracker or BehaviorTracker(config)

    if guard_decorator == "default":
        decorator = MagicMock()
        decorator.behavior_tracker = tracker
        guard_decorator = decorator

    if middleware == "default":
        middleware = MagicMock()
        middleware.suspicious_request_counts = suspicious_counts or {}

    context = BehavioralContext(
        config=config,
        logger=logging.getLogger("test_behavioral_global"),
        event_bus=event_bus,
        guard_decorator=guard_decorator,
        behavior_tracker=tracker if guard_decorator is None else None,
        middleware=middleware,
    )
    processor = BehavioralProcessor(context)
    return processor, event_bus, tracker


def _make_request() -> MagicMock:
    request = MagicMock()
    request.method = "GET"
    request.url_path = "/x"
    request.state = MagicMock()
    request.state.guard_endpoint_id = None
    request.state.guard_decorator = None
    return request


async def test_global_return_rules_process_without_correlation() -> None:
    processor, event_bus, _ = _build_processor()
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=2,
        pattern="status:404",
        action="log",
    )
    request = _make_request()
    response = MockGuardResponse("not found", status_code=404)
    for _ in range(3):
        await processor.process_global_return_rules(
            request, response, "1.2.3.4", [rule]
        )
    events = list(event_bus.send_middleware_event.call_args_list)
    assert any(c.kwargs.get("violation_type") == "return_pattern" for c in events)


async def test_correlation_halves_threshold_when_ip_has_detections() -> None:
    processor, event_bus, _ = _build_processor(
        suspicious_counts={"1.2.3.4": {"xss": 1}}
    )
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=10,
        pattern="status:404",
        action="log",
        correlate_with_detection=True,
    )
    request = _make_request()
    response = MockGuardResponse("not found", status_code=404)
    for _ in range(5):
        await processor.process_global_return_rules(
            request, response, "1.2.3.4", [rule]
        )
    assert event_bus.send_middleware_event.call_count == 0
    await processor.process_global_return_rules(request, response, "1.2.3.4", [rule])
    assert event_bus.send_middleware_event.call_count == 1
    call = event_bus.send_middleware_event.call_args_list[-1]
    assert call.kwargs["violation_type"] == "return_pattern"
    assert call.kwargs["correlation"] is True
    assert call.kwargs["correlated_categories"] == ["xss"]
    assert call.kwargs["threshold"] == 5


async def test_correlation_does_not_fire_when_ip_clean() -> None:
    processor, event_bus, _ = _build_processor(suspicious_counts={})
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=10,
        pattern="status:404",
        action="log",
        correlate_with_detection=True,
    )
    request = _make_request()
    response = MockGuardResponse("not found", status_code=404)
    for _ in range(10):
        await processor.process_global_return_rules(
            request, response, "1.2.3.4", [rule]
        )
    assert event_bus.send_middleware_event.call_count == 0


async def test_correlation_halves_threshold_floor_at_one() -> None:
    processor, event_bus, _ = _build_processor(
        suspicious_counts={"1.2.3.4": {"sqli": 1}}
    )
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=1,
        pattern="status:404",
        action="log",
        correlate_with_detection=True,
    )
    request = _make_request()
    response = MockGuardResponse("not found", status_code=404)
    await processor.process_global_return_rules(request, response, "1.2.3.4", [rule])
    assert event_bus.send_middleware_event.call_count == 0
    await processor.process_global_return_rules(request, response, "1.2.3.4", [rule])
    assert event_bus.send_middleware_event.call_count == 1


async def test_global_return_rules_use_middleware_tracker_without_decorator() -> None:
    config = SecurityConfig()
    tracker = BehaviorTracker(config)
    processor, event_bus, _ = _build_processor(
        guard_decorator=None,
        middleware_tracker=tracker,
    )
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=1,
        pattern="status:404",
        action="log",
    )
    request = _make_request()
    response = MockGuardResponse("not found", status_code=404)
    await processor.process_global_return_rules(request, response, "1.2.3.4", [rule])
    assert event_bus.send_middleware_event.call_count == 0
    await processor.process_global_return_rules(request, response, "1.2.3.4", [rule])
    assert event_bus.send_middleware_event.call_count == 1


async def test_global_return_rules_short_circuit_when_no_tracker() -> None:
    processor, event_bus, _ = _build_processor(guard_decorator=None)
    processor.context.behavior_tracker = None

    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=1,
        pattern="status:404",
        action="log",
    )
    request = _make_request()
    response = MockGuardResponse("not found", status_code=404)
    await processor.process_global_return_rules(request, response, "1.2.3.4", [rule])
    assert event_bus.send_middleware_event.call_count == 0


async def test_global_return_rules_handle_missing_middleware() -> None:
    processor, event_bus, _ = _build_processor(middleware=None)
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=1,
        pattern="status:404",
        action="log",
        correlate_with_detection=True,
    )
    request = _make_request()
    response = MockGuardResponse("not found", status_code=404)
    await processor.process_global_return_rules(request, response, "1.2.3.4", [rule])
    assert event_bus.send_middleware_event.call_count == 0
    await processor.process_global_return_rules(request, response, "1.2.3.4", [rule])
    assert event_bus.send_middleware_event.call_count == 1
    call = event_bus.send_middleware_event.call_args_list[-1]
    assert call.kwargs["correlation"] is False
    assert call.kwargs["correlated_categories"] == []


async def test_global_return_rules_zero_count_ignored_for_correlation() -> None:
    processor, event_bus, _ = _build_processor(
        suspicious_counts={"1.2.3.4": {"xss": 0}}
    )
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=4,
        pattern="status:404",
        action="log",
        correlate_with_detection=True,
    )
    request = _make_request()
    response = MockGuardResponse("not found", status_code=404)
    for _ in range(4):
        await processor.process_global_return_rules(
            request, response, "1.2.3.4", [rule]
        )
    assert event_bus.send_middleware_event.call_count == 0
    await processor.process_global_return_rules(request, response, "1.2.3.4", [rule])
    assert event_bus.send_middleware_event.call_count == 1
    call = event_bus.send_middleware_event.call_args_list[-1]
    assert call.kwargs["correlation"] is False


async def test_global_return_rules_apply_action_invoked() -> None:
    config = SecurityConfig()
    tracker = MagicMock(spec=BehaviorTracker)
    tracker.track_return_pattern = AsyncMock(return_value=True)
    tracker.apply_action = AsyncMock()
    event_bus = MagicMock()
    event_bus.send_middleware_event = AsyncMock()
    middleware = MagicMock()
    middleware.suspicious_request_counts = {}
    context = BehavioralContext(
        config=config,
        logger=logging.getLogger("t"),
        event_bus=event_bus,
        guard_decorator=None,
        behavior_tracker=tracker,
        middleware=middleware,
    )
    processor = BehavioralProcessor(context)
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=1,
        pattern="status:404",
        action="ban",
    )
    request = _make_request()
    response = MockGuardResponse("not found", status_code=404)
    await processor.process_global_return_rules(request, response, "1.2.3.4", [rule])
    tracker.apply_action.assert_called_once()
