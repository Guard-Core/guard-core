import logging
from typing import Any
from unittest.mock import MagicMock

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.behavioral.context import BehavioralContext
from guard_core.sync.core.behavioral.processor import BehavioralProcessor
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from tests.test_sync.conftest import MockGuardResponse

_IP = "203.0.113.77"


class _Agent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def send_event(self, event: Any) -> None:
        self.events.append(event)


def _processor() -> tuple[BehavioralProcessor, _Agent]:
    config = SyncSecurityConfig(enable_redis=False)
    event_bus = MagicMock()
    event_bus.send_middleware_event = MagicMock()
    tracker = BehaviorTracker(config)
    agent = _Agent()
    tracker.agent_handler = agent
    context = BehavioralContext(
        config=config,
        logger=logging.getLogger("test_behavioral_rule_attribution"),
        event_bus=event_bus,
        guard_decorator=None,
        behavior_tracker=tracker,
        middleware=MagicMock(suspicious_request_counts={}),
    )
    return BehavioralProcessor(context), agent


def _request(path: str) -> MagicMock:
    request = MagicMock()
    request.method = "GET"
    request.url_path = path
    request.state = MagicMock()
    request.state.guard_endpoint_id = None
    request.state.guard_route_id = path
    request.state.guard_decorator = None
    request.state.guard_exclusion_scoped = False
    return request


def _route(rule: BehaviorRule) -> RouteConfig:
    route_config = RouteConfig()
    route_config.behavior_rules = [rule]
    return route_config


def _assert_attributed(agent: _Agent, rule: BehaviorRule) -> None:
    [event] = [e for e in agent.events if e.event_type == "behavioral_violation"]
    assert event.metadata["matched_rule_type"] == "behavioral"
    assert event.metadata["matched_rule_id"] == rule.matched_rule_id()
    assert event.metadata["rule_type"] == rule.rule_type


def test_the_route_usage_path_carries_the_behavioral_attribution() -> None:
    processor, agent = _processor()
    rule = BehaviorRule(rule_type="usage", threshold=1, window=60, action="log")
    for _ in range(2):
        processor.process_usage_rules(_request("/u"), _IP, _route(rule))
    _assert_attributed(agent, rule)


def test_the_route_return_pattern_path_carries_the_behavioral_attribution() -> None:
    processor, agent = _processor()
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=1,
        window=60,
        pattern="status:404",
        action="log",
    )
    for _ in range(2):
        processor.process_return_rules(
            _request("/r"), MockGuardResponse("no", status_code=404), _IP, _route(rule)
        )
    _assert_attributed(agent, rule)


def test_the_global_usage_path_carries_the_behavioral_attribution() -> None:
    processor, agent = _processor()
    rule = BehaviorRule(rule_type="usage", threshold=1, window=60, action="log")
    for path in ("/a", "/b"):
        processor.process_global_rules(
            _request(path), MockGuardResponse("ok"), _IP, [rule]
        )
    _assert_attributed(agent, rule)


def test_the_global_return_pattern_path_carries_the_behavioral_attribution() -> None:
    processor, agent = _processor()
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=1,
        window=60,
        pattern="status:404",
        action="log",
    )
    for path in ("/a", "/b"):
        processor.process_global_rules(
            _request(path), MockGuardResponse("no", status_code=404), _IP, [rule]
        )
    _assert_attributed(agent, rule)
