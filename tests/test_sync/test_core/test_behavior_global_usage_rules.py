import logging
from typing import Any
from unittest.mock import MagicMock

from guard_core.models import BehaviorRuleConfig, SyncSecurityConfig
from guard_core.sync.core.behavioral.context import BehavioralContext
from guard_core.sync.core.behavioral.processor import BehavioralProcessor
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from tests.test_sync.conftest import MockGuardResponse


def _global_processor() -> tuple[BehavioralProcessor, MagicMock]:
    config = SyncSecurityConfig(enable_redis=False)
    event_bus = MagicMock()
    event_bus.send_middleware_event = MagicMock()
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


def test_global_usage_rule_counts_one_ip_across_all_endpoints() -> None:
    processor, event_bus = _global_processor()
    rule = BehaviorRule(rule_type="usage", threshold=2, window=60, action="log")
    for path in ("/a", "/b", "/c"):
        processor.process_global_rules(
            _request_for(path), MagicMock(), "1.2.3.4", [rule]
        )
    events = event_bus.send_middleware_event.call_args_list
    assert [c.kwargs["violation_type"] for c in events] == ["usage"]
    assert events[0].kwargs["decorator_type"] == "behavioral_global"


def test_global_frequency_rule_fires_and_other_ip_does_not() -> None:
    processor, event_bus = _global_processor()
    rule = BehaviorRule(rule_type="frequency", threshold=1, window=60, action="log")
    processor.process_global_rules(_request_for("/a"), MagicMock(), "1.2.3.4", [rule])
    processor.process_global_rules(_request_for("/a"), MagicMock(), "5.6.7.8", [rule])
    assert event_bus.send_middleware_event.call_count == 0
    processor.process_global_rules(_request_for("/b"), MagicMock(), "1.2.3.4", [rule])
    events = event_bus.send_middleware_event.call_args_list
    assert [c.kwargs["violation_type"] for c in events] == ["frequency"]


def test_global_return_rule_counts_one_ip_across_all_endpoints() -> None:
    processor, event_bus = _global_processor()
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=2,
        window=60,
        pattern="status:404",
        action="log",
    )
    for path in ("/missing-a", "/missing-b", "/missing-c"):
        processor.process_global_rules(
            _request_for(path),
            MockGuardResponse("not found", status_code=404),
            "1.2.3.4",
            [rule],
        )
    events = event_bus.send_middleware_event.call_args_list
    assert [c.kwargs["violation_type"] for c in events] == ["return_pattern"]
    assert events[0].kwargs["decorator_type"] == "behavioral_global"


def test_global_return_rule_counts_other_ips_separately() -> None:
    processor, event_bus = _global_processor()
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=1,
        window=60,
        pattern="status:404",
        action="log",
    )
    for ip in ("1.2.3.4", "5.6.7.8"):
        processor.process_global_rules(
            _request_for("/x"),
            MockGuardResponse("not found", status_code=404),
            ip,
            [rule],
        )
    assert event_bus.send_middleware_event.call_count == 0


_DUPLICATE_RULE = BehaviorRuleConfig(
    rule_type="return_pattern", threshold=2, pattern="status:404"
)
_BAN_RULE = BehaviorRuleConfig(
    rule_type="return_pattern", threshold=2, pattern="status:404", action="ban"
)


def test_exact_duplicate_global_rules_are_dropped_at_construction() -> None:
    config = SyncSecurityConfig(
        enable_redis=False,
        global_behavior_rules=(_DUPLICATE_RULE, _BAN_RULE, _DUPLICATE_RULE),
    )
    assert config.global_behavior_rules == (_DUPLICATE_RULE, _BAN_RULE)


def test_exact_duplicate_global_rules_are_dropped_on_assignment() -> None:
    config = SyncSecurityConfig(enable_redis=False)
    config.global_behavior_rules = (_BAN_RULE, _BAN_RULE)
    assert config.global_behavior_rules == (_BAN_RULE,)


def test_exact_duplicate_global_rules_are_dropped_on_model_copy() -> None:
    config = SyncSecurityConfig(enable_redis=False)
    copied = config.model_copy(
        update={"global_behavior_rules": (_DUPLICATE_RULE, _DUPLICATE_RULE)}
    )
    assert copied.global_behavior_rules == (_DUPLICATE_RULE,)


def test_global_rules_run_without_decorator_and_without_enrichment() -> None:
    config = SyncSecurityConfig(enable_redis=False, enable_enrichment=False)
    initializer = HandlerInitializer(config=config, guard_decorator=None)
    event_bus = MagicMock()
    event_bus.send_middleware_event = MagicMock()
    context = BehavioralContext(
        config=config,
        logger=logging.getLogger("test_global_usage"),
        event_bus=event_bus,
        guard_decorator=None,
        behavior_tracker=initializer.behavior_tracker,
    )
    processor = BehavioralProcessor(context)
    rule = BehaviorRule(rule_type="usage", threshold=1, window=60, action="log")
    for _ in range(2):
        processor.process_global_rules(
            _request_for("/a"), MagicMock(), "1.2.3.4", [rule]
        )
    assert event_bus.send_middleware_event.call_count == 1


class _RecordingAgent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def send_event(self, event: Any) -> None:
        self.events.append(event)

    def send_metric(self, _: Any) -> None:
        return None

    def initialize_redis(self, _: Any) -> None:
        return None

    def flush_buffer(self) -> None:
        return None

    def get_dynamic_rules(self) -> Any | None:
        return None

    def health_check(self) -> bool:
        return True

    def get_stats(self) -> dict[str, Any]:
        return {}


def test_global_rule_without_decorator_sends_behavioral_violation() -> None:
    config = SyncSecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="a" * 10,
        enable_enrichment=False,
    )
    agent = _RecordingAgent()
    initializer = HandlerInitializer(config=config, agent_handler=agent)
    initializer.initialize_agent_integrations()
    event_bus = MagicMock()
    event_bus.send_middleware_event = MagicMock()
    context = BehavioralContext(
        config=config,
        logger=logging.getLogger("test_global_usage"),
        event_bus=event_bus,
        guard_decorator=None,
        behavior_tracker=initializer.behavior_tracker,
    )
    processor = BehavioralProcessor(context)
    rule = BehaviorRule(rule_type="usage", threshold=1, window=60, action="log")
    for _ in range(2):
        processor.process_global_rules(
            _request_for("/a"), MagicMock(), "1.2.3.4", [rule]
        )
    assert [event.event_type for event in agent.events] == ["behavioral_violation"]
    assert event_bus.send_middleware_event.call_count == 1
