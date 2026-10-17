import logging
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import BehaviorRuleConfig, SecurityConfig
from guard_core.sync._utils import sampling
from guard_core.sync.core.behavioral import _throttle
from guard_core.sync.core.behavioral.context import BehavioralContext
from guard_core.sync.core.behavioral.processor import BehavioralProcessor
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers import _behavior_throttle, behavior_handler
from guard_core.sync.handlers._behavior_throttle import (
    ThrottleCheck,
    bucket_key,
    usage_hits_key,
)
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.sync.handlers.redis_handler import redis_handler
from tests.test_sync.conftest import MockGuardResponse, MockGuardResponseFactory

_IP = "203.0.113.50"
_ENDPOINT = "module.view"
_T0 = 1_900_000_000.0


class _Clock:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.now = _T0
        self.mono = 10_000.0
        fake_time = SimpleNamespace(time=lambda: self.now)
        monkeypatch.setattr(_throttle, "time", fake_time)
        monkeypatch.setattr(behavior_handler, "time", fake_time)
        monkeypatch.setattr(
            sampling, "time", SimpleNamespace(monotonic=lambda: self.mono)
        )

    def advance(self, seconds: float) -> None:
        self.now += seconds
        self.mono += seconds


class _Middleware:
    def __init__(self, config: SecurityConfig) -> None:
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self._factory = ErrorResponseFactory(
            ResponseContext(
                config=config,
                logger=logging.getLogger("test_throttle"),
                metrics_collector=MagicMock(),
                response_factory=MockGuardResponseFactory(),
            )
        )

    def create_error_response(self, status_code: int, default_message: str) -> Any:
        return self._factory.create_error_response(status_code, default_message)


class _Agent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def send_event(self, event: Any) -> None:
        self.events.append(event)


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {"enable_redis": False}
    fields.update(overrides)
    return SecurityConfig(**fields)


def _processor(
    config: SecurityConfig,
    tracker: BehaviorTracker,
    middleware: bool = True,
    decorator: Any = None,
) -> tuple[BehavioralProcessor, MagicMock, _Agent]:
    event_bus = MagicMock()
    event_bus.send_middleware_event = MagicMock()
    agent = _Agent()
    tracker.agent_handler = agent
    context = BehavioralContext(
        config=config,
        logger=logging.getLogger("test_throttle"),
        event_bus=event_bus,
        guard_decorator=decorator,
        behavior_tracker=tracker,
        middleware=_Middleware(config) if middleware else None,
    )
    return BehavioralProcessor(context), event_bus, agent


def _request(path: str = "/x", route_id: str | None = _ENDPOINT) -> MagicMock:
    request = MagicMock()
    request.method = "GET"
    request.url_path = path
    request.state = MagicMock()
    request.state.guard_endpoint_id = None
    request.state.guard_route_id = route_id
    request.state.guard_decorator = None
    request.state.guard_exclusion_scoped = False
    return request


def _route(*rules: BehaviorRule) -> RouteConfig:
    route_config = RouteConfig()
    route_config.behavior_rules = list(rules)
    return route_config


def _throttle_rule(
    threshold: int, window: int = 60, rule_type: Any = "usage", **kw: Any
) -> BehaviorRule:
    return BehaviorRule(
        rule_type=rule_type,
        threshold=threshold,
        window=window,
        action="throttle",
        **kw,
    )


def _statuses(
    processor: BehavioralProcessor,
    clock: _Clock,
    route_config: RouteConfig | None,
    count: int,
    step: float = 1.0,
) -> list[Any]:
    results: list[Any] = []
    for _ in range(count):
        response = processor.process_usage_rules(_request(), _IP, route_config)
        results.append(
            None
            if response is None
            else (response.status_code, response.headers.get("Retry-After"))
        )
        clock.advance(step)
    return results


@contextmanager
def _redis(config: SecurityConfig) -> Iterator[Any]:
    manager = redis_handler(config)
    manager.initialize()
    try:
        yield manager
    finally:
        manager.delete_pattern("behavior_*")
        manager.close()


def test_route_usage_throttle_answers_429_from_the_threshold_in_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config()
    processor, _, _ = _processor(config, BehaviorTracker(config))
    route = _route(_throttle_rule(3))
    assert _statuses(processor, clock, route, 5) == [
        None,
        None,
        None,
        (429, "57"),
        (429, "56"),
    ]


def test_frequency_throttle_refuses_like_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config()
    processor, _, _ = _processor(config, BehaviorTracker(config))
    route = _route(_throttle_rule(2, window=10, rule_type="frequency"))
    assert _statuses(processor, clock, route, 3) == [None, None, (429, "8")]


def test_custom_action_overrides_throttle_and_is_never_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config()
    processor, _, _ = _processor(config, BehaviorTracker(config))
    acted_on: list[str] = []

    def custom_action(client_ip: str, endpoint_id: str, details: str) -> None:
        acted_on.append(client_ip)

    route = _route(_throttle_rule(2, custom_action=custom_action))
    assert _statuses(processor, clock, route, 4) == [None] * 4
    assert acted_on == [_IP, _IP]


def test_throttle_429_uses_custom_error_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config(custom_error_responses={429: "Slow down"})
    processor, _, _ = _processor(config, BehaviorTracker(config))
    route = _route(_throttle_rule(1))
    processor.process_usage_rules(_request(), _IP, route)
    clock.advance(1)
    response = processor.process_usage_rules(_request(), _IP, route)
    assert response is not None
    assert (response.status_code, response.body) == (429, b"Slow down")


def test_client_is_admitted_again_once_its_count_falls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config()
    processor, _, _ = _processor(config, BehaviorTracker(config))
    route = _route(_throttle_rule(2, window=10))
    assert _statuses(processor, clock, route, 3) == [None, None, (429, "8")]
    clock.advance(7.5)
    assert _statuses(processor, clock, route, 2, step=0.2) == [None, (429, "1")]


def test_retry_after_is_clamped_to_the_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config()
    processor, _, _ = _processor(config, BehaviorTracker(config))
    route = _route(_throttle_rule(1, window=5))
    assert _statuses(processor, clock, route, 2, step=0) == [None, (429, "5")]
    clock.advance(4.99)
    assert _statuses(processor, clock, route, 1) == [(429, "1")]


def test_route_usage_throttle_is_shared_over_redis(
    monkeypatch: pytest.MonkeyPatch, security_config_redis: SecurityConfig
) -> None:
    clock = _Clock(monkeypatch)
    with _redis(security_config_redis) as manager:
        trackers = [BehaviorTracker(security_config_redis) for _ in range(2)]
        processors = []
        for tracker in trackers:
            tracker.initialize_redis(manager)
            processors.append(_processor(security_config_redis, tracker)[0])
        route = _route(_throttle_rule(3))
        results = []
        for n in range(5):
            response = processors[n % 2].process_usage_rules(_request(), _IP, route)
            results.append(
                None
                if response is None
                else (
                    response.status_code,
                    response.body,
                    response.headers["Retry-After"],
                )
            )
            clock.advance(1)
        assert results == [
            None,
            None,
            None,
            (429, b"Custom Too Many Requests", "57"),
            (429, b"Custom Too Many Requests", "56"),
        ]


def test_global_usage_throttle_covers_unrouted_requests_across_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config(
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="usage", threshold=2, window=60, action="throttle"
            ),
        )
    )
    processor, _, _ = _processor(config, BehaviorTracker(config))
    results = []
    for n in range(3):
        response = processor.process_usage_rules(
            _request(f"/missing-{n}", route_id=None), _IP, None
        )
        results.append(None if response is None else response.status_code)
        clock.advance(1)
    assert results == [None, None, 429]


def test_global_usage_throttle_is_recorded_once_per_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config(
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="usage", threshold=3, window=60, action="throttle"
            ),
        )
    )
    processor, _, _ = _processor(config, BehaviorTracker(config))
    global_rules = list(processor._global_rules())
    results = []
    for _ in range(4):
        request = _request()
        response = processor.process_usage_rules(request, _IP, None)
        if response is None:
            processor.process_global_rules(
                request, MockGuardResponse(status_code=200), _IP, global_rules
            )
        results.append(None if response is None else response.status_code)
        clock.advance(1)
    assert results == [None, None, None, 429]


def test_a_refusing_rule_records_no_hit_for_the_other_rules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _Clock(monkeypatch)
    config = _config()
    tracker = BehaviorTracker(config)
    processor, _, _ = _processor(config, tracker)
    tight, loose = _throttle_rule(2), _throttle_rule(10)
    route = _route(tight, loose)
    for _ in range(4):
        processor.process_usage_rules(_request(), _IP, route)
    assert len(tracker.usage_counts[bucket_key(_ENDPOINT, loose)][_IP]) == 2
    assert len(tracker.usage_counts[bucket_key(_ENDPOINT, tight)][_IP]) == 2


def test_a_refusing_rule_records_no_hit_for_the_other_rules_over_redis(
    monkeypatch: pytest.MonkeyPatch, security_config_redis: SecurityConfig
) -> None:
    _Clock(monkeypatch)
    with _redis(security_config_redis) as manager:
        tracker = BehaviorTracker(security_config_redis)
        tracker.initialize_redis(manager)
        processor, _, _ = _processor(security_config_redis, tracker)
        tight, loose = _throttle_rule(2), _throttle_rule(10)
        route = _route(tight, loose)
        for _ in range(4):
            processor.process_usage_rules(_request(), _IP, route)
        prefix = security_config_redis.redis_prefix
        with manager.get_connection() as conn:
            loose_key = (
                f"{prefix}behavior_usage:{usage_hits_key(_ENDPOINT, _IP, loose)}"
            )
            assert conn.zcard(loose_key) == 2


def test_redis_script_is_reloaded_after_a_script_flush(
    monkeypatch: pytest.MonkeyPatch, security_config_redis: SecurityConfig
) -> None:
    clock = _Clock(monkeypatch)
    with _redis(security_config_redis) as manager:
        tracker = BehaviorTracker(security_config_redis)
        tracker.initialize_redis(manager)
        processor, _, _ = _processor(security_config_redis, tracker)
        route = _route(_throttle_rule(1))
        assert _statuses(processor, clock, route, 1) == [None]
        with manager.get_connection() as conn:
            conn.script_flush()
        response = processor.process_usage_rules(_request(), _IP, route)
        assert response is not None and response.status_code == 429


class _BrokenRedis:
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config

    def record_sliding_window_hit(self, *args: Any) -> int:
        return 0

    @contextmanager
    def get_connection(self) -> Iterator[Any]:
        if self.config.enable_redis:
            raise ConnectionError("redis down")
        yield None


def _broken_redis_tracker(config: SecurityConfig) -> BehaviorTracker:
    tracker = BehaviorTracker(config)
    tracker.redis_handler = _BrokenRedis(config)
    return tracker


def test_redis_failure_fails_open_to_memory_with_one_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    clock = _Clock(monkeypatch)
    monkeypatch.setattr(_behavior_throttle, "_redis_fail_open_warned", False)
    config = _config(enable_redis=True, redis_fail_open=True)
    processor, _, _ = _processor(config, _broken_redis_tracker(config))
    with caplog.at_level(logging.WARNING):
        results = _statuses(processor, clock, _route(_throttle_rule(1)), 3)
    assert [r if r is None else r[0] for r in results] == [None, 429, 429]
    warnings = [r for r in caplog.records if "behavior throttle rules" in r.message]
    assert len(warnings) == 1


def test_redis_failure_fails_secure_with_500(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _Clock(monkeypatch)
    config = _config(enable_redis=True, redis_fail_open=False, fail_secure=True)
    processor, _, _ = _processor(config, _broken_redis_tracker(config))
    with caplog.at_level(logging.ERROR):
        response = processor.process_usage_rules(
            _request(), _IP, _route(_throttle_rule(1))
        )
    assert response is not None
    assert (response.status_code, response.body) == (500, b"Security check failed")
    assert any(
        "Error in behavior throttle (GuardRedisError)" in r.message
        for r in caplog.records
    )


def test_redis_failure_admits_when_not_fail_secure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _Clock(monkeypatch)
    config = _config(enable_redis=True, redis_fail_open=False, fail_secure=False)
    processor, _, _ = _processor(config, _broken_redis_tracker(config))
    assert (
        processor.process_usage_rules(_request(), _IP, _route(_throttle_rule(1)))
        is None
    )


def test_redis_failure_without_middleware_admits_even_when_fail_secure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _Clock(monkeypatch)
    config = _config(enable_redis=True, redis_fail_open=False, fail_secure=True)
    processor, _, _ = _processor(
        config, _broken_redis_tracker(config), middleware=False
    )
    assert (
        processor.process_usage_rules(_request(), _IP, _route(_throttle_rule(1)))
        is None
    )


def _serve_404s(
    processor: BehavioralProcessor,
    clock: _Clock,
    route: RouteConfig | None,
    count: int,
) -> list[int]:
    statuses = []
    for _ in range(count):
        request = _request()
        refused = processor.process_usage_rules(request, _IP, route)
        if refused is not None:
            statuses.append(refused.status_code)
        else:
            response = MockGuardResponse(status_code=404)
            if route is not None:
                processor.process_return_rules(request, response, _IP, route)
            processor.process_global_rules(
                request, response, _IP, list(processor._global_rules())
            )
            statuses.append(404)
        clock.advance(1)
    return statuses


def test_route_return_throttle_serves_threshold_plus_one_then_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config()
    processor, event_bus, _ = _processor(config, BehaviorTracker(config))
    route = _route(_throttle_rule(2, rule_type="return_pattern", pattern="status:404"))
    assert _serve_404s(processor, clock, route, 3) == [404, 404, 404]
    assert event_bus.send_middleware_event.call_count == 0
    assert _serve_404s(processor, clock, route, 2) == [429, 429]


def test_global_return_throttle_uses_the_correlated_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config(
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="return_pattern",
                threshold=4,
                window=60,
                pattern="status:404",
                action="throttle",
                correlate_with_detection=True,
            ),
        )
    )
    processor, _, _ = _processor(config, BehaviorTracker(config))
    middleware = processor.context.middleware
    assert middleware is not None
    middleware.suspicious_request_counts[_IP] = {"xss": 1}
    assert _serve_404s(processor, clock, None, 5) == [404, 404, 404, 429, 429]


def test_global_return_throttle_without_correlation_uses_the_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config(
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="return_pattern",
                threshold=2,
                window=60,
                pattern="status:404",
                action="throttle",
                correlate_with_detection=True,
            ),
        )
    )
    processor, _, _ = _processor(config, BehaviorTracker(config))
    assert _serve_404s(processor, clock, None, 4) == [404, 404, 404, 429]


def test_throttled_requests_count_toward_a_route_ban_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config()
    tracker = BehaviorTracker(config)
    processor, _, _ = _processor(config, tracker)
    fired: list[int] = []
    original = tracker.apply_action

    def record(rule: BehaviorRule, *args: Any, **kwargs: Any) -> str:
        if rule.action == "ban":
            fired.append(len(results) + 1)
        return original(rule, *args, **kwargs)

    monkeypatch.setattr(tracker, "apply_action", record)
    route = _route(
        _throttle_rule(2),
        BehaviorRule(rule_type="usage", threshold=4, window=60, action="ban"),
    )
    results: list[Any] = []
    for _ in range(6):
        response = processor.process_usage_rules(_request(), _IP, route)
        results.append(None if response is None else response.status_code)
        clock.advance(1)
    assert results == [None, None, 429, 429, 429, 429]
    assert fired == [5, 6]


def test_throttled_requests_count_toward_global_rules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config(
        global_behavior_rules=(
            BehaviorRuleConfig(rule_type="usage", threshold=4, window=60, action="ban"),
        )
    )
    tracker = BehaviorTracker(config)
    processor, _, _ = _processor(config, tracker)
    fired: list[int] = []
    current = [0]
    original = tracker.apply_action

    def record(rule: BehaviorRule, *args: Any, **kwargs: Any) -> str:
        if rule.action == "ban":
            fired.append(current[0])
        return original(rule, *args, **kwargs)

    monkeypatch.setattr(tracker, "apply_action", record)
    route = _route(_throttle_rule(2))
    for n in range(1, 7):
        current[0] = n
        request = _request()
        response = processor.process_usage_rules(request, _IP, route)
        if response is None:
            processor.process_global_rules(
                request,
                MockGuardResponse(status_code=200),
                _IP,
                list(processor._global_rules()),
            )
        clock.advance(1)
    assert fired == [5, 6]


def test_first_refusal_sends_the_pair_with_throttle_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config()
    rule = _throttle_rule(1)
    processor, event_bus, agent = _processor(config, BehaviorTracker(config))
    _statuses(processor, clock, _route(rule), 2)
    decorator_event = event_bus.send_middleware_event.call_args.kwargs
    assert decorator_event["event_type"] == "decorator_violation"
    assert decorator_event["action_taken"] == "throttle"
    assert decorator_event["decorator_type"] == "behavioral"
    assert "matched_rule_id" not in decorator_event
    assert [e.event_type for e in agent.events] == ["behavioral_violation"]
    event = agent.events[0]
    assert event.action_taken == "throttle"
    assert event.metadata["matched_rule_type"] == "behavioral"
    assert event.metadata["matched_rule_id"] == rule.matched_rule_id()
    assert event.metadata["refusals_since_last_event"] == 1


def test_later_refusals_are_sampled_per_minute_with_the_refusal_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config()
    processor, event_bus, agent = _processor(config, BehaviorTracker(config))
    route = _route(_throttle_rule(1, window=3600))
    _statuses(processor, clock, route, 6, step=10)
    assert event_bus.send_middleware_event.call_count == 1
    clock.advance(15)
    _statuses(processor, clock, route, 1)
    assert event_bus.send_middleware_event.call_count == 2
    assert [e.metadata["refusals_since_last_event"] for e in agent.events] == [1, 5]


def test_an_episode_ends_after_a_window_without_refusals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config()
    processor, event_bus, _ = _processor(config, BehaviorTracker(config))
    route = _route(_throttle_rule(1, window=10))
    _statuses(processor, clock, route, 2)
    assert event_bus.send_middleware_event.call_count == 1
    clock.advance(11)
    assert _statuses(processor, clock, route, 2) == [None, (429, "9")]
    assert event_bus.send_middleware_event.call_count == 2


def test_the_trip_marker_is_shared_over_redis(
    monkeypatch: pytest.MonkeyPatch, security_config_redis: SecurityConfig
) -> None:
    _Clock(monkeypatch)
    with _redis(security_config_redis) as manager:
        trackers = [BehaviorTracker(security_config_redis) for _ in range(2)]
        for tracker in trackers:
            tracker.initialize_redis(manager)
        check = ThrottleCheck(_throttle_rule(1), _ENDPOINT, True, 1)
        assert trackers[0].check_throttle(_IP, [check], _T0, False) == []
        first = trackers[0].check_throttle(_IP, [check], _T0 + 1, False)
        second = trackers[1].check_throttle(_IP, [check], _T0 + 2, False)
        assert [t.first_of_episode for t in first + second] == [True, False]


def test_trip_markers_and_refusal_counts_stay_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    monkeypatch.setattr(_behavior_throttle, "MAX_TRIP_MARKERS", 2)
    monkeypatch.setattr(_throttle, "MAX_SAMPLED_THROTTLE_KEYS", 2)
    config = _config()
    tracker = BehaviorTracker(config)
    processor, _, _ = _processor(config, tracker)
    route = _route(_throttle_rule(1, window=3600))
    for ip in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
        for _ in range(3):
            processor.process_usage_rules(_request(), ip, route)
        clock.advance(1)
    assert len(tracker._trip_markers) == 2
    assert len(processor._throttle_refusals) == 2


def test_route_throttle_through_a_decorator_reports_throttle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config()
    decorator = MagicMock()
    decorator.send_decorator_event = MagicMock()
    processor, _, _ = _processor(config, BehaviorTracker(config), decorator=decorator)
    _statuses(processor, clock, _route(_throttle_rule(1)), 2)
    kwargs = decorator.send_decorator_event.call_args.kwargs
    assert (kwargs["action_taken"], kwargs["decorator_type"]) == ("throttle", "usage")


def test_global_throttle_trip_is_reported_as_global(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config(
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="usage", threshold=1, window=60, action="throttle"
            ),
        )
    )
    processor, event_bus, _ = _processor(config, BehaviorTracker(config))
    _statuses(processor, clock, None, 2)
    kwargs = event_bus.send_middleware_event.call_args.kwargs
    assert kwargs["decorator_type"] == "behavioral_global"


def test_passive_mode_serves_records_and_reports_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    clock = _Clock(monkeypatch)
    config = _config(passive_mode=True)
    tracker = BehaviorTracker(config)
    processor, event_bus, agent = _processor(config, tracker)
    rule = _throttle_rule(1)
    with caplog.at_level(logging.WARNING):
        assert _statuses(processor, clock, _route(rule), 5) == [None] * 5
    assert len(tracker.usage_counts[bucket_key(_ENDPOINT, rule)][_IP]) == 5
    assert event_bus.send_middleware_event.call_count == 1
    assert event_bus.send_middleware_event.call_args.kwargs["action_taken"] == (
        "logged_only"
    )
    assert [e.action_taken for e in agent.events] == ["logged_only"]
    passive_lines = [r for r in caplog.records if "Would throttle IP" in r.message]
    assert len(passive_lines) == 1


def test_adapter_without_middleware_only_logs_and_warns_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    clock = _Clock(monkeypatch)
    monkeypatch.setattr(_throttle, "_missing_middleware_warned", False)
    config = _config()
    processor, event_bus, agent = _processor(
        config, BehaviorTracker(config), middleware=False
    )
    with caplog.at_level(logging.WARNING):
        assert _statuses(processor, clock, _route(_throttle_rule(1)), 3) == [None] * 3
    assert event_bus.send_middleware_event.call_args.kwargs["action_taken"] == (
        "logged_only"
    )
    assert [e.action_taken for e in agent.events] == ["logged_only"]
    warnings = [
        r for r in caplog.records if "throttle rules are only logged" in r.message
    ]
    assert len(warnings) == 1
