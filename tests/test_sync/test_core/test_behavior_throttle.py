import logging
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any, Literal
from unittest.mock import MagicMock

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.models import BehaviorRuleConfig, SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils import sampling
from guard_core.sync.core.behavioral import _throttle
from guard_core.sync.core.behavioral.context import BehavioralContext
from guard_core.sync.core.behavioral.processor import BehavioralProcessor
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory
from guard_core.sync.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.sync.handlers import _behavior_throttle, behavior_handler
from guard_core.sync.handlers._behavior_throttle import (
    ThrottleCheck,
    bucket_key,
    usage_hits_key,
)
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.sync.handlers.redis_handler import RedisHandlerBase, redis_handler
from tests.test_sync.conftest import MockGuardResponse, MockGuardResponseFactory
from tests.test_sync.engine_redis_commands import (
    server_loses_the_script_of_the_next_evalsha,
)

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
    def __init__(self, config: SyncSecurityConfig) -> None:
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self._factory = ErrorResponseFactory(
            ResponseContext(
                config=config,
                logger=logging.getLogger("test_throttle"),
                metrics_collector=MagicMock(),
                response_factory=MockGuardResponseFactory(),
            )
        )

    def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        return self._factory.create_error_response(status_code, default_message)


class _Agent(MagicMock):
    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.events: list[Any] = []

    def send_event(self, event: object) -> None:
        self.events.append(event)


def _config(**overrides: object) -> SyncSecurityConfig:
    fields: dict[str, Any] = {"enable_redis": False}
    fields.update(overrides)
    return SyncSecurityConfig(**fields)


def _processor(
    config: SyncSecurityConfig,
    tracker: BehaviorTracker,
    middleware: bool = True,
    decorator: BaseSecurityDecorator | None = None,
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
    threshold: int,
    window: int = 60,
    rule_type: Literal["usage", "return_pattern", "frequency"] = "usage",
    pattern: str | None = None,
    custom_action: Callable[..., object] | None = None,
) -> BehaviorRule:
    return BehaviorRule(
        rule_type=rule_type,
        threshold=threshold,
        window=window,
        pattern=pattern,
        action="throttle",
        custom_action=custom_action,
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
def _redis(config: SyncSecurityConfig) -> Iterator[Any]:
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
    monkeypatch: pytest.MonkeyPatch, security_config_redis: SyncSecurityConfig
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
    monkeypatch: pytest.MonkeyPatch, security_config_redis: SyncSecurityConfig
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
    monkeypatch: pytest.MonkeyPatch, security_config_redis: SyncSecurityConfig
) -> None:
    clock = _Clock(monkeypatch)
    with _redis(security_config_redis) as manager:
        tracker = BehaviorTracker(security_config_redis)
        tracker.initialize_redis(manager)
        processor, _, _ = _processor(security_config_redis, tracker)
        route = _route(_throttle_rule(1))
        assert _statuses(processor, clock, route, 1) == [None]
        turned = server_loses_the_script_of_the_next_evalsha(monkeypatch)
        response = processor.process_usage_rules(_request(), _IP, route)
        assert len(turned) == 1
        assert response is not None and response.status_code == 429


class _BrokenRedis(RedisHandlerBase):
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
        return 0

    @contextmanager
    def get_connection(self) -> Iterator[Any]:
        if self.config.enable_redis:
            raise ConnectionError("redis down")
        yield None


def _broken_redis_tracker(config: SyncSecurityConfig) -> BehaviorTracker:
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


def test_redis_failure_fails_secure_like_the_pipeline(
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
    assert (response.status_code, response.body) == (503, b"Security check failed")
    assert response.headers["Retry-After"] == "5"
    assert any(
        "Error in behavior throttle (GuardRedisError)" in r.message
        for r in caplog.records
    )


def test_redis_failure_never_blocks_when_redis_fails_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _Clock(monkeypatch)
    config = _config(
        enable_redis=True, redis_fail_open=True, fail_secure=True, passive_mode=False
    )
    tracker = _broken_redis_tracker(config)

    def raising(*_args: object, **_kwargs: object) -> list[object]:
        raise GuardRedisError(503, "Redis down")

    monkeypatch.setattr(tracker, "check_throttle", raising)
    processor, _, _ = _processor(config, tracker)

    response = processor.process_usage_rules(_request(), _IP, _route(_throttle_rule(1)))

    assert response is None


def test_redis_failure_never_blocks_in_passive_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _Clock(monkeypatch)
    config = _config(
        enable_redis=True, redis_fail_open=False, fail_secure=True, passive_mode=True
    )
    processor, _, _ = _processor(config, _broken_redis_tracker(config))

    response = processor.process_usage_rules(_request(), _IP, _route(_throttle_rule(1)))

    assert response is None


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
    status: int = 404,
) -> list[int]:
    statuses = []
    for _ in range(count):
        request = _request()
        refused = processor.process_usage_rules(request, _IP, route)
        if refused is not None:
            statuses.append(refused.status_code)
        else:
            response = MockGuardResponse(status_code=status)
            if route is not None:
                processor.process_return_rules(request, response, _IP, route)
            processor.process_global_rules(
                request, response, _IP, list(processor._global_rules())
            )
            statuses.append(status)
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
    assert isinstance(middleware, _Middleware)
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

    def record(
        rule: BehaviorRule,
        client_ip: str,
        endpoint_id: str,
        details: str,
        *,
        observe_only: bool = False,
        **event_metadata: object,
    ) -> str:
        if rule.action == "ban":
            fired.append(len(results) + 1)
        return original(
            rule,
            client_ip,
            endpoint_id,
            details,
            observe_only=observe_only,
            **event_metadata,
        )

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

    def record(
        rule: BehaviorRule,
        client_ip: str,
        endpoint_id: str,
        details: str,
        *,
        observe_only: bool = False,
        **event_metadata: object,
    ) -> str:
        if rule.action == "ban":
            fired.append(current[0])
        return original(
            rule,
            client_ip,
            endpoint_id,
            details,
            observe_only=observe_only,
            **event_metadata,
        )

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
    monkeypatch: pytest.MonkeyPatch, security_config_redis: SyncSecurityConfig
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
    monkeypatch.setattr(_throttle, "MAX_SAMPLED_THROTTLE_KEYS", 2)
    config = _config()
    monkeypatch.setattr(config, "behavior_throttle_max_trip_markers", 2)
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


def _global_rule_config(**fields: object) -> BehaviorRuleConfig:
    values: dict[str, Any] = {"threshold": 1, "window": 60, "action": "throttle"}
    values.update(fields)
    return BehaviorRuleConfig(**values)


def test_route_return_throttle_counts_matching_responses_not_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config()
    processor, _, _ = _processor(config, BehaviorTracker(config))
    route = _route(_throttle_rule(1, rule_type="return_pattern", pattern="status:404"))
    assert _serve_404s(processor, clock, route, 4, status=200) == [200] * 4


def test_global_return_throttle_counts_matching_responses_not_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    rule = _global_rule_config(rule_type="return_pattern", pattern="status:404")
    config = _config(global_behavior_rules=(rule,))
    processor, _, _ = _processor(config, BehaviorTracker(config))
    assert _serve_404s(processor, clock, None, 4, status=200) == [200] * 4


def test_route_throttle_refuses_when_a_global_throttle_also_applies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config(
        global_behavior_rules=(_global_rule_config(rule_type="usage", threshold=100),)
    )
    processor, _, _ = _processor(config, BehaviorTracker(config))
    statuses = _statuses(processor, clock, _route(_throttle_rule(1)), 2)
    assert [s if s is None else s[0] for s in statuses] == [None, 429]


def test_throttle_429_carries_the_default_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _Clock(monkeypatch)
    config = _config()
    processor, _, _ = _processor(config, BehaviorTracker(config))
    route = _route(_throttle_rule(1))
    processor.process_usage_rules(_request(), _IP, route)
    response = processor.process_usage_rules(_request(), _IP, route)
    assert response is not None
    assert (response.status_code, response.body) == (429, b"Too many requests")


@pytest.mark.parametrize(
    ("route_rules", "global_rules", "statuses", "reason", "extra", "applied"),
    [
        (
            [_throttle_rule(1, window=20)],
            (),
            [],
            "Behavioral usage throttle threshold reached: 1 calls in 20s",
            {"threshold": 1},
            "Throttle threshold reached: 1 calls in 20s",
        ),
        (
            [],
            (_global_rule_config(rule_type="usage", window=20),),
            [],
            "Global behavioral usage throttle threshold reached: 1 calls in 20s",
            {"threshold": 1, "decorator_type": "behavioral_global"},
            "Throttle threshold reached: 1 calls in 20s",
        ),
        (
            [
                _throttle_rule(
                    2, window=20, rule_type="return_pattern", pattern="status:404"
                )
            ],
            (),
            [404, 404, 404],
            "Behavioral return_pattern throttle threshold reached: "
            "2 for 'status:404' in 20s",
            {"threshold": 2, "pattern": "status:404"},
            "Throttle threshold reached: 2 for 'status:404' in 20s",
        ),
    ],
    ids=["route-usage", "global-usage", "route-return"],
)
def test_throttle_trip_reports_the_rule_and_its_limit(
    monkeypatch: pytest.MonkeyPatch,
    route_rules: list[BehaviorRule],
    global_rules: tuple[BehaviorRuleConfig, ...],
    statuses: list[int],
    reason: str,
    extra: dict[str, Any],
    applied: str,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config(global_behavior_rules=global_rules)
    tracker = BehaviorTracker(config)
    processor, event_bus, _ = _processor(config, tracker)
    reasons: list[str] = []
    original = tracker.apply_action

    def record(
        rule: BehaviorRule,
        client_ip: str,
        endpoint_id: str,
        details: str,
        *,
        observe_only: bool = False,
        **event_metadata: object,
    ) -> str:
        reasons.append(details)
        return original(
            rule,
            client_ip,
            endpoint_id,
            details,
            observe_only=observe_only,
            **event_metadata,
        )

    monkeypatch.setattr(tracker, "apply_action", record)
    route = _route(*route_rules) if route_rules else None
    if statuses:
        assert _serve_404s(processor, clock, route, 3) == statuses
    else:
        processor.process_usage_rules(_request(), _IP, route)
    refused = processor.process_usage_rules(_request(), _IP, route)
    assert refused is not None and refused.status_code == 429
    kwargs = event_bus.send_middleware_event.call_args.kwargs
    assert kwargs["reason"] == reason
    assert {key: kwargs[key] for key in extra} == extra
    assert ("pattern" in kwargs) == ("pattern" in extra)
    assert reasons == [applied]


def test_refusal_events_are_sampled_again_exactly_one_minute_later(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    config = _config()
    processor, event_bus, _ = _processor(config, BehaviorTracker(config))
    route = _route(_throttle_rule(1, window=3600))
    _statuses(processor, clock, route, 2)
    assert event_bus.send_middleware_event.call_count == 1
    clock.advance(59)
    _statuses(processor, clock, route, 1)
    assert event_bus.send_middleware_event.call_count == 2


def test_throttle_sampling_and_bounds_match_the_spec() -> None:
    assert _throttle.THROTTLE_EVENT_SAMPLE_SECONDS == 60
    assert _throttle.MAX_SAMPLED_THROTTLE_KEYS == 10_000


def test_a_fresh_process_has_not_warned_about_a_missing_middleware() -> None:
    code = (
        "from guard_core.sync.core.behavioral import _throttle; "
        "print(_throttle._missing_middleware_warned)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "False"


def test_missing_middleware_warning_text_and_logger(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    clock = _Clock(monkeypatch)
    monkeypatch.setattr(_throttle, "_missing_middleware_warned", False)
    config = _config()
    processor, _, _ = _processor(config, BehaviorTracker(config), middleware=False)
    with caplog.at_level(logging.WARNING):
        _statuses(processor, clock, _route(_throttle_rule(1)), 2)
    warnings = [
        r for r in caplog.records if r.name == "guard_core.sync.core.behavioral"
    ]
    assert [r.getMessage() for r in warnings] == [
        "Behavior throttle rules are only logged: this adapter does not pass "
        "its middleware to the behavioral processor, so the engine cannot "
        "answer 429. Upgrade the adapter to enforce throttle rules. "
        "Rules: usage threshold=1 window=60s. Missing capability: a middleware "
        "with create_error_response, passed to the BehavioralContext or "
        "reachable through the pipeline's checks."
    ]


def test_redis_failure_logs_the_redacted_error_and_the_fail_secure_block(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _Clock(monkeypatch)
    config = _config(enable_redis=True, redis_fail_open=False, fail_secure=True)
    processor, _, _ = _processor(config, _broken_redis_tracker(config))
    with caplog.at_level(logging.WARNING, logger="test_throttle"):
        processor.process_usage_rules(_request(), _IP, _route(_throttle_rule(1)))
    assert [r.getMessage() for r in caplog.records if r.name == "test_throttle"] == [
        "Error in behavior throttle (GuardRedisError): "
        "Redis behavior throttling unavailable",
        "Blocking request due to check error in fail-secure mode: behavior throttle",
    ]


def test_global_throttle_hits_use_the_global_scope_key_over_redis(
    monkeypatch: pytest.MonkeyPatch, security_config_redis: SyncSecurityConfig
) -> None:
    _Clock(monkeypatch)
    rule_config = _global_rule_config(rule_type="usage", threshold=100)
    config = security_config_redis.model_copy(
        update={"global_behavior_rules": (rule_config,)}
    )
    with _redis(config) as manager:
        tracker = BehaviorTracker(config)
        tracker.initialize_redis(manager)
        processor, _, _ = _processor(config, tracker)
        processor.process_usage_rules(_request(), _IP, None)
        rule = processor._global_rules()[0]
        key = usage_hits_key(f"global|{rule.discriminator()}", _IP, rule)
        with manager.get_connection() as conn:
            assert conn.zcard(f"{config.redis_prefix}behavior_usage:{key}") == 1


def test_global_rules_are_converted_once_per_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(global_behavior_rules=(_global_rule_config(rule_type="usage"),))
    processor, _, _ = _processor(config, BehaviorTracker(config))
    converted: list[BehaviorRuleConfig] = []
    original = _throttle.config_to_rule

    def counting(rule_config: BehaviorRuleConfig) -> BehaviorRule:
        converted.append(rule_config)
        return original(rule_config)

    monkeypatch.setattr(_throttle, "config_to_rule", counting)
    first = processor._global_rules()
    assert processor._global_rules() is first
    assert len(converted) == 1


def test_bounded_refusal_counts_evict_the_oldest_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    monkeypatch.setattr(_throttle, "MAX_SAMPLED_THROTTLE_KEYS", 2)
    config = _config()
    processor, _, _ = _processor(config, BehaviorTracker(config))
    rule = _throttle_rule(1, window=3600)
    ips = ("198.51.100.1", "198.51.100.2", "198.51.100.3")
    for ip in ips:
        for _ in range(3):
            processor.process_usage_rules(_request(), ip, _route(rule))
        clock.advance(1)
    assert list(processor._throttle_refusals) == [
        _behavior_throttle.trip_marker_key(_ENDPOINT, ip, rule) for ip in ips[1:]
    ]


def test_a_refused_request_counts_only_in_global_non_throttle_usage_rules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(monkeypatch)
    throttle = _global_rule_config(rule_type="usage", threshold=100)
    returns = _global_rule_config(
        rule_type="return_pattern", pattern="status:404", threshold=100, action="log"
    )
    config = _config(global_behavior_rules=(throttle, returns))
    tracker = BehaviorTracker(config)
    processor, _, _ = _processor(config, tracker)
    statuses = _statuses(processor, clock, _route(_throttle_rule(1)), 2)
    assert [s if s is None else s[0] for s in statuses] == [None, 429]
    global_throttle, global_return = processor._global_rules()
    scope = f"global|{global_throttle.discriminator()}"
    assert len(tracker.usage_counts[bucket_key(scope, global_throttle)][_IP]) == 1
    return_scope = f"global|{global_return.discriminator()}"
    assert bucket_key(return_scope, global_return) not in tracker.usage_counts


def test_route_return_throttle_refuses_over_redis(
    monkeypatch: pytest.MonkeyPatch, security_config_redis: SyncSecurityConfig
) -> None:
    clock = _Clock(monkeypatch)
    with _redis(security_config_redis) as manager:
        tracker = BehaviorTracker(security_config_redis)
        tracker.initialize_redis(manager)
        processor, _, _ = _processor(security_config_redis, tracker)
        route = _route(
            _throttle_rule(2, rule_type="return_pattern", pattern="status:404")
        )
        assert _serve_404s(processor, clock, route, 4) == [404, 404, 404, 429]


def test_every_address_of_one_network_shares_one_throttle_episode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _Clock(monkeypatch)
    config = _config()
    processor, _, _ = _processor(config, BehaviorTracker(config))
    rule = _throttle_rule(1, window=3600)
    for ip in ("2001:db8:0:1::5", "2001:db8:0:1:ffff::9"):
        for _ in range(3):
            processor.process_usage_rules(_request(), ip, _route(rule))

    assert list(processor._throttle_refusals) == [
        _behavior_throttle.trip_marker_key(_ENDPOINT, "2001:db8:0:1::/64", rule)
    ]
