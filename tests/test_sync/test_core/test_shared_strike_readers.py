import logging
import uuid
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import BehaviorRuleConfig, SecurityConfig
from guard_core.sync.core.behavioral._throttle import effective_return_threshold
from guard_core.sync.core.behavioral.context import BehavioralContext
from guard_core.sync.core.behavioral.processor import BehavioralProcessor
from guard_core.sync.core.checks.helpers import escalate_identity_violation
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.handlers._behavior_throttle import ThrottleCheck, _with_correlation
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.sync.handlers.ratelimit_handler import record_shared_violation
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL, MockGuardResponse

IP = "198.51.100.88"
DETECT = "guard_core.sync.core.checks.implementations.suspicious_activity"
HELPERS = "guard_core.sync.core.checks.helpers"


def _config(**overrides: Any) -> SecurityConfig:
    values: dict[str, Any] = {
        "enable_redis": True,
        "redis_url": REDIS_URL,
        "redis_prefix": f"test:wp3fu:readers:{uuid.uuid4().hex}:",
        "enable_penetration_detection": True,
        "enable_ip_banning": True,
        "auto_ban_threshold": 1000,
        "enable_rate_limiting": False,
    }
    values.update(overrides)
    return SecurityConfig(**values)


def _threat(*categories: str) -> DetectionResult:
    return DetectionResult(
        is_threat=True,
        trigger_info="probe",
        threat_categories=list(categories),
        threat_scores={name: 1.0 for name in categories},
    )


class _Worker:
    def __init__(self, config: SecurityConfig, redis: RedisManager) -> None:
        middleware = MagicMock()
        middleware.config = config
        middleware.logger = logging.getLogger("test_shared_strike_readers")
        middleware.suspicious_request_counts = {}
        middleware.rate_limit_handler.redis_handler = redis
        middleware.event_bus.send_middleware_event = MagicMock()
        middleware.create_error_response = MagicMock(
            return_value=MagicMock(status_code=400)
        )
        middleware.route_resolver.should_bypass_check = lambda *_: False
        self.middleware = middleware
        self.check = SuspiciousActivityCheck(middleware)
        self.check.ip_ban_manager = Mock(ban_ip=MagicMock(return_value=True))

    def request(self) -> MagicMock:
        request = MagicMock()
        request.state.is_whitelisted = False
        request.state.client_ip = IP
        request.state.route_config = None
        request.url_full = "https://test/x"
        return request

    def detect(self, monkeypatch: pytest.MonkeyPatch, *categories: str) -> None:
        result = _threat(*categories)

        def fake(*_args: Any, **_kwargs: Any) -> DetectionResult:
            return result

        monkeypatch.setattr(f"{DETECT}.get_cached_detection_result", fake)
        self.check.check(self.request())

    def last_request_count(self) -> int:
        calls = self.middleware.event_bus.send_middleware_event.call_args_list
        return int(calls[-1].kwargs["request_count"])


@pytest.fixture
def redis() -> Generator[RedisManager, None]:
    config = _config()
    manager = RedisManager(config)
    manager.initialize()
    try:
        yield manager
    finally:
        manager.delete_pattern("*")
        manager.close()


def test_the_penetration_event_counts_the_strikes_of_every_worker(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = redis.config
    first, second = _Worker(config, redis), _Worker(config, redis)
    for _ in range(3):
        first.detect(monkeypatch, "xss")

    second.detect(monkeypatch, "xss")

    assert second.last_request_count() == 4


def test_the_event_count_includes_the_shared_rate_limit_strikes(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = _Worker(redis.config, redis)
    record_shared_violation(redis, IP)
    record_shared_violation(redis, IP)

    worker.detect(monkeypatch, "xss")

    assert worker.last_request_count() == 3


def test_the_identity_violation_event_counts_every_workers_strikes(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = redis.config
    first, second = _Worker(config, redis), _Worker(config, redis)
    for _ in range(2):
        first.detect(monkeypatch, "xss")

    def fake(*_args: Any, **_kwargs: Any) -> DetectionResult:
        return _threat("xss")

    monkeypatch.setattr(f"{HELPERS}.get_cached_detection_result", fake)
    escalate_identity_violation(
        second.middleware,
        config,
        second.check.ip_ban_manager,
        second.request(),
        IP,
        logging.getLogger("test_shared_strike_readers"),
        "check",
        frozenset(),
        "blacklist_hit",
        "trigger",
    )

    assert second.last_request_count() == 3


def _processor(
    config: SecurityConfig, redis: RedisManager, rule: BehaviorRuleConfig
) -> tuple[BehavioralProcessor, MagicMock, MagicMock]:
    config.global_behavior_rules = (rule,)
    tracker = BehaviorTracker(config)
    tracker.redis_handler = redis
    event_bus = MagicMock()
    event_bus.send_middleware_event = MagicMock()
    middleware = MagicMock()
    middleware.suspicious_request_counts = {}
    middleware.create_error_response = MagicMock(
        side_effect=lambda status, message: MockGuardResponse(message, status)
    )
    context = BehavioralContext(
        config=config,
        logger=logging.getLogger("test_shared_strike_readers"),
        event_bus=event_bus,
        guard_decorator=None,
        behavior_tracker=tracker,
        middleware=middleware,
    )
    return BehavioralProcessor(context), event_bus, middleware


def _request() -> MagicMock:
    request = MagicMock()
    request.method = "GET"
    request.url_path = "/x"
    request.state = MagicMock()
    request.state.guard_endpoint_id = None
    request.state.guard_route_id = "module.view"
    request.state.guard_decorator = None
    request.state.guard_exclusion_scoped = False
    return request


def test_a_correlated_return_rule_sees_the_detections_of_every_worker(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = redis.config
    detector = _Worker(config, redis)
    detector.detect(monkeypatch, "xss")
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=10,
        pattern="status:404",
        action="log",
        correlate_with_detection=True,
    )
    processor, event_bus, _ = _processor(config, redis, _rule_config(rule))
    request = _request()
    response = MockGuardResponse("not found", status_code=404)

    for _ in range(5):
        processor.process_global_return_rules(request, response, IP, [rule])
    assert event_bus.send_middleware_event.call_count == 0
    processor.process_global_return_rules(request, response, IP, [rule])

    assert event_bus.send_middleware_event.call_count == 1
    call = event_bus.send_middleware_event.call_args_list[-1]
    assert call.kwargs["correlation"] is True
    assert call.kwargs["correlated_categories"] == ["xss"]
    assert call.kwargs["threshold"] == 5


def test_a_correlated_throttle_rule_sees_the_detections_of_every_worker(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = redis.config
    detector = _Worker(config, redis)
    detector.detect(monkeypatch, "xss")
    rule = BehaviorRuleConfig(
        rule_type="return_pattern",
        threshold=4,
        window=60,
        pattern="status:404",
        action="throttle",
        correlate_with_detection=True,
    )
    processor, _, _ = _processor(config, redis, rule)

    statuses = []
    for _ in range(5):
        request = _request()
        refused = processor.process_usage_rules(request, IP, None)
        if refused is not None:
            statuses.append(refused.status_code)
            continue
        response = MockGuardResponse("not found", status_code=404)
        processor.process_global_rules(
            request, response, IP, list(processor._global_rules())
        )
        statuses.append(404)

    assert statuses == [404, 404, 404, 429, 429]


def _rule_config(rule: BehaviorRule) -> BehaviorRuleConfig:
    return BehaviorRuleConfig(
        rule_type=rule.rule_type,
        threshold=rule.threshold,
        window=rule.window,
        pattern=rule.pattern,
        action=rule.action,
        correlate_with_detection=rule.correlate_with_detection,
    )


def _command_calls(redis: RedisManager, command: str) -> int:
    with redis.get_connection() as conn:
        stats = conn.info("commandstats")
    entry = stats.get(f"cmdstat_{command}")
    return int(entry["calls"]) if entry else 0


def _category_reads_for_404s(
    redis: RedisManager, correlated: bool, requests: int
) -> int:
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=10,
        pattern="status:404",
        action="log",
        correlate_with_detection=correlated,
    )
    redis.config.redis_prefix = f"{redis.config.redis_prefix}{uuid.uuid4().hex}:"
    processor, _, _ = _processor(redis.config, redis, _rule_config(rule))
    request = _request()
    response = MockGuardResponse("not found", status_code=404)
    before = _command_calls(redis, "smembers")
    for _ in range(requests):
        processor.process_global_return_rules(request, response, IP, [rule])
    return _command_calls(redis, "smembers") - before


def test_a_correlated_rule_below_its_correlated_threshold_reads_nothing(
    redis: RedisManager,
) -> None:
    assert _category_reads_for_404s(redis, True, 5) == 0


def test_a_correlated_rule_past_its_correlated_threshold_reads_once(
    redis: RedisManager,
) -> None:
    assert _category_reads_for_404s(redis, True, 6) == 1
    assert _category_reads_for_404s(redis, True, 8) == 3


def test_a_rule_that_does_not_correlate_never_reads_the_categories(
    redis: RedisManager,
) -> None:
    assert _category_reads_for_404s(redis, False, 12) == 0


def test_a_request_without_return_rules_costs_no_category_read(
    redis: RedisManager,
) -> None:
    usage = BehaviorRule(rule_type="usage", threshold=1000, window=60, action="log")
    processor, _, _ = _processor(redis.config, redis, _rule_config(usage))
    request = _request()
    response = MockGuardResponse("ok", status_code=200)
    before = _command_calls(redis, "smembers")

    for _ in range(3):
        processor.process_global_rules(request, response, IP, [usage])

    assert _command_calls(redis, "smembers") == before


def _category_reads_for_throttled_404s(
    redis: RedisManager, correlated: bool, requests: int
) -> tuple[int, list[int]]:
    redis.config.redis_prefix = f"{redis.config.redis_prefix}{uuid.uuid4().hex}:"
    rule = BehaviorRuleConfig(
        rule_type="return_pattern",
        threshold=4,
        window=60,
        pattern="status:404",
        action="throttle",
        correlate_with_detection=correlated,
    )
    processor, _, _ = _processor(redis.config, redis, rule)
    before = _command_calls(redis, "smembers")
    statuses = []
    for _ in range(requests):
        request = _request()
        refused = processor.process_usage_rules(request, IP, None)
        if refused is not None:
            statuses.append(refused.status_code)
            continue
        response = MockGuardResponse("not found", status_code=404)
        processor.process_global_rules(
            request, response, IP, list(processor._global_rules())
        )
        statuses.append(404)
    return _command_calls(redis, "smembers") - before, statuses


def test_a_correlated_throttle_rule_reads_only_where_the_answer_can_change(
    redis: RedisManager,
) -> None:
    reads, statuses = _category_reads_for_throttled_404s(redis, True, 5)

    assert statuses == [404] * 5
    # throttle script: requests 4 and 5 (count in [3, 5)); response phase:
    # requests 3 to 5 (count above the correlated threshold of 2)
    assert reads == 5


def test_a_throttle_rule_that_does_not_correlate_never_reads_categories(
    redis: RedisManager,
) -> None:
    reads, _ = _category_reads_for_throttled_404s(redis, False, 8)

    assert reads == 0


def test_a_failed_category_read_falls_back_to_the_process_categories(
    redis: RedisManager, caplog: pytest.LogCaptureFixture
) -> None:
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=10,
        pattern="status:404",
        action="log",
        correlate_with_detection=True,
    )
    processor, event_bus, middleware = _processor(
        redis.config, redis, _rule_config(rule)
    )
    middleware.suspicious_request_counts = {IP: {"sqli": 2}}
    tracker = processor.context.behavior_tracker
    assert tracker is not None
    tracker.redis_handler = Mock(
        config=redis.config,
        record_sliding_window_hit=MagicMock(side_effect=[1, 2, 3, 4, 5, 6]),
        read_detection_categories=MagicMock(side_effect=RuntimeError("redis down")),
    )
    request = _request()
    response = MockGuardResponse("not found", status_code=404)

    with caplog.at_level(logging.WARNING):
        for _ in range(6):
            processor.process_global_return_rules(request, response, IP, [rule])

    assert event_bus.send_middleware_event.call_count == 1
    call = event_bus.send_middleware_event.call_args_list[-1]
    assert call.kwargs["correlated_categories"] == ["sqli"]
    assert any("categories unavailable" in r.getMessage() for r in caplog.records)


def test_two_correlated_rules_share_one_category_read_per_request(
    redis: RedisManager,
) -> None:
    rules = [
        BehaviorRule(
            rule_type="return_pattern",
            threshold=10,
            pattern="status:404",
            action="log",
            ban_duration=duration,
            correlate_with_detection=True,
        )
        for duration in (60, 3600)
    ]
    processor, _, _ = _processor(redis.config, redis, _rule_config(rules[0]))
    redis.config.global_behavior_rules = tuple(_rule_config(rule) for rule in rules)
    request = _request()
    response = MockGuardResponse("not found", status_code=404)
    for _ in range(5):
        processor.process_global_return_rules(request, response, IP, rules)
    before = _command_calls(redis, "smembers")

    processor.process_global_return_rules(request, response, IP, rules)

    assert _command_calls(redis, "smembers") - before == 1


def test_the_correlated_threshold_is_half_the_threshold_with_a_floor_of_one() -> None:
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=9,
        pattern="status:404",
        correlate_with_detection=True,
    )

    assert effective_return_threshold(rule, ["xss"]) == (4, True)
    assert effective_return_threshold(rule, []) == (9, False)


def test_the_process_categories_are_asked_once_for_several_correlated_checks() -> None:
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=10,
        pattern="status:404",
        correlate_with_detection=True,
    )
    checks = [
        ThrottleCheck(rule, f"global|{n}", False, 11, correlated_refuse_at=6)
        for n in range(3)
    ]
    asked: list[int] = []

    def categories() -> list[str]:
        asked.append(1)
        return ["xss"]

    resolved = _with_correlation(checks, [7, 7, 3], categories)

    assert [check.refuse_at for check in resolved] == [6, 6, 11]
    assert len(asked) == 1
    clean = _with_correlation(checks[:1], [7], lambda: [])
    assert [check.refuse_at for check in clean] == [11]


def test_a_disabled_redis_reads_no_categories() -> None:
    manager = RedisManager(SecurityConfig(enable_redis=False))

    assert manager.read_detection_categories(IP, 0.0) == []
