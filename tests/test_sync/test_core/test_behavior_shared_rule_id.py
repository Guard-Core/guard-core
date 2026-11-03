import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import BehaviorRuleConfig, SyncSecurityConfig
from guard_core.sync.core.behavioral.context import BehavioralContext
from guard_core.sync.core.behavioral.processor import BehavioralProcessor
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.sync.handlers.redis_handler import redis_handler
from tests.test_sync.conftest import MockGuardResponse

_IP = "203.0.113.77"
_THRESHOLD = 4
_REQUESTS = _THRESHOLD + 2

_BACKENDS = [
    pytest.param(False, id="memory"),
    pytest.param(True, id="redis"),
]


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


def _rule(rule_type: object = "usage", **overrides: object) -> BehaviorRule:
    fields: dict[str, Any] = {
        "rule_type": rule_type,
        "threshold": _THRESHOLD,
        "window": 60,
        "action": "log",
    }
    if rule_type == "return_pattern":
        fields["pattern"] = "status:404"
    fields.update(overrides)
    return BehaviorRule(**fields)


def _route(*rules: BehaviorRule) -> RouteConfig:
    route_config = RouteConfig()
    route_config.behavior_rules = list(rules)
    return route_config


@contextmanager
def _engine(
    use_redis: bool,
    config: SyncSecurityConfig,
    middleware: object = None,
) -> Iterator[tuple[BehavioralProcessor, MagicMock]]:
    tracker = BehaviorTracker(config)
    manager = None
    if use_redis:
        manager = redis_handler(config)
        manager.initialize()
        tracker.initialize_redis(manager)
    acted = MagicMock()
    event_bus = MagicMock()
    event_bus.send_middleware_event = MagicMock()
    context = BehavioralContext(
        config=config,
        logger=logging.getLogger("test_shared_rule_id"),
        event_bus=event_bus,
        guard_decorator=None,
        behavior_tracker=tracker,
        middleware=middleware,
    )
    try:
        with patch.object(tracker, "apply_action", acted):
            yield BehavioralProcessor(context), acted
    finally:
        if manager is not None:
            manager.delete_pattern("behavior_*")
            manager.close()


def _config(
    use_redis: bool, redis_config: SyncSecurityConfig, **extra: object
) -> SyncSecurityConfig:
    base = redis_config if use_redis else SyncSecurityConfig(enable_redis=False)
    return base.model_copy(update=extra)


def _run_route_usage(
    processor: BehavioralProcessor, acted: MagicMock, route: RouteConfig
) -> list[int]:
    per_request = []
    for _ in range(_REQUESTS):
        before = acted.call_count
        processor.process_usage_rules(_request(), _IP, route)
        per_request.append(acted.call_count - before)
    return per_request


@pytest.mark.parametrize("use_redis", _BACKENDS)
def test_one_rule_acts_from_the_request_after_its_threshold(
    use_redis: bool, security_config_redis: SyncSecurityConfig
) -> None:
    config = _config(use_redis, security_config_redis)
    with _engine(use_redis, config) as (processor, acted):
        counts = _run_route_usage(processor, acted, _route(_rule()))
    assert counts == [0] * _THRESHOLD + [1, 1]


@pytest.mark.parametrize("use_redis", _BACKENDS)
def test_route_usage_rules_sharing_a_rule_id_count_each_request_once(
    use_redis: bool, security_config_redis: SyncSecurityConfig
) -> None:
    config = _config(use_redis, security_config_redis)
    route = _route(_rule(ban_duration=60), _rule(ban_duration=3600))
    with _engine(use_redis, config) as (processor, acted):
        counts = _run_route_usage(processor, acted, route)
    assert counts == [0] * _THRESHOLD + [2, 2]
    assert [call.args[0].ban_duration for call in acted.call_args_list[:2]] == [
        60,
        3600,
    ]


@pytest.mark.parametrize("use_redis", _BACKENDS)
def test_a_usage_rule_and_the_same_rule_with_a_stray_pattern_share_one_count(
    use_redis: bool, security_config_redis: SyncSecurityConfig
) -> None:
    config = _config(use_redis, security_config_redis)
    route = _route(_rule(), _rule(pattern="ignored"))
    with _engine(use_redis, config) as (processor, acted):
        counts = _run_route_usage(processor, acted, route)
    assert counts == [0] * _THRESHOLD + [2, 2]


@pytest.mark.parametrize("use_redis", _BACKENDS)
def test_global_usage_rules_sharing_a_rule_id_count_each_request_once(
    use_redis: bool, security_config_redis: SyncSecurityConfig
) -> None:
    config = _config(use_redis, security_config_redis)
    rules = [
        BehaviorRule(
            "usage", threshold=_THRESHOLD, window=60, action="log", ban_duration=d
        )
        for d in (60, 3600)
    ]
    with _engine(use_redis, config) as (processor, acted):
        counts = []
        for _ in range(_REQUESTS):
            before = acted.call_count
            processor.process_global_rules(
                _request(), MockGuardResponse("ok"), _IP, rules
            )
            counts.append(acted.call_count - before)
    assert counts == [0] * _THRESHOLD + [2, 2]


@pytest.mark.parametrize("use_redis", _BACKENDS)
def test_route_return_rules_sharing_a_rule_id_count_each_response_once(
    use_redis: bool, security_config_redis: SyncSecurityConfig
) -> None:
    config = _config(use_redis, security_config_redis)
    route = _route(_rule("return_pattern", ban_duration=60), _rule("return_pattern"))
    response = MockGuardResponse("missing", status_code=404)
    with _engine(use_redis, config) as (processor, acted):
        counts = []
        for _ in range(_REQUESTS):
            before = acted.call_count
            processor.process_return_rules(_request(), response, _IP, route)
            counts.append(acted.call_count - before)
    assert counts == [0] * _THRESHOLD + [2, 2]


@pytest.mark.parametrize("use_redis", _BACKENDS)
def test_global_return_rules_sharing_a_rule_id_count_each_response_once(
    use_redis: bool, security_config_redis: SyncSecurityConfig
) -> None:
    config = _config(use_redis, security_config_redis)
    rules = [_rule("return_pattern", ban_duration=d) for d in (60, 3600)]
    response = MockGuardResponse("missing", status_code=404)
    with _engine(use_redis, config) as (processor, acted):
        counts = []
        for _ in range(_REQUESTS):
            before = acted.call_count
            processor.process_global_rules(_request(), response, _IP, rules)
            counts.append(acted.call_count - before)
    assert counts == [0] * _THRESHOLD + [2, 2]


@pytest.mark.parametrize("use_redis", _BACKENDS)
def test_return_rules_sharing_a_rule_id_apply_their_own_effective_threshold(
    use_redis: bool, security_config_redis: SyncSecurityConfig
) -> None:
    config = _config(use_redis, security_config_redis)
    rules = [
        _rule("return_pattern", threshold=8, correlate_with_detection=True),
        _rule("return_pattern", threshold=8),
    ]
    middleware = MagicMock()
    middleware.suspicious_request_counts = {_IP: {"xss": 1}}
    response = MockGuardResponse("missing", status_code=404)
    with _engine(use_redis, config, middleware) as (processor, acted):
        tracker = processor.context.behavior_tracker
        assert tracker is not None
        if use_redis:
            now = time.time()
            assert tracker.redis_handler is not None
            tracker.redis_handler.record_detection_strikes(
                _IP, ("xss",), now, now - 3600, 3600, 10_000
            )
        counts = []
        for _ in range(10):
            before = acted.call_count
            processor.process_global_rules(_request(), response, _IP, rules)
            counts.append(acted.call_count - before)
    assert counts == [0] * 4 + [1] * 4 + [2, 2]


class _Middleware:
    suspicious_request_counts: dict[str, dict[str, int]] = {}

    def create_error_response(
        self, status_code: int, default_message: str
    ) -> MagicMock:
        response = MagicMock()
        response.status_code = status_code
        response.headers = {}
        return response


def _throttle(**overrides: object) -> BehaviorRule:
    return _rule(threshold=3, action="throttle", **overrides)


@pytest.mark.parametrize("use_redis", _BACKENDS)
def test_route_throttle_rules_sharing_a_rule_id_count_each_request_once(
    use_redis: bool, security_config_redis: SyncSecurityConfig
) -> None:
    config = _config(use_redis, security_config_redis)
    route = _route(_throttle(ban_duration=60), _throttle(ban_duration=3600))
    with _engine(use_redis, config, _Middleware()) as (processor, _):
        statuses = []
        for _ in range(5):
            response = processor.process_usage_rules(_request(), _IP, route)
            statuses.append(None if response is None else response.status_code)
    assert statuses == [None, None, None, 429, 429]


@pytest.mark.parametrize("use_redis", _BACKENDS)
def test_global_throttle_rules_sharing_a_rule_id_count_each_request_once(
    use_redis: bool, security_config_redis: SyncSecurityConfig
) -> None:
    config = _config(
        use_redis,
        security_config_redis,
        global_behavior_rules=tuple(
            BehaviorRuleConfig(
                rule_type="usage",
                threshold=3,
                window=60,
                action="throttle",
                ban_duration=d,
            )
            for d in (60, 3600)
        ),
    )
    with _engine(use_redis, config, _Middleware()) as (processor, _):
        statuses = []
        for _ in range(5):
            response = processor.process_usage_rules(_request(), _IP, None)
            statuses.append(None if response is None else response.status_code)
    assert statuses == [None, None, None, 429, 429]


@pytest.mark.parametrize("use_redis", _BACKENDS)
def test_refused_requests_count_once_in_global_usage_rules_sharing_a_rule_id(
    use_redis: bool, security_config_redis: SyncSecurityConfig
) -> None:
    config = _config(
        use_redis,
        security_config_redis,
        global_behavior_rules=tuple(
            BehaviorRuleConfig(
                rule_type="usage",
                threshold=_THRESHOLD,
                window=60,
                action="log",
                ban_duration=d,
            )
            for d in (60, 3600)
        ),
    )
    route = _route(BehaviorRule("usage", threshold=1, action="throttle"))
    with _engine(use_redis, config, _Middleware()) as (processor, acted):
        fired = []
        for _ in range(8):
            before = acted.call_count
            processor.process_usage_rules(_request(), _IP, route)
            fired.append(
                sum(
                    "Global usage threshold exceeded" in call.args[3]
                    for call in acted.call_args_list[before:]
                )
            )
    assert fired == [0] * 4 + [2, 2, 2, 2]


def _custom_action(client_ip: str, endpoint_id: str, details: str) -> None:
    return None


@pytest.mark.parametrize(
    "custom_first", [False, True], ids=["plain-first", "custom-first"]
)
@pytest.mark.parametrize("use_redis", _BACKENDS)
def test_a_throttle_rule_and_its_custom_action_copy_count_each_request_once(
    use_redis: bool, custom_first: bool, security_config_redis: SyncSecurityConfig
) -> None:
    config = _config(use_redis, security_config_redis)
    rules = [_throttle(), _throttle(custom_action=_custom_action)]
    route = _route(*(rules[::-1] if custom_first else rules))
    with _engine(use_redis, config, _Middleware()) as (processor, acted):
        statuses = []
        custom_fired = []
        for _ in range(5):
            before = acted.call_count
            response = processor.process_usage_rules(_request(), _IP, route)
            statuses.append(None if response is None else response.status_code)
            custom_fired.append(
                sum(
                    call.args[0].custom_action is not None
                    for call in acted.call_args_list[before:]
                )
            )
    assert statuses == [None, None, None, 429, 429]
    assert custom_fired == [0, 0, 0, 1, 1]
