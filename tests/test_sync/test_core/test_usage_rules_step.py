import logging
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import BehaviorRuleConfig, SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.behavioral import _throttle
from guard_core.sync.core.behavioral.context import BehavioralContext
from guard_core.sync.core.behavioral.processor import BehavioralProcessor
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.implementations.route_config import RouteConfigCheck
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers._behavior_throttle import bucket_key, usage_hits_key
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.sync.handlers.redis_handler import redis_handler
from tests.test_sync.conftest import MockGuardResponse, MockGuardResponseFactory

_IP = "203.0.113.77"
_ENDPOINT = "module.view"


class _Request:
    def __init__(
        self, method: str = "POST", headers: dict[str, str] | None = None
    ) -> None:
        self.method = method
        self.headers = headers or {}
        self.url_path = "/api/reports"
        self.client_host = _IP
        self.state = SimpleNamespace(guard_route_id=_ENDPOINT)


def _request(method: str = "POST", headers: dict[str, str] | None = None) -> Any:
    return _Request(method, headers)


class _Middleware:
    def __init__(self, config: SecurityConfig, route_config: RouteConfig | None):
        self.config = config
        self.logger = logging.getLogger("test_usage_rules_step")
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self.event_bus = MagicMock()
        self.event_bus.send_middleware_event = MagicMock()
        self.route_resolver = SimpleNamespace(
            get_route_config=lambda request: route_config
        )
        self.agent_handler = None
        self.behavioral_processor: BehavioralProcessor | None = None
        self._factory = ErrorResponseFactory(
            ResponseContext(
                config=config,
                logger=self.logger,
                metrics_collector=MagicMock(),
                response_factory=MockGuardResponseFactory(),
            )
        )


class _AnsweringMiddleware(_Middleware):
    def create_error_response(self, status_code: int, default_message: str) -> Any:
        return self._factory.create_error_response(status_code, default_message)


class _Blocker(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "ip_security"

    def check(self, request: Any) -> GuardResponse | None:
        return MockGuardResponse("blocked", 403)


class _App:
    def __init__(
        self,
        config: SecurityConfig,
        route_config: RouteConfig | None = None,
        *,
        released_adapter: bool = True,
        blocker: bool = False,
        can_answer: bool = True,
    ) -> None:
        self.config = config
        self.tracker = BehaviorTracker(config)
        middleware_class = _AnsweringMiddleware if can_answer else _Middleware
        self.middleware: Any = cast(Any, middleware_class(config, route_config))
        self.context = BehavioralContext(
            config=config,
            logger=self.middleware.logger,
            event_bus=self.middleware.event_bus,
            guard_decorator=None,
            behavior_tracker=self.tracker,
            middleware=None if released_adapter else self.middleware,
        )
        self.processor = BehavioralProcessor(self.context)
        self.middleware.behavioral_processor = self.processor
        checks: list[SecurityCheck] = [RouteConfigCheck(self.middleware)]
        if blocker:
            checks.append(_Blocker(self.middleware))
        self.pipeline = SecurityCheckPipeline(checks)
        self.route_config = route_config

    def serve(self, request: Any = None) -> Any:
        request = request or _request()
        refused = self.pipeline.execute(request)
        if refused is None:
            self.adapter_usage_call(request)
            self.adapter_response_phase(request)
        return refused

    def adapter_usage_call(self, request: Any) -> Any:
        if self.route_config is None or not self.route_config.behavior_rules:
            return None
        return self.processor.process_usage_rules(request, _IP, self.route_config)

    def adapter_response_phase(self, request: Any) -> None:
        rules = [
            BehaviorRule(cfg.rule_type, cfg.threshold, cfg.window, action=cfg.action)
            for cfg in self.config.global_behavior_rules
        ]
        if rules:
            self.processor.process_global_return_rules(
                request, MockGuardResponse("ok", 200), _IP, rules
            )

    def statuses(self, count: int = 5) -> list[int]:
        codes = []
        for _ in range(count):
            refused = self.serve()
            codes.append(200 if refused is None else refused.status_code)
        return codes

    def hits(self, rule: BehaviorRule, scope: str | None = None) -> int:
        key = bucket_key(scope or _ENDPOINT, rule)
        return len(self.tracker.usage_counts.get(key, {}).get(_IP, []))


def _rule(action: str = "throttle", **fields: Any) -> BehaviorRuleConfig:
    return BehaviorRuleConfig(
        rule_type="usage", threshold=1, window=60, action=action, **fields
    )


def _config(**fields: Any) -> SecurityConfig:
    values: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
    }
    values.update(fields)
    return SecurityConfig(**values)


def _route(*rules: BehaviorRule) -> RouteConfig:
    route_config = RouteConfig()
    route_config.behavior_rules = list(rules)
    return route_config


def _throttle_rule(threshold: int = 1) -> BehaviorRule:
    return BehaviorRule("usage", threshold, 60, action="throttle")


def test_global_throttle_refuses_under_a_pipeline_without_middleware() -> None:
    app = _App(_config(global_behavior_rules=(_rule(),)))
    assert app.statuses() == [200, 429, 429, 429, 429]


def test_route_throttle_refuses_under_a_pipeline_without_middleware() -> None:
    app = _App(_config(), _route(_throttle_rule()))
    assert app.statuses() == [200, 429, 429, 429, 429]


def test_refusal_carries_retry_after_and_the_body_of_the_error_response() -> None:
    app = _App(_config(global_behavior_rules=(_rule(),)))
    app.serve()
    refused = app.serve()
    assert refused.status_code == 429
    assert refused.body == b"Too many requests"
    assert 0 < int(refused.headers["Retry-After"]) <= 60


def test_the_shared_processor_is_never_given_a_middleware() -> None:
    app = _App(_config(global_behavior_rules=(_rule(),)))
    app.statuses(3)
    assert app.context.middleware is None


def test_landed_adapter_context_middleware_still_answers() -> None:
    app = _App(_config(global_behavior_rules=(_rule(),)), released_adapter=False)
    assert app.statuses() == [200, 429, 429, 429, 429]


def test_a_pipeline_without_route_resolution_keeps_its_behavior() -> None:
    app = _App(_config(global_behavior_rules=(_rule(),)))
    detection_only = SecurityCheckPipeline([_PassCheck(app.middleware)])
    for _ in range(4):
        assert detection_only.execute(_request()) is None


class _PassCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "suspicious_activity"

    def check(self, request: Any) -> GuardResponse | None:
        return None


def test_a_cors_preflight_is_not_refused_and_not_recorded() -> None:
    app = _App(_config(enable_cors=True, global_behavior_rules=(_rule(),)))
    preflight = {"access-control-request-method": "POST"}
    codes = []
    for _ in range(3):
        refused = app.pipeline.execute(_request("OPTIONS", preflight))
        codes.append(None if refused is None else refused.status_code)
        app.serve()
    assert codes == [None, None, None]
    assert app.statuses(2) == [429, 429]


class _PairIteratingHeaders:
    # Werkzeug's EnvironHeaders iterates (name, value) pairs, unlike a Mapping.
    def __init__(self, pairs: dict[str, str]) -> None:
        self._pairs = pairs

    def keys(self) -> list[str]:
        return list(self._pairs)

    def get(self, name: str, default: str | None = None) -> str | None:
        return self._pairs.get(name, default)

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._pairs.items())


def test_a_flask_style_headers_object_does_not_break_the_preflight_skip() -> None:
    app = _App(_config(enable_cors=True, global_behavior_rules=(_rule(),)))
    codes = []
    for method in ("OPTIONS", "POST", "OPTIONS", "POST"):
        request = _request(method, {"Origin": "https://app.example"})
        request.headers = _PairIteratingHeaders(
            {"Access-Control-Request-Method": "POST"} if method == "OPTIONS" else {}
        )
        refused = app.pipeline.execute(request)
        codes.append(None if refused is None else refused.status_code)
        if refused is None and method == "POST":
            app.adapter_response_phase(request)
    assert codes == [None, None, None, 429]


def test_an_exclusion_scoped_request_is_never_throttled() -> None:
    app = _App(_config(global_behavior_rules=(_rule(),)))
    for _ in range(4):
        request = _request()
        request.state.guard_exclusion_scoped = True
        assert app.pipeline.execute(request) is None


def test_passive_mode_admits_and_reports_every_request_to_on_block() -> None:
    fired: list[dict[str, Any]] = []
    app = _App(
        _config(
            passive_mode=True,
            global_behavior_rules=(_rule(),),
            on_block=lambda request, payload: fired.append(payload),
        )
    )
    assert app.statuses(4) == [200] * 4
    assert [(p["check_name"], p["status_code"], p["passive_mode"]) for p in fired] == [
        ("behavior_throttle", None, True)
    ] * 3


def test_on_block_fires_once_per_refusal_and_not_from_the_marked_call() -> None:
    fired: list[dict[str, Any]] = []
    app = _App(
        _config(on_block=lambda request, payload: fired.append(payload)),
        _route(_throttle_rule()),
    )
    assert app.statuses(4) == [200, 429, 429, 429]
    assert [(p["check_name"], p["status_code"], p["passive_mode"]) for p in fired] == [
        ("behavior_throttle", 429, False)
    ] * 3


def test_a_second_usage_call_on_the_same_request_does_not_record_again() -> None:
    throttle = _throttle_rule(100)
    app = _App(_config(), _route(throttle))
    app.serve()
    request = _request()
    first = app.pipeline.execute(request)
    again = app.processor.process_usage_rules(request, _IP, app.route_config)
    assert again is first
    assert app.hits(throttle) == 2


def test_route_and_global_usage_log_rules_record_each_request_once() -> None:
    route_rule = BehaviorRule("usage", 100, 60, action="log")
    app = _App(_config(global_behavior_rules=(_rule("log"),)), _route(route_rule))
    assert app.statuses(7) == [200] * 7
    global_rule = BehaviorRule("usage", 1, 60, action="log")
    assert app.hits(route_rule) == 7
    assert app.hits(global_rule, f"global|{global_rule.discriminator()}") == 7


def test_a_throttle_and_a_global_usage_rule_record_each_request_once() -> None:
    throttle = _throttle_rule(100)
    app = _App(_config(global_behavior_rules=(_rule("log"),)), _route(throttle))
    assert app.statuses(7) == [200] * 7
    global_rule = BehaviorRule("usage", 1, 60, action="log")
    assert app.hits(throttle) == 7
    assert app.hits(global_rule, f"global|{global_rule.discriminator()}") == 7


@contextmanager
def _redis_app(
    config: SecurityConfig, route_config: RouteConfig | None = None
) -> Iterator[_App]:
    app = _App(config, route_config)
    manager = redis_handler(config)
    manager.initialize()
    app.tracker.initialize_redis(manager)
    try:
        yield app
    finally:
        manager.delete_pattern("behavior_*")
        manager.close()


def _usage_cardinality(
    app: _App, rule: BehaviorRule, scope_id: str | None = None
) -> int:
    key = usage_hits_key(scope_id or _ENDPOINT, _IP, rule)
    manager = redis_handler(app.config)
    with manager.get_connection() as conn:
        cardinality: int = conn.zcard(f"{app.config.redis_prefix}behavior_usage:{key}")
    return cardinality


def test_redis_throttle_refuses_under_a_pipeline_without_middleware(
    security_config_redis: SecurityConfig,
) -> None:
    config = security_config_redis.model_copy(
        update={"global_behavior_rules": (_rule(),)}
    )
    with _redis_app(config) as app:
        assert app.statuses(4) == [200, 429, 429, 429]


def test_redis_usage_zsets_hold_each_admitted_request_once(
    security_config_redis: SecurityConfig,
) -> None:
    route_rule = BehaviorRule("usage", 100, 60, action="log")
    config = security_config_redis.model_copy(
        update={"global_behavior_rules": (_rule("log"),)}
    )
    with _redis_app(config, _route(route_rule)) as app:
        assert app.statuses(7) == [200] * 7
        global_rule = BehaviorRule("usage", 1, 60, action="log")
        global_scope = f"global|{global_rule.discriminator()}"
        assert _usage_cardinality(app, route_rule) == 7
        assert _usage_cardinality(app, global_rule, global_scope) == 7


@pytest.mark.parametrize(
    ("fail_secure", "expected"), [(True, 500), (False, 200)], ids=["secure", "open"]
)
def test_a_failing_usage_rule_follows_the_check_error_policy(
    fail_secure: bool, expected: int
) -> None:
    app = _App(_config(fail_secure=fail_secure, global_behavior_rules=(_rule("log"),)))
    failing = MagicMock(side_effect=RuntimeError("boom"))
    with patch.object(app.tracker, "track_endpoint_usage", failing):
        refused = [app.pipeline.execute(_request()) for _ in range(2)]
    assert [200 if r is None else r.status_code for r in refused] == [expected] * 2


def test_a_request_refused_before_the_step_is_not_recorded() -> None:
    app = _App(_config(global_behavior_rules=(_rule(),)), blocker=True)
    assert app.statuses(3) == [403, 403, 403]
    global_rule = BehaviorRule("usage", 1, 60, action="throttle")
    assert app.hits(global_rule, f"global|{global_rule.discriminator()}") == 0


def test_startup_warns_once_naming_the_rule_for_a_middleware_that_cannot_answer(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(_throttle, "_missing_middleware_warned", False)
    config = _config(global_behavior_rules=(_rule(),))
    with caplog.at_level(logging.WARNING):
        _App(config, can_answer=False)
        _App(config, can_answer=False)
    lines = [r.getMessage() for r in caplog.records if "only logged" in r.message]
    assert len(lines) == 1
    assert "usage threshold=1 window=60s" in lines[0]
    assert "create_error_response" in lines[0]


def test_first_use_still_warns_when_no_middleware_is_reachable(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(_throttle, "_missing_middleware_warned", False)
    app = _App(_config(), _route(_throttle_rule()), can_answer=False)
    with caplog.at_level(logging.WARNING):
        assert app.statuses(3) == [200, 200, 200]
    lines = [r.getMessage() for r in caplog.records if "only logged" in r.message]
    assert len(lines) == 1
    assert "usage threshold=1 window=60s" in lines[0]


def test_startup_does_not_warn_when_a_middleware_can_answer(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(_throttle, "_missing_middleware_warned", False)
    with caplog.at_level(logging.WARNING):
        _App(_config(global_behavior_rules=(_rule(),)))
        _App(_config(global_behavior_rules=(_rule(),)), released_adapter=False)
    assert [r for r in caplog.records if "only logged" in r.message] == []
