import dataclasses
import gc
import json
import logging
import os
import re
import time
import weakref
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core import _security_headers_override as override_module
from guard_core.models import SecurityConfig
from guard_core.sync._utils.config_registry import REDIS_HANDLERS, ConfigHandlerRegistry
from guard_core.sync.core.events.metrics import MetricsCollector
from guard_core.sync.core.initialization._headers_manager_attach import (
    attach_security_headers_manager_to_redis,
)
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory
from guard_core.sync.handlers.cors_handler import CorsHandler
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)
from tests.test_sync.conftest import (
    MockGuardResponse,
    MockGuardResponseFactory,
    SyncMockGuardRequest,
)

LOGGER = "guard_core.sync.handlers.security_headers"
APP_CSP = {"default-src": ["'self'", "https://app.example"]}
GLOBAL_CSP = {"default-src": ["'self'", "https://global.example"]}
OTHER_CSP = {"default-src": ["'none'"]}
CLOCK_MODULE = "guard_core.sync.handlers._security_headers_override_state"
PULLED_OVERRIDES = override_module.PULLED_OVERRIDES
REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"


class FakeRedis:
    def __init__(self, prefix: str = "t:") -> None:
        self.config = MagicMock(redis_prefix=prefix)
        self.store: dict[str, Any] = {}
        self.ttls: dict[str, int | None] = {}
        self.gets = 0
        self.sets = 0
        self.times = 0
        self.round_trips = 0
        self.get_keys: list[str] = []
        self.pipeline_options: list[dict[str, Any]] = []
        self.time_value: tuple[int, int] | None = None
        self.down = False

    def get_key(self, namespace: str, key: str) -> Any:
        self.gets += 1
        if self.down:
            raise ConnectionError("redis is down")
        return self.store.get(f"{self.config.redis_prefix}{namespace}:{key}")

    def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool:
        self.sets += 1
        if self.down:
            raise ConnectionError("redis is down")
        full = f"{self.config.redis_prefix}{namespace}:{key}"
        self.store[full] = value
        self.ttls[full] = ttl
        return True

    @contextmanager
    def get_connection(self) -> Any:
        if self.down:
            raise ConnectionError("redis is down")
        store = self.store
        redis = self

        class Pipe:
            def __init__(self) -> None:
                self.commands: list[tuple[str, tuple[Any, ...]]] = []

            def get(self, key: str) -> None:
                redis.get_keys.append(key)
                self.commands.append(("get", (key,)))

            def time(self) -> None:
                self.commands.append(("time", ()))

            def execute(self) -> list[Any]:
                results: list[Any] = []
                for name, args in self.commands:
                    if name == "get":
                        redis.gets += 1
                        results.append(store.get(args[0]))
                    else:
                        redis.times += 1
                        now = time.time()
                        results.append(
                            redis.time_value or (int(now), int((now % 1) * 1_000_000))
                        )
                redis.round_trips += 1
                return results

        class Conn:
            def pipeline(self, **options: Any) -> Pipe:
                redis.pipeline_options.append(options)
                return Pipe()

            def keys(self, pattern: str) -> list[str]:
                prefix = pattern.rstrip("*")
                return [key for key in store if key.startswith(prefix)]

            def delete(self, *keys: str) -> None:
                for key in keys:
                    store.pop(key, None)

        yield Conn()


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    fake = Clock()
    monkeypatch.setattr(f"{CLOCK_MODULE}.now_monotonic", fake, raising=False)
    return fake


def _config(**overrides: Any) -> SecurityConfig:
    headers = {
        "enabled": True,
        "csp": APP_CSP,
        "frame_options": "DENY",
        "referrer_policy": "no-referrer",
    }
    headers.update(overrides)
    return SecurityConfig(enable_redis=False, security_headers=headers)


def _app(
    config: SecurityConfig | None = None,
    redis: FakeRedis | None = None,
    agent: Any = None,
) -> ErrorResponseFactory:
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = MagicMock()
    factory = ErrorResponseFactory(
        ResponseContext(
            config=config or _config(),
            logger=MagicMock(),
            metrics_collector=metrics,
            response_factory=MockGuardResponseFactory(),
            agent_handler=agent,
        )
    )
    if redis is not None:
        factory.security_headers_manager.redis_handler = redis
    return factory


def _hash_of(manager: SecurityHeadersManager) -> str | None:
    return manager._startup_hash


def _redis_of(manager: SecurityHeadersManager) -> Any:
    return manager.redis_handler


def _in_redis(manager: SecurityHeadersManager) -> bool:
    return bool(manager._override_in_redis)


def _override(**keys: Any) -> None:
    security_headers_manager.configure(override_apps=True, **keys)


def _override_events(agent: Any) -> list[Any]:
    events = [call.args[0] for call in agent.send_event.call_args_list]
    return [e for e in events if e.action_taken.startswith("override_")]


def _response(app: ErrorResponseFactory, path: str = "/x") -> dict[str, str]:
    response = app.apply_security_headers(MockGuardResponse("ok", 200), path)
    return dict(response.headers)


@pytest.fixture
def other_worker() -> Iterator[Callable[[], Any]]:
    from contextlib import contextmanager

    @contextmanager
    def _other() -> Iterator[None]:
        holder = override_module.PROCESS_OVERRIDE
        saved = holder.record
        holder.record = override_module.OverrideRecord(0.0, {})
        try:
            yield
        finally:
            holder.record = saved

    yield _other


def test_the_global_call_changes_the_csp_of_a_guarded_app() -> None:
    app = _app()
    assert (_response(app))["Content-Security-Policy"].endswith("app.example")

    _override(csp=GLOBAL_CSP)

    after = _response(app)
    assert (
        after["Content-Security-Policy"] == "default-src 'self' https://global.example"
    )


def test_a_path_never_requested_gets_the_override_too() -> None:
    app = _app()
    _response(app, "/seen")

    _override(csp=GLOBAL_CSP)

    assert (_response(app, "/never-seen"))["Content-Security-Policy"].endswith(
        "global.example"
    )


def test_keys_the_call_did_not_pass_keep_the_value_of_the_app() -> None:
    app = _app()

    _override(csp=GLOBAL_CSP)

    after = _response(app)
    assert after["X-Frame-Options"] == "DENY"
    assert after["Referrer-Policy"] == "no-referrer"
    assert after["X-Content-Type-Options"] == "nosniff"


def test_the_override_reaches_every_app_in_the_process() -> None:
    first, second = _app(), _app(_config(frame_options="SAMEORIGIN"))

    _override(frame_options="DENY")

    assert (_response(first))["X-Frame-Options"] == "DENY"
    assert (_response(second))["X-Frame-Options"] == "DENY"


def test_an_app_created_after_the_call_gets_the_override() -> None:
    _override(csp=GLOBAL_CSP)

    assert (_response(_app()))["Content-Security-Policy"].endswith("global.example")


def test_nobody_calling_configure_leaves_every_app_alone() -> None:
    first = _app()
    second = _app(_config(csp=OTHER_CSP))

    assert (_response(first))["Content-Security-Policy"].endswith("app.example")
    assert (_response(second))["Content-Security-Policy"] == "default-src 'none'"


def test_the_managers_own_headers_keep_the_full_replace() -> None:
    security_headers_manager.configure(csp=GLOBAL_CSP, frame_options="DENY")
    security_headers_manager.configure(csp=GLOBAL_CSP)

    headers = security_headers_manager.get_headers()

    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert "Content-Security-Policy" in headers


def test_hsts_sub_keys_merge_over_the_hsts_of_the_app() -> None:
    app = _app()

    _override(hsts_max_age=100)

    assert (_response(app))["Strict-Transport-Security"] == (
        "max-age=100; includeSubDomains"
    )


def test_the_call_can_switch_a_header_off_for_every_app() -> None:
    app = _app()

    _override(frame_options=None)

    assert "X-Frame-Options" not in _response(app)


def test_an_app_with_headers_off_stays_off() -> None:
    app = _app(SecurityConfig(enable_redis=False, security_headers=None))

    _override(csp=GLOBAL_CSP)

    assert "Content-Security-Policy" not in _response(app)


def test_enabled_false_in_a_call_switches_every_app_off() -> None:
    app = _app()

    _override(enabled=False)

    assert _response(app) == {}


def test_a_second_call_that_omits_a_key_drops_it_with_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app()
    _override(csp=GLOBAL_CSP, frame_options="SAMEORIGIN")
    assert (_response(app))["X-Frame-Options"] == "SAMEORIGIN"

    with caplog.at_level(logging.INFO, logger=LOGGER):
        _override(csp=OTHER_CSP)

    after = _response(app)
    assert after["X-Frame-Options"] == "DENY"
    assert after["Content-Security-Policy"] == "default-src 'none'"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    dropped = re.search(r"dropped keys: ([^;]*);", warnings[0].getMessage())
    assert dropped is not None
    assert dropped.group(1) == "frame_options"


def test_a_bare_call_clears_the_override_with_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app()
    _override(csp=GLOBAL_CSP, frame_options="SAMEORIGIN")

    with caplog.at_level(logging.INFO, logger=LOGGER):
        _override()

    after = _response(app)
    assert after["Content-Security-Policy"].endswith("app.example")
    assert after["X-Frame-Options"] == "DENY"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "csp" in message
    assert "frame_options" in message


def test_a_bare_call_with_nothing_to_clear_logs_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        _override()

    assert caplog.records == []


def test_every_call_that_changes_the_override_logs_one_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger=LOGGER):
        _override(csp=GLOBAL_CSP)
        _override(csp=GLOBAL_CSP)

    assert [r.levelno for r in caplog.records] == [logging.INFO]


def test_reset_clears_the_override_in_the_process() -> None:
    app = _app()
    _override(csp=GLOBAL_CSP)

    security_headers_manager.reset()

    assert (_response(app))["Content-Security-Policy"].endswith("app.example")


def test_values_are_redacted_in_the_log_and_the_event(
    caplog: pytest.LogCaptureFixture,
) -> None:
    agent = MagicMock()
    agent.send_event = MagicMock()
    app = _app(agent=agent)

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        _override(custom_headers={"X-Auth-Token": "SEKRET-VALUE", "X-Build": "build-7"})
    _response(app)

    assert "SEKRET-VALUE" not in caplog.text
    assert "X-Auth-Token" in caplog.text
    agent.send_event.assert_called()
    event = _override_events(agent)[-1]
    assert "SEKRET-VALUE" not in json.dumps(event.metadata)
    assert event.metadata["override_keys"] == ["custom"]
    assert event.metadata["dropped_keys"] == []


def test_the_event_lists_the_dropped_keys_with_redacted_values() -> None:
    agent = MagicMock()
    agent.send_event = MagicMock()
    app = _app(agent=agent)
    _override(csp=GLOBAL_CSP, custom_headers={"X-Auth-Token": "SEKRET-VALUE"})
    _response(app)

    _override(csp=GLOBAL_CSP)
    _response(app)

    event = _override_events(agent)[-1]
    assert event.metadata["dropped_keys"] == ["custom"]
    assert "SEKRET-VALUE" not in json.dumps(event.metadata)


def test_no_override_means_no_redis_traffic_beyond_the_pull(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)

    for _ in range(20):
        _response(app)
    assert (redis.gets, redis.sets) == (1, 0)

    clock.now += 5.0
    _response(app)
    assert (redis.gets, redis.sets) == (2, 0)


def test_the_call_is_saved_without_a_ttl_under_the_prefix_and_config_hash(
    clock: Clock,
) -> None:
    redis = FakeRedis("svc:")
    app = _app(redis=redis)
    _override(csp=GLOBAL_CSP)

    _response(app)

    keys = [key for key in redis.store if key.startswith("svc:security_headers:")]
    assert len(keys) == 1
    assert redis.ttls[keys[0]] is None
    assert json.loads(redis.store[keys[0]])["keys"] == {"csp": GLOBAL_CSP}


def test_a_second_worker_applies_the_override_within_five_seconds(
    clock: Clock, other_worker: Callable[[], Any]
) -> None:
    redis = FakeRedis()
    worker_a = _app(redis=redis)
    worker_b = _app(redis=redis)
    with other_worker():
        assert (_response(worker_b))["Content-Security-Policy"].endswith("app.example")
    _override(csp=GLOBAL_CSP)
    _response(worker_a)

    clock.now += 4.9
    with other_worker():
        assert (_response(worker_b))["Content-Security-Policy"].endswith("app.example")
        clock.now += 0.2
        assert (_response(worker_b))["Content-Security-Policy"].endswith(
            "global.example"
        )


def test_a_worker_started_with_another_config_ignores_the_override(
    clock: Clock, other_worker: Callable[[], Any]
) -> None:
    redis = FakeRedis()
    worker_a = _app(redis=redis)
    worker_b = _app(_config(frame_options="SAMEORIGIN"), redis=redis)
    _override(csp=GLOBAL_CSP)
    _response(worker_a)

    clock.now += 10.0
    with other_worker():
        assert (_response(worker_b))["Content-Security-Policy"].endswith("app.example")


def test_redis_down_keeps_the_last_applied_override(
    clock: Clock, other_worker: Callable[[], Any]
) -> None:
    redis = FakeRedis()
    worker_a = _app(redis=redis)
    worker_b = _app(redis=redis)
    _override(csp=GLOBAL_CSP)
    _response(worker_a)
    with other_worker():
        clock.now += 10.0
        assert (_response(worker_b))["Content-Security-Policy"].endswith(
            "global.example"
        )

        redis.down = True
        clock.now += 10.0
        assert (_response(worker_b))["Content-Security-Policy"].endswith(
            "global.example"
        )


def test_reset_clears_the_override_in_redis_and_other_workers_follow(
    clock: Clock, other_worker: Callable[[], Any]
) -> None:
    redis = FakeRedis()
    worker_a = _app(redis=redis)
    worker_b = _app(redis=redis)
    _override(csp=GLOBAL_CSP)
    _response(worker_a)
    with other_worker():
        clock.now += 10.0
        _response(worker_b)

    security_headers_manager.redis_handler = redis
    security_headers_manager.reset()

    assert [key for key in redis.store if "security_headers" in key] == []
    with other_worker():
        clock.now += 10.0
        assert (_response(worker_b))["Content-Security-Policy"].endswith("app.example")


def test_a_bare_call_deletes_the_saved_override(clock: Clock) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    _override(csp=GLOBAL_CSP)
    _response(app)
    assert redis.store

    _override()
    _response(app)

    assert redis.store == {}


def test_the_factory_hands_the_context_redis_to_its_manager() -> None:
    redis = FakeRedis()
    metrics = MagicMock(spec=MetricsCollector)

    factory = ErrorResponseFactory(
        ResponseContext(
            config=_config(),
            logger=MagicMock(),
            metrics_collector=metrics,
            response_factory=MockGuardResponseFactory(),
            redis_handler=redis,
        )
    )

    assert factory.security_headers_manager.redis_handler is redis


def test_the_not_passed_marker_is_falsy_and_prints_its_name() -> None:
    assert not override_module.NOT_PASSED
    assert repr(override_module.NOT_PASSED) == "NOT_PASSED"


def test_now_monotonic_is_the_monotonic_clock() -> None:
    before = time.monotonic()
    assert before <= override_module.now_monotonic() <= time.monotonic()


def test_a_call_without_hsts_parameters_passes_no_hsts_key() -> None:
    passed = override_module.override_from_call(
        enabled=True,
        csp=override_module.NOT_PASSED,
        hsts_max_age=override_module.NOT_PASSED,
        hsts_include_subdomains=override_module.NOT_PASSED,
        hsts_preload=override_module.NOT_PASSED,
        frame_options=override_module.NOT_PASSED,
        content_type_options=override_module.NOT_PASSED,
        xss_protection=override_module.NOT_PASSED,
        referrer_policy=override_module.NOT_PASSED,
        permissions_policy="UNSET",
        custom_headers=override_module.NOT_PASSED,
    )

    assert passed == {"enabled": True}


def test_hsts_max_age_none_switches_hsts_off_whatever_else_is_passed() -> None:
    passed = override_module.override_from_call(
        enabled=override_module.NOT_PASSED,
        csp=override_module.NOT_PASSED,
        hsts_max_age=None,
        hsts_include_subdomains=False,
        hsts_preload=True,
        frame_options=override_module.NOT_PASSED,
        content_type_options=override_module.NOT_PASSED,
        xss_protection=override_module.NOT_PASSED,
        referrer_policy=override_module.NOT_PASSED,
        permissions_policy="UNSET",
        custom_headers=override_module.NOT_PASSED,
    )

    assert passed == {"hsts": None}


@pytest.mark.parametrize(
    "raw", ["not json", '{"set_at": 1}', '{"set_at": 1, "keys": 3}']
)
def test_an_unreadable_record_is_refused(raw: str) -> None:
    with pytest.raises((ValueError, KeyError, TypeError)):
        override_module.OverrideRecord.from_json(raw)


def test_the_config_fingerprint_ignores_object_addresses_and_set_order() -> None:
    def check(request: Any) -> None:
        return None

    first = SecurityConfig(
        enable_redis=False, custom_request_check=check, whitelist=["10.0.0.1"]
    )
    second = SecurityConfig(
        enable_redis=False, custom_request_check=check, whitelist=["10.0.0.1"]
    )

    assert override_module.config_fingerprint(first) == (
        override_module.config_fingerprint(second)
    )
    assert override_module.config_fingerprint(first) != (
        override_module.config_fingerprint(_config())
    )


def test_a_manager_that_is_not_the_global_one_does_not_set_the_override() -> None:
    SecurityHeadersManager.isolated().configure(csp=GLOBAL_CSP, override_apps=True)

    assert override_module.PROCESS_OVERRIDE.record.keys == {}


def test_a_failed_save_is_retried_after_five_seconds(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis()
    redis.down = True
    app = _app(redis=redis)
    _override(csp=GLOBAL_CSP)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        _response(app)
        _response(app)
    assert redis.sets == 1
    assert "Failed to save the security headers override" in caplog.text

    redis.down = False
    clock.now += 5.0
    _response(app)
    assert redis.sets == 2
    assert len(redis.store) == 1


def test_a_failed_pull_is_logged_and_retried_after_five_seconds(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis()
    redis.down = True
    app = _app(redis=redis)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        _response(app)
        _response(app)
    assert redis.gets == 0
    assert redis.round_trips == 0
    assert "keeping the last applied one" in caplog.text


def test_an_unreadable_override_in_redis_is_ignored_with_a_warning(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    _response(app)
    key = f"t:security_headers:{app.security_headers_manager._override_key()}"
    redis.store[key] = "not json"

    clock.now += 5.0
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        headers = _response(app)

    assert headers["Content-Security-Policy"].endswith("app.example")
    assert "unreadable security headers override" in caplog.text


def test_a_pulled_override_older_than_the_local_one_is_ignored(
    clock: Clock, other_worker: Callable[[], Any]
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    _override(csp=GLOBAL_CSP)
    _response(app)
    manager = app.security_headers_manager
    stale = override_module.OverrideRecord(1.0, {"csp": OTHER_CSP})
    redis.store[f"t:security_headers:{manager._override_key()}"] = stale.to_json()

    clock.now += 5.0
    headers = _response(app)

    assert headers["Content-Security-Policy"].endswith("global.example")


def test_a_failing_agent_does_not_break_the_response() -> None:
    agent = MagicMock()
    agent.send_event = MagicMock(side_effect=RuntimeError("agent down"))
    app = _app(agent=agent)
    _override(csp=GLOBAL_CSP)

    assert (_response(app))["Content-Security-Policy"].endswith("global.example")


def test_an_app_without_an_agent_still_applies_the_override() -> None:
    app = _app()
    _override(csp=GLOBAL_CSP)

    assert (_response(app))["Content-Security-Policy"].endswith("global.example")


def test_changing_a_value_of_the_same_keys_is_an_info_not_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    _override(csp=GLOBAL_CSP)

    with caplog.at_level(logging.INFO, logger=LOGGER):
        _override(csp=OTHER_CSP)

    assert [r.levelno for r in caplog.records] == [logging.INFO]


def test_resolve_headers_applies_the_override_and_the_off_switch() -> None:
    manager = SecurityHeadersManager.isolated()
    config = _config()

    _override(frame_options="SAMEORIGIN")
    assert manager.resolve_headers(config)["X-Frame-Options"] == "SAMEORIGIN"

    _override(enabled=False)
    assert manager.resolve_headers(config) == {}


def test_resetting_another_manager_leaves_the_process_override() -> None:
    app = _app()
    _override(csp=GLOBAL_CSP)

    SecurityHeadersManager.isolated().reset()

    assert (_response(app))["Content-Security-Policy"].endswith("global.example")


def test_an_empty_override_never_touches_a_redis_it_never_wrote(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    _override(csp=GLOBAL_CSP)
    _override()
    app = _app(redis=redis)

    _response(app)
    _override(csp=GLOBAL_CSP)
    _override()
    _response(app)

    assert redis.sets == 0
    assert redis.store == {}
    manager = app.security_headers_manager
    assert manager._override_saved_at == manager._override.set_at > 0


def test_a_call_without_the_flag_configures_only_the_manager(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app()

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        security_headers_manager.configure(csp=GLOBAL_CSP)

    assert caplog.records == []
    assert override_module.PROCESS_OVERRIDE.record.keys == {}
    assert (_response(app))["Content-Security-Policy"].endswith("app.example")
    manager_headers = security_headers_manager.get_headers()
    assert manager_headers["Content-Security-Policy"].endswith("global.example")


def test_a_record_whose_keys_are_not_an_object_is_refused_with_its_reason() -> None:
    with pytest.raises(ValueError, match="^override keys must be an object$"):
        override_module.OverrideRecord.from_json('{"set_at": 1, "keys": [1]}')


def test_the_process_override_starts_empty() -> None:
    record = override_module._ProcessOverride().record

    assert isinstance(record, override_module.OverrideRecord)
    assert record.set_at == 0.0
    assert dict(record.keys) == {}


def test_every_passed_parameter_becomes_its_key() -> None:
    passed = override_module.override_from_call(
        enabled=True,
        csp={"default-src": ["'self'"]},
        hsts_max_age=100,
        hsts_include_subdomains=False,
        hsts_preload=True,
        frame_options="DENY",
        content_type_options="nosniff",
        xss_protection="0",
        referrer_policy="no-referrer",
        permissions_policy="camera=()",
        custom_headers={"X-A": "1"},
    )

    assert passed == {
        "enabled": True,
        "csp": {"default-src": ["'self'"]},
        "frame_options": "DENY",
        "content_type_options": "nosniff",
        "xss_protection": "0",
        "referrer_policy": "no-referrer",
        "custom": {"X-A": "1"},
        "permissions_policy": "camera=()",
        "hsts": {"max_age": 100, "include_subdomains": False, "preload": True},
    }


def test_only_the_hsts_sub_keys_a_call_passed_are_recorded() -> None:
    not_passed = override_module.NOT_PASSED

    assert override_module._hsts_from_call(not_passed, not_passed, True) == {
        "preload": True
    }
    assert override_module._hsts_from_call(7, not_passed, not_passed) == {"max_age": 7}
    assert override_module._hsts_from_call(7, False, not_passed) == {
        "max_age": 7,
        "include_subdomains": False,
    }


def test_the_override_replaces_keys_and_merges_only_hsts() -> None:
    effective = {
        "frame_options": "DENY",
        "csp": {"a": ["1"]},
        "hsts": {"max_age": 1, "include_subdomains": True},
        "referrer_policy": "no-referrer",
    }

    merged = override_module.apply_override(
        effective,
        {"csp": {"b": ["2"]}, "hsts": {"max_age": 9}, "frame_options": None},
    )

    assert merged == {
        "frame_options": None,
        "csp": {"b": ["2"]},
        "hsts": {"max_age": 9, "include_subdomains": True},
        "referrer_policy": "no-referrer",
    }
    assert effective["frame_options"] == "DENY"
    assert override_module.apply_override({"hsts": None}, {"hsts": {"max_age": 9}}) == {
        "hsts": {"max_age": 9}
    }
    assert override_module.apply_override({"hsts": {"max_age": 1}}, {"hsts": None}) == {
        "hsts": None
    }


def test_the_override_fingerprint_is_empty_stable_and_sixteen_characters() -> None:
    assert override_module.override_fingerprint({}) == ""
    first = override_module.override_fingerprint({"a": 1, "b": {1, 2}})
    second = override_module.override_fingerprint({"b": {1, 2}, "a": 1})
    assert first == second
    assert len(first) == 16
    assert first != override_module.override_fingerprint({"a": 2, "b": {1, 2}})


def test_the_config_fingerprint_is_thirty_two_characters_and_order_free() -> None:
    config = _config()

    assert len(override_module.config_fingerprint(config)) == 32

    class Reordered:
        def model_dump(self, mode: str) -> dict[str, int]:
            assert mode == "python"
            return {"b": 1, "a": 2}

    class Ordered:
        def model_dump(self, mode: str) -> dict[str, int]:
            return {"a": 2, "b": 1}

    assert override_module.config_fingerprint(Reordered()) == (
        override_module.config_fingerprint(Ordered())
    )


def test_unstable_values_reduce_to_their_qualified_names() -> None:
    class Check:
        def __call__(self) -> None:
            return None

    stable = override_module._stable
    assert stable({"b", "a"}) == ["a", "b"]
    assert stable(frozenset({2, 1})) == ["1", "2"]
    assert stable(len) == "builtins.len"
    assert stable(Check()) == f"{Check.__module__}.Check"
    assert stable(object()) == "<builtins.object>"


def test_display_values_are_compact_sorted_json_for_dicts_and_str_otherwise() -> None:
    display = override_module._display_value

    assert display({"b": 1, "a": [2]}) == '{"a": [2], "b": 1}'
    assert display({"a": {1}}) == '{"a": "{1}"}'
    assert display("x") == "x"
    assert display(5) == "5"
    assert display(None) == "None"


def test_the_override_is_displayed_by_header_name() -> None:
    shown = override_module.override_display(
        {
            "custom": {"X-A": "1", "X-B": 2},
            "csp": {"d": ["s"]},
            "hsts": {"max_age": 1},
            "frame_options": "DENY",
            "unknown_key": "v",
        }
    )

    assert shown == {
        "X-A": "1",
        "X-B": "2",
        "Content-Security-Policy": '{"d": ["s"]}',
        "Strict-Transport-Security": '{"max_age": 1}',
        "X-Frame-Options": "DENY",
        "unknown_key": "v",
    }
    assert override_module.override_display({"custom": "text"}) == {"custom": "text"}


def test_the_event_metadata_has_the_four_documented_fields() -> None:
    assert override_module.override_event_metadata(
        ["b", "a"], ["d"], {"X": "1"}, {"Y": "2"}
    ) == {
        "override_keys": ["a", "b"],
        "dropped_keys": ["d"],
        "override_values": {"X": "1"},
        "dropped_values": {"Y": "2"},
    }


def test_a_new_manager_starts_with_no_override_state() -> None:
    manager = SecurityHeadersManager.isolated()

    assert manager._override.set_at == 0.0
    assert manager._override_saved_at == 0.0
    assert manager._override_announced_at == 0.0
    assert _in_redis(manager) is False
    assert manager._override_next_pull == 0.0
    assert manager._override_save_retry_at == 0.0
    assert manager._startup_hash is None


def test_a_process_record_with_the_same_time_does_not_replace_the_own_one() -> None:
    manager = SecurityHeadersManager.isolated()
    own = override_module.OverrideRecord(5.0, {"csp": APP_CSP})
    manager._override = own
    override_module.PROCESS_OVERRIDE.record = override_module.OverrideRecord(
        5.0, {"csp": OTHER_CSP}
    )

    assert manager._current_override() is own


def test_the_next_set_time_is_just_after_the_current_one() -> None:
    manager = SecurityHeadersManager.isolated()
    manager._override = override_module.OverrideRecord(time.time() + 1000, {})

    gap = manager._next_set_at() - manager._override.set_at

    assert 0 < gap <= 1e-5


def test_the_log_lines_have_the_documented_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger=LOGGER):
        _override(
            csp=OTHER_CSP,
            frame_options="SAMEORIGIN",
            custom_headers={"X-Auth-Token": "S"},
        )
        _override(csp=GLOBAL_CSP)
        _override()

    set_line, drop_line, clear_line = [r.getMessage() for r in caplog.records]
    assert set_line == (
        "Security headers override set by configure(): keys: csp, custom, "
        "frame_options; values: {'Content-Security-Policy': "
        "'{\"default-src\": [\"\\'none\\'\"]}', 'X-Frame-Options': 'SAMEORIGIN', "
        "'X-Auth-Token': '[REDACTED]'}"
    )
    assert drop_line == (
        "Security headers override changed by configure(): dropped keys: custom, "
        "frame_options; dropped values: {'X-Frame-Options': 'SAMEORIGIN', "
        "'X-Auth-Token': '[REDACTED]'}; override now sets: csp; values: "
        "{'Content-Security-Policy': "
        '\'{"default-src": ["\\\'self\\\'", "https://global.example"]}\'}'
    )
    assert clear_line == (
        "Security headers override changed by configure(): dropped keys: csp; "
        "dropped values: {'Content-Security-Policy': "
        '\'{"default-src": ["\\\'self\\\'", "https://global.example"]}\'}; '
        "override now sets: nothing; values: {}"
    )


def test_an_app_without_redis_never_computes_the_startup_hash() -> None:
    app = _app()

    _response(app)

    assert app.security_headers_manager._startup_hash is None


def test_an_override_event_is_sent_once_per_record() -> None:
    agent = MagicMock()
    agent.send_event = MagicMock()
    app = _app(agent=agent)
    _override(csp=GLOBAL_CSP)

    for _ in range(3):
        _response(app)

    assert len(_override_events(agent)) == 1


def test_the_override_events_describe_a_change_and_a_clear() -> None:
    agent = MagicMock()
    agent.send_event = MagicMock()
    app = _app(agent=agent)
    _override(csp=GLOBAL_CSP)
    _response(app)
    _override()
    _response(app)

    changed, cleared = _override_events(agent)

    assert changed.action_taken == "override_changed"
    assert cleared.action_taken == "override_cleared"
    for event in (changed, cleared):
        assert event.event_type == "security_headers_applied"
        assert event.handler_name == "security_headers"
        assert event.timestamp.tzinfo is not None
    assert cleared.metadata["dropped_keys"] == ["csp"]
    assert cleared.metadata["override_keys"] == []
    assert changed.metadata["override_values"] == {
        "Content-Security-Policy": '{"default-src": ["\'self\'", "https://global.example"]}'
    }


def test_a_failing_agent_is_logged_at_debug_without_the_error_internals(
    caplog: pytest.LogCaptureFixture,
) -> None:
    agent = MagicMock()
    agent.send_event = MagicMock(side_effect=RuntimeError("agent down"))
    app = _app(agent=agent)
    _override(csp=GLOBAL_CSP)

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        _response(app)

    assert "Failed to send the override event to agent: agent down" in [
        r.getMessage() for r in caplog.records
    ]


def test_a_failed_save_logs_the_error_and_keeps_the_override_unsaved(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis()
    redis.down = True
    app = _app(redis=redis)
    _override(csp=GLOBAL_CSP)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        _response(app)

    manager = app.security_headers_manager
    assert [r.getMessage() for r in caplog.records][-1] == (
        "Failed to save the security headers override: redis is down"
    )
    assert manager._override_saved_at == 0.0
    assert vars(manager)["_override_in_redis"] is False
    assert manager._override_save_retry_at == clock.now + 5.0


def test_a_failed_pull_logs_the_error(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis()
    redis.down = True
    app = _app(redis=redis)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        _response(app)

    assert [r.getMessage() for r in caplog.records] == [
        "Failed to pull the security headers override, keeping the last applied "
        "one: redis is down"
    ]
    assert app.security_headers_manager._override_next_pull == clock.now + 5.0


def test_an_unreadable_record_logs_its_reason(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    _response(app)
    key = f"t:security_headers:{app.security_headers_manager._override_key()}"
    redis.store[key] = '{"set_at": 1, "keys": 3}'

    clock.now += 5.0
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        _response(app)

    assert [r.getMessage() for r in caplog.records] == [
        "Ignoring an unreadable security headers override in Redis: "
        "override keys must be an object"
    ]


def test_a_pulled_record_is_adopted_and_logged_once(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    _response(app)
    manager = app.security_headers_manager
    key = f"t:security_headers:{manager._override_key()}"
    record = override_module.OverrideRecord(time.time() + 1000, {"csp": GLOBAL_CSP})
    redis.store[key] = record.to_json()

    with caplog.at_level(logging.INFO, logger=LOGGER):
        for _ in range(3):
            clock.now += 5.0
            _response(app)

    assert [r.getMessage() for r in caplog.records] == [
        "Security headers override pulled from Redis: keys: csp; values: "
        "{'Content-Security-Policy': "
        '\'{"default-src": ["\\\'self\\\'", "https://global.example"]}\'}'
    ]
    assert manager._override_saved_at == record.set_at
    assert _in_redis(manager) is True


def test_a_pulled_empty_record_is_logged_as_nothing(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    _response(app)
    key = f"t:security_headers:{app.security_headers_manager._override_key()}"
    redis.store[key] = override_module.OverrideRecord(time.time() + 1000, {}).to_json()

    clock.now += 5.0
    with caplog.at_level(logging.INFO, logger=LOGGER):
        _response(app)

    assert [r.getMessage() for r in caplog.records] == [
        "Security headers override pulled from Redis: keys: nothing; values: {}"
    ]


def test_a_record_that_vanishes_from_redis_clears_what_was_taken_from_it(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    _response(app)
    manager = app.security_headers_manager
    key = f"t:security_headers:{manager._override_key()}"
    redis.store[key] = override_module.OverrideRecord(
        time.time() + 1000, {"csp": GLOBAL_CSP}
    ).to_json()
    clock.now += 5.0
    _response(app)
    assert _in_redis(manager) is True
    del redis.store[key]

    clock.now += 5.0
    with caplog.at_level(logging.INFO, logger=LOGGER):
        headers = _response(app)

    assert headers["Content-Security-Policy"].endswith("app.example")
    assert [r.getMessage() for r in caplog.records] == [
        "Security headers override cleared in Redis"
    ]
    assert _in_redis(manager) is False
    assert manager._override_saved_at == manager._override.set_at
    assert manager._override_saved_at is not None


def test_reset_forgets_every_piece_of_override_state(clock: Clock) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    _override(csp=GLOBAL_CSP)
    _response(app)
    manager = app.security_headers_manager
    assert _hash_of(manager) is not None
    assert _in_redis(manager) is True

    manager.reset()

    assert _hash_of(manager) is None
    assert _in_redis(manager) is False
    assert manager._override_next_pull == 0.0
    assert manager._override_saved_at == manager._override.set_at
    assert dict(manager._override.keys) == {}


def test_a_callable_without_module_or_name_attributes_still_gets_a_stable_name() -> (
    None
):
    class Bare:
        def __getattribute__(self, name: str) -> object:
            if name in ("__module__", "__qualname__"):
                raise AttributeError(name)
            return object.__getattribute__(self, name)

        def __call__(self) -> None:
            return None

    class Plain:
        pass

    assert override_module._stable(Bare()) == ".Bare"
    assert override_module._stable(Plain()) == (
        f"<{Plain.__module__}.{Plain.__qualname__}>"
    )


def test_the_log_lines_join_several_keys_with_a_comma(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    _override(csp=GLOBAL_CSP, frame_options="DENY", referrer_policy="no-referrer")
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        _override(csp=GLOBAL_CSP, frame_options="DENY")
    assert "override now sets: csp, frame_options; values:" in caplog.text

    redis = FakeRedis()
    app = _app(redis=redis)
    _response(app)
    key = f"t:security_headers:{app.security_headers_manager._override_key()}"
    redis.store[key] = override_module.OverrideRecord(
        time.time() + 1000, {"frame_options": "DENY", "csp": GLOBAL_CSP}
    ).to_json()
    clock.now += 5.0
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=LOGGER):
        _response(app)
    assert "pulled from Redis: keys: csp, frame_options; values:" in caplog.text


def test_configure_keeps_the_defaults_for_what_a_call_leaves_out() -> None:
    manager = SecurityHeadersManager.isolated()

    manager.configure(hsts_max_age=100)

    assert manager.hsts_config == {
        "max_age": 100,
        "include_subdomains": True,
        "preload": False,
    }
    assert manager.cors_config is None
    assert manager.enabled is True

    manager.configure(hsts_max_age=31536000)

    assert manager.hsts_config == {
        "max_age": 31536000,
        "include_subdomains": True,
        "preload": False,
    }


def test_configure_hands_every_parameter_to_the_managers_own_state() -> None:
    manager = SecurityHeadersManager.isolated()

    manager.configure(
        enabled=True,
        csp=GLOBAL_CSP,
        hsts_max_age=31536000,
        hsts_include_subdomains=True,
        hsts_preload=True,
        frame_options="DENY",
        content_type_options="custom-nosniff",
        xss_protection="1",
        referrer_policy="no-referrer",
        permissions_policy="camera=()",
        custom_headers={"X-Own": "1"},
        cors_origins=["https://a.example"],
        cors_allow_credentials=True,
        cors_allow_methods=["PUT"],
        cors_allow_headers=["X-H"],
    )

    headers = manager.get_headers()
    assert headers["X-Content-Type-Options"] == "custom-nosniff"
    assert headers["X-XSS-Protection"] == "1"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Permissions-Policy"] == "camera=()"
    assert headers["X-Own"] == "1"
    assert headers["Strict-Transport-Security"] == (
        "max-age=31536000; includeSubDomains; preload"
    )
    assert manager.cors_config == {
        "origins": ["https://a.example"],
        "allow_credentials": True,
        "allow_methods": ["PUT"],
        "allow_headers": ["X-H"],
        "max_age": 3600,
    }


def test_configure_defaults_the_cors_credentials_to_false() -> None:
    manager = SecurityHeadersManager.isolated()

    manager.configure(cors_origins=["https://a.example"])

    assert manager.cors_config is not None
    assert manager.cors_config["allow_credentials"] is False


def test_a_record_stamped_far_ahead_does_not_outrank_a_later_call() -> None:
    app = _app()
    override_module.PROCESS_OVERRIDE.record = override_module.OverrideRecord(
        time.time() + 10**9, {"csp": OTHER_CSP}
    )

    assert (_response(app))["Content-Security-Policy"].endswith("app.example")

    _override(csp=GLOBAL_CSP)

    assert (_response(app))["Content-Security-Policy"].endswith("global.example")


def test_a_pulled_record_stamped_far_ahead_is_ignored(clock: Clock) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    _response(app)
    key = f"t:security_headers:{app.security_headers_manager._override_key()}"
    redis.store[key] = override_module.OverrideRecord(
        time.time() + 10**9, {"csp": OTHER_CSP}
    ).to_json()

    clock.now += 5.0

    assert (_response(app))["Content-Security-Policy"].endswith("app.example")


def test_a_record_ahead_by_less_than_the_skew_keeps_its_time() -> None:
    near = time.time() + override_module.MAX_CLOCK_SKEW_SECONDS - 60
    far = time.time() + override_module.MAX_CLOCK_SKEW_SECONDS + 60

    assert override_module.OverrideRecord(near, {}).ordered_at() == near
    assert override_module.OverrideRecord(far, {}).ordered_at() == 0.0


def test_a_global_reset_clears_an_override_an_app_pulled_from_redis(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    _response(app)
    manager = app.security_headers_manager
    key = f"t:security_headers:{manager._override_key()}"
    redis.store[key] = override_module.OverrideRecord(
        time.time() + 100, {"csp": GLOBAL_CSP}
    ).to_json()
    clock.now += 5.0
    assert (_response(app))["Content-Security-Policy"].endswith("global.example")

    security_headers_manager.reset()

    assert (_response(app))["Content-Security-Policy"].endswith("app.example")
    assert redis.store == {}
    assert _in_redis(manager) is False


def test_the_response_path_and_reset_never_read_the_wall_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app()
    _response(app)

    def forbidden() -> float:
        raise AssertionError("time.time() was called")

    monkeypatch.setattr(time, "time", forbidden)

    security_headers_manager.reset()
    app.security_headers_manager.reset()
    assert "Content-Security-Policy" in _response(app)
    assert override_module.OverrideRecord(1.0, {}).ordered_at() == 1.0


def test_the_approximate_clock_follows_the_monotonic_clock() -> None:
    before = override_module.approximate_now()
    time.sleep(0.01)

    assert 0.005 < override_module.approximate_now() - before < 1.0
    assert abs(override_module.approximate_now() - time.time()) < 5.0


def _released_startup_call() -> None:
    # The call every released adapter makes while it initializes (fastapi-guard
    # v8.1.2 guard/middleware.py:286-304), every key filled in from its config.
    security_headers_manager.configure(
        enabled=True,
        csp={"default-src": ["'self'", "https://startup.example"]},
        hsts_max_age=31536000,
        hsts_include_subdomains=True,
        hsts_preload=False,
        frame_options="SAMEORIGIN",
        content_type_options="nosniff",
        xss_protection="1; mode=block",
        referrer_policy="strict-origin-when-cross-origin",
        permissions_policy="UNSET",
        custom_headers=None,
        cors_origins=None,
        cors_allow_credentials=False,
        cors_allow_methods=None,
        cors_allow_headers=None,
    )


def test_the_startup_call_of_a_released_adapter_overrides_no_app(
    caplog: pytest.LogCaptureFixture,
) -> None:
    first = _app()
    second = _app(_config(csp=OTHER_CSP, xss_protection="0"))
    _response(first)

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        _released_startup_call()

    assert caplog.records == []
    after = _response(first)
    assert after["Content-Security-Policy"].endswith("app.example")
    assert after["X-Frame-Options"] == "DENY"
    assert after["X-XSS-Protection"] == "0"
    assert (_response(second))["Content-Security-Policy"] == ("default-src 'none'")


def test_the_startup_call_writes_nothing_to_redis(clock: Clock) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    _response(app)

    _released_startup_call()
    clock.now += 5.0
    _response(app)

    assert redis.sets == 0
    assert redis.store == {}


def test_a_direct_write_of_enabled_is_never_an_override() -> None:
    app = _app()

    security_headers_manager.enabled = False

    assert (_response(app))["Content-Security-Policy"].endswith("app.example")
    assert override_module.PROCESS_OVERRIDE.record.keys == {}
    security_headers_manager.enabled = True


def test_a_passed_enabled_true_switches_on_an_app_whose_headers_are_off() -> None:
    off = _app(SecurityConfig(enable_redis=False, security_headers=None))
    off_dict = _app(
        SecurityConfig(enable_redis=False, security_headers={"enabled": False})
    )
    assert _response(off) == {}

    _override(enabled=True)

    for app in (off, off_dict):
        headers = _response(app)
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "SAMEORIGIN"


def test_a_passed_enabled_false_switches_every_app_off_and_not_passed_keeps() -> None:
    on = _app()
    off = _app(SecurityConfig(enable_redis=False, security_headers=None))

    _override(csp=GLOBAL_CSP)

    assert (_response(on))["Content-Security-Policy"].endswith("global.example")
    assert _response(off) == {}

    _override(enabled=False)

    assert _response(on) == {}
    assert _response(off) == {}


def test_initialize_redis_loads_the_override_record_of_the_app_config(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    manager = app.security_headers_manager
    config = app.context.config
    saved = override_module.OverrideRecord(time.time() + 50, {"csp": GLOBAL_CSP})
    key = f"t:security_headers:override:{override_module.config_fingerprint(config)}"
    redis.store[key] = saved.to_json()

    manager.initialize_redis(redis, config)

    assert (_response(app))["Content-Security-Policy"].endswith("global.example")
    assert manager.redis_handler is redis


def test_the_override_is_saved_and_pulled_through_the_persistence_methods(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    manager = app.security_headers_manager
    calls: list[str] = []
    cache = type(manager)._cache_configuration
    load = type(manager)._load_cached_config

    def spy_cache(self: Any, *args: Any, **kwargs: Any) -> Any:
        calls.append("cache")
        return cache(self, *args, **kwargs)

    def spy_load(self: Any, *args: Any, **kwargs: Any) -> Any:
        calls.append("load")
        return load(self, *args, **kwargs)

    monkeypatch.setattr(type(manager), "_cache_configuration", spy_cache)
    monkeypatch.setattr(type(manager), "_load_cached_config", spy_load)

    _response(app)
    assert calls[:2] == ["load", "cache"]
    calls.clear()

    _override(csp=GLOBAL_CSP)
    _response(app)
    assert calls == ["cache"]
    assert len([k for k in redis.store if ":override:" in k]) == 1
    assert {redis.ttls[k] for k in redis.store} == {None}
    calls.clear()

    clock.now += 5.0
    _response(app)
    assert calls == ["load"]


def test_the_managers_own_keys_keep_their_v440_names_and_ttl() -> None:
    redis = FakeRedis()
    manager = SecurityHeadersManager.isolated()
    manager.configure(csp=GLOBAL_CSP, hsts_max_age=100, custom_headers={"X-O": "1"})
    manager.redis_handler = redis

    manager._cache_configuration()

    assert {k: redis.ttls[k] for k in redis.store} == {
        "t:security_headers:csp_config": 86400,
        "t:security_headers:hsts_config": 86400,
        "t:security_headers:custom_headers": 86400,
    }


def test_an_unbound_manager_reads_exactly_its_three_v440_keys() -> None:
    redis = FakeRedis()
    manager = SecurityHeadersManager.isolated()

    manager.initialize_redis(redis)

    assert redis.gets == 3


def test_a_sync_round_calls_the_persistence_methods_without_the_managers_own_keys(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    manager = app.security_headers_manager
    seen: list[tuple[str, Any]] = []
    cache = type(manager)._cache_configuration
    load = type(manager)._load_cached_config

    def spy_cache(self: Any, *args: Any, **kwargs: Any) -> Any:
        seen.append(("cache", kwargs.get("own_state")))
        return cache(self, *args, **kwargs)

    def spy_load(self: Any, *args: Any, **kwargs: Any) -> Any:
        seen.append(("load", kwargs.get("own_state")))
        return load(self, *args, **kwargs)

    _response(app)
    monkeypatch.setattr(type(manager), "_cache_configuration", spy_cache)
    monkeypatch.setattr(type(manager), "_load_cached_config", spy_load)
    _override(csp=GLOBAL_CSP)
    _response(app)
    clock.now += 5.0
    _response(app)

    assert seen == [("cache", False), ("load", False)]


def test_the_request_that_saves_the_override_does_not_also_pull(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    _response(app)
    gets = redis.gets

    _override(csp=GLOBAL_CSP)
    clock.now += 5.0
    _response(app)

    assert redis.sets == 1
    assert redis.gets == gets


def test_saving_an_override_that_is_already_saved_writes_nothing(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    _response(app)
    _override(csp=GLOBAL_CSP)
    _response(app)
    assert redis.sets == 1

    app.security_headers_manager._cache_configuration(own_state=False)

    assert redis.sets == 1


class Worker:
    """One simulated worker: its own override state and a local clock that is skewed."""

    def __init__(self, skew: float) -> None:
        self.skew = skew
        self.record = override_module.OverrideRecord(0.0, {})
        self.global_record = override_module.OverrideRecord(0.0, {})
        self.offset = 0.0

    @contextmanager
    def acting(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
        holder = override_module.PROCESS_OVERRIDE
        saved = (holder.record, getattr(holder, "clock_offset", 0.0))
        holder.record = self.record
        holder.clock_offset = self.offset
        saved_global = security_headers_manager._override
        security_headers_manager._override = self.global_record
        real = time.time

        def skewed() -> float:
            return real() + self.skew

        with monkeypatch.context() as patch:
            patch.setattr(override_module, "wall_now", skewed, raising=False)
            try:
                yield
            finally:
                self.record = holder.record
                self.global_record = security_headers_manager._override
                self.offset = getattr(holder, "clock_offset", 0.0)
                security_headers_manager._override = saved_global
                holder.record, holder.clock_offset = saved


@pytest.mark.parametrize(
    ("older_skew", "newer_skew"), [(3600.0, 0.0), (0.0, -3600.0), (3600.0, -3600.0)]
)
def test_the_newer_call_wins_whatever_the_skew_of_the_worker_clocks(
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
    older_skew: float,
    newer_skew: float,
) -> None:
    redis = FakeRedis()
    older, newer, observer = Worker(older_skew), Worker(newer_skew), Worker(0.0)
    apps = {}
    for name, worker in (("older", older), ("newer", newer), ("observer", observer)):
        with worker.acting(monkeypatch):
            apps[name] = _app(redis=redis)
            _response(apps[name])
    with older.acting(monkeypatch):
        _override(csp=OTHER_CSP)
        _response(apps["older"])
    time.sleep(0.05)
    with newer.acting(monkeypatch):
        _override(csp=GLOBAL_CSP)
        _response(apps["newer"])
    for _ in range(2):
        clock.now += 5.0
        with older.acting(monkeypatch):
            _response(apps["older"])
        with observer.acting(monkeypatch):
            seen = _response(apps["observer"])

    assert seen["Content-Security-Policy"].endswith("global.example")
    with older.acting(monkeypatch):
        assert (_response(apps["older"]))["Content-Security-Policy"].endswith(
            "global.example"
        )


def test_a_response_with_a_cors_origin_resolves_the_override_once(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(
        SecurityConfig(
            enable_redis=False,
            enable_cors=True,
            cors_allow_origins=["https://a.example"],
            security_headers={"enabled": True},
        )
    )
    _override(csp=GLOBAL_CSP)
    request = SyncMockGuardRequest(path="/x", headers={"origin": "https://a.example"})
    app.process_response(request, MockGuardResponse("ok", 200), 0.1, None)
    manager = app.security_headers_manager
    calls: list[int] = []
    original = type(manager)._current_override

    def counted(self: Any) -> Any:
        calls.append(1)
        return original(self)

    monkeypatch.setattr(type(manager), "_current_override", counted)
    monkeypatch.setattr(type(manager), "resolve_override", counted)

    response = app.process_response(request, MockGuardResponse("ok", 200), 0.1, None)

    assert response.headers["Content-Security-Policy"].endswith("global.example")
    assert len(calls) == 1


def test_a_response_resolves_the_override_once(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app()
    _override(csp=GLOBAL_CSP)
    _response(app)
    manager = app.security_headers_manager
    calls: list[int] = []
    original = type(manager)._current_override

    def counted(self: Any) -> Any:
        calls.append(1)
        return original(self)

    monkeypatch.setattr(type(manager), "_current_override", counted)
    monkeypatch.setattr(type(manager), "resolve_override", counted)

    _response(app)

    assert len(calls) == 1


def test_without_any_override_a_response_reads_no_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app()
    _response(app)
    reads: list[int] = []
    real = override_module.approximate_now

    def counted() -> float:
        reads.append(1)
        return real()

    monkeypatch.setattr(override_module, "approximate_now", counted)

    _response(app)

    assert reads == []


def test_the_clock_offset_is_measured_at_initialization_and_on_each_pull(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    redis = FakeRedis()
    worker = Worker(7200.0)
    with worker.acting(monkeypatch):
        app = _app(redis=redis)
        _response(app)
    assert redis.times == 1
    assert worker.offset == pytest.approx(-7200.0, abs=1.0)

    with worker.acting(monkeypatch):
        for _ in range(5):
            _response(app)
    assert redis.times == 1

    clock.now += 5.0
    with worker.acting(monkeypatch):
        _response(app)
    assert redis.times == 2


def test_a_redis_error_keeps_the_last_clock_offset(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    redis = FakeRedis()
    worker = Worker(-1800.0)
    with worker.acting(monkeypatch):
        app = _app(redis=redis)
        _response(app)
    measured = worker.offset
    assert measured == pytest.approx(1800.0, abs=1.0)

    redis.down = True
    clock.now += 5.0
    with worker.acting(monkeypatch):
        _response(app)

    assert worker.offset == measured


def test_a_call_is_stamped_on_redis_time(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    redis = FakeRedis()
    worker = Worker(3600.0)
    with worker.acting(monkeypatch):
        app = _app(redis=redis)
        _response(app)
        _override(csp=GLOBAL_CSP)
        stamp = override_module.PROCESS_OVERRIDE.record.set_at
        _response(app)

    assert stamp == pytest.approx(time.time(), abs=2.0)
    saved = next(iter(v for k, v in redis.store.items() if ":override:" in k))
    assert json.loads(saved)["set_at"] == pytest.approx(time.time(), abs=2.0)


def test_the_far_ahead_guard_works_on_the_corrected_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    holder = override_module.PROCESS_OVERRIDE
    monkeypatch.setattr(holder, "clock_offset", 5000.0)
    skew = override_module.MAX_CLOCK_SKEW_SECONDS
    near = override_module.approximate_now() + 5000.0 + skew - 60
    far = override_module.approximate_now() + 5000.0 + skew + 60

    assert override_module.OverrideRecord(near, {}).ordered_at() == near
    assert override_module.OverrideRecord(far, {}).ordered_at() == 0.0


def test_the_offset_costs_no_round_trip_of_its_own(clock: Clock) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)

    _response(app)
    assert (redis.round_trips, redis.gets, redis.times) == (1, 1, 1)

    for _ in range(5):
        _response(app)
    assert redis.round_trips == 1

    clock.now += 5.0
    _response(app)
    assert (redis.round_trips, redis.times) == (2, 2)


def test_the_registry_finds_a_handler_by_config_and_holds_it_weakly() -> None:
    registry = ConfigHandlerRegistry()
    config = _config()

    class Handler:
        pass

    handler = Handler()
    assert registry.lookup(config) is None

    registry.register(config, handler)
    assert registry.lookup(config) is handler
    assert registry.lookup(_config()) is None

    del handler
    gc.collect()
    assert registry.lookup(config) is None
    assert id(config) not in registry._entries


def test_the_handler_initializer_registers_its_redis_handler_under_the_config() -> None:
    config = _config()
    redis = FakeRedis()

    HandlerInitializer(config=config, redis_handler=redis)
    HandlerInitializer(config=_config())

    assert REDIS_HANDLERS.lookup(config) is redis


def test_a_released_adapter_gets_its_redis_found_at_the_pull_boundary(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    config = SecurityConfig(
        enable_redis=True,
        enable_agent=False,
        security_headers={"enabled": True, "csp": APP_CSP, "frame_options": "DENY"},
    )
    factory = _app(config)
    manager = factory.security_headers_manager
    assert _redis_of(manager) is None
    _response(factory)
    assert _redis_of(manager) is None

    HandlerInitializer(config=config, redis_handler=redis)
    _response(factory)
    assert _redis_of(manager) is None

    clock.now += 5.0
    _response(factory)

    assert _redis_of(manager) is redis
    _override(csp=GLOBAL_CSP)
    _response(factory)
    assert len([k for k in redis.store if ":override:" in k]) == 1


def test_the_lookup_runs_once_per_window_not_per_response(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = SecurityConfig(
        enable_redis=True, enable_agent=False, security_headers={"enabled": True}
    )
    factory = _app(config)
    lookups: list[int] = []
    original = REDIS_HANDLERS.lookup

    def counted(cfg: Any) -> Any:
        lookups.append(1)
        return original(cfg)

    monkeypatch.setattr(REDIS_HANDLERS, "lookup", counted)

    for _ in range(10):
        _response(factory)
    assert len(lookups) == 1

    clock.now += 5.0
    _response(factory)
    assert len(lookups) == 2


def test_an_app_without_redis_never_looks_a_handler_up(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    factory = _app()
    lookups: list[int] = []
    monkeypatch.setattr(REDIS_HANDLERS, "lookup", lambda cfg: lookups.append(1))

    clock.now += 50.0
    _response(factory)

    assert lookups == []


def test_the_registry_forgets_a_config_that_was_collected() -> None:
    registry = ConfigHandlerRegistry()

    class Handler:
        pass

    handler = Handler()
    config = _config()
    registry.register(config, handler)
    assert registry._entries

    del config
    gc.collect()

    assert registry._entries == {}


def test_the_registry_accepts_a_config_that_cannot_be_weakly_referenced() -> None:
    class Slotted:
        __slots__ = ()

    class Handler:
        pass

    registry = ConfigHandlerRegistry()
    config, handler = Slotted(), Handler()

    registry.register(config, handler)

    assert registry.lookup(config) is handler


def test_the_registry_keeps_kinds_apart_and_a_dead_entry_is_dropped_once() -> None:
    registry = ConfigHandlerRegistry()
    config = _config()

    class Handler:
        pass

    redis, limiter = Handler(), Handler()
    registry.register(config, redis, "redis")
    registry.register(config, limiter, "limiter")

    assert registry.lookup(config, "redis") is redis
    assert registry.lookup(config, "limiter") is limiter
    assert registry.lookup(config) is None

    del redis
    gc.collect()
    assert registry.lookup(config, "redis") is None
    assert registry.lookup(config, "redis") is None


def test_a_cors_handler_sees_the_override_a_manager_pulled(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    redis = FakeRedis()
    config = SecurityConfig(
        enable_redis=False,
        enable_cors=True,
        cors_allow_origins=["https://app.example"],
        security_headers={"enabled": True, "frame_options": "DENY"},
    )
    app = _app(config, redis=redis)
    _response(app)
    saved = override_module.OverrideRecord(
        time.time() + 10, {"frame_options": "SAMEORIGIN"}
    )
    manager = app.security_headers_manager
    redis.store[f"t:security_headers:{manager._override_key()}"] = saved.to_json()
    preflight = {
        "origin": "https://app.example",
        "access-control-request-method": "GET",
    }
    cors = CorsHandler(config)
    assert cors.build_preflight_response(preflight).headers["X-Frame-Options"] == (
        "DENY"
    )

    clock.now += 5.0
    _response(app)

    assert cors.build_preflight_response(preflight).headers["X-Frame-Options"] == (
        "SAMEORIGIN"
    )
    assert override_module.PULLED_OVERRIDES

    security_headers_manager.reset()
    assert override_module.PULLED_OVERRIDES == {}


def test_a_pulled_clear_reaches_the_cors_handler(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    config = SecurityConfig(
        enable_redis=False,
        enable_cors=True,
        cors_allow_origins=["https://app.example"],
        security_headers={"enabled": True, "frame_options": "DENY"},
    )
    app = _app(config, redis=redis)
    _response(app)
    manager = app.security_headers_manager
    key = f"t:security_headers:{manager._override_key()}"
    redis.store[key] = override_module.OverrideRecord(
        time.time() + 10, {"frame_options": "SAMEORIGIN"}
    ).to_json()
    clock.now += 5.0
    _response(app)
    del redis.store[key]
    clock.now += 5.0
    _response(app)
    preflight = {
        "origin": "https://app.example",
        "access-control-request-method": "GET",
    }

    cleared = CorsHandler(config).build_preflight_response(preflight)

    assert cleared.headers["X-Frame-Options"] == "DENY"


def test_the_own_state_is_tagged_with_the_startup_fingerprint(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    redis = FakeRedis()
    config = _config()
    manager = SecurityHeadersManager.isolated()
    monkeypatch.setattr(SecurityHeadersManager, "_instance", manager)
    manager.configure(csp=GLOBAL_CSP, custom_headers={"X-Own": "1"})

    manager.initialize_redis(redis, config)

    stored = json.loads(redis.store["t:security_headers:csp_config"])
    assert stored == {
        "fingerprint": override_module.config_fingerprint(config),
        "value": GLOBAL_CSP,
    }
    assert redis.ttls["t:security_headers:csp_config"] == 86400


def test_a_redeploy_with_another_config_ignores_the_stored_own_state(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    redis = FakeRedis()
    first = SecurityHeadersManager.isolated()
    monkeypatch.setattr(SecurityHeadersManager, "_instance", first)
    first.configure(csp=GLOBAL_CSP)
    first.initialize_redis(redis, _config())

    redeployed = SecurityHeadersManager.isolated()
    monkeypatch.setattr(SecurityHeadersManager, "_instance", redeployed)
    redeployed.configure(csp=OTHER_CSP)
    redeployed.initialize_redis(redis, _config(frame_options="SAMEORIGIN"))

    assert redeployed.csp_config == OTHER_CSP
    same = SecurityHeadersManager.isolated()
    monkeypatch.setattr(SecurityHeadersManager, "_instance", same)
    same.initialize_redis(redis, _config(frame_options="SAMEORIGIN"))
    assert same.csp_config == OTHER_CSP


def test_an_app_manager_never_reads_or_writes_the_own_state(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    app.security_headers_manager.configure(csp=GLOBAL_CSP)

    _response(app)

    assert not [k for k in redis.store if k.endswith("csp_config")]
    assert redis.gets == 1


def test_the_own_state_pull_rides_the_override_pull(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    redis = FakeRedis()
    config = _config()
    shared = security_headers_manager
    shared.initialize_redis(redis, config)
    app = _app(config, redis=redis)
    _response(app)
    trips = redis.round_trips
    redis.store["t:security_headers:csp_config"] = json.dumps(
        {
            "fingerprint": override_module.config_fingerprint(config),
            "value": OTHER_CSP,
        }
    )

    clock.now += 5.0
    _response(app)

    assert redis.round_trips == trips + 1
    assert shared.csp_config == OTHER_CSP


def test_a_configure_on_the_attached_manager_is_written_by_the_next_sync(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    config = _config()
    shared = security_headers_manager
    shared.initialize_redis(redis, config)
    app = _app(config, redis=redis)
    _response(app)
    assert not [k for k in redis.store if k.endswith("csp_config")]

    shared.configure(csp=GLOBAL_CSP)
    _response(app)

    stored = json.loads(redis.store["t:security_headers:csp_config"])
    assert stored["value"] == GLOBAL_CSP
    sets = redis.sets
    _response(app)
    assert redis.sets == sets


def test_the_handler_initializer_attaches_the_headers_manager_to_redis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix="test:wp10fu:",
        enable_agent=False,
        security_headers={"enabled": True},
    )
    redis = RedisManager(config)
    initializer = HandlerInitializer(config=config, redis_handler=redis)
    initializer.initialize_redis_handlers()
    try:
        assert security_headers_manager.redis_handler is redis
    finally:
        redis.close()


def test_a_mock_redis_handler_is_not_attached_to_the_headers_manager() -> None:
    config = _config()
    initializer = HandlerInitializer(config=config, redis_handler=MagicMock())

    attach_security_headers_manager_to_redis(initializer.redis_handler, config)

    assert security_headers_manager.redis_handler is None


def test_a_redis_handler_that_never_connected_is_not_attached() -> None:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix="test:wp10fu:",
        enable_agent=False,
    )
    redis = RedisManager(config)
    redis._redis = None

    attach_security_headers_manager_to_redis(redis, config)

    assert security_headers_manager.redis_handler is None


def test_the_registry_drops_an_entry_whose_handler_is_gone_without_its_callback() -> (
    None
):
    registry = ConfigHandlerRegistry()
    config = _config()

    class Handler:
        pass

    handler = Handler()
    dead = weakref.ref(handler)
    del handler
    gc.collect()
    registry._entries[(None, id(config))] = dead

    assert registry.lookup(config) is None
    assert registry._entries == {}


def test_own_state_with_another_fingerprint_or_nothing_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = SecurityHeadersManager.isolated()
    monkeypatch.setattr(SecurityHeadersManager, "_instance", manager)
    manager._startup_hash = "mine"
    tag = json.dumps

    manager._apply_own_state(
        tag({"fingerprint": "other", "value": GLOBAL_CSP}),
        tag({"fingerprint": "other", "value": {"max_age": 1}}),
        tag({"fingerprint": "other", "value": {"X-A": "1"}}),
    )
    assert (manager.csp_config, manager.hsts_config, manager.custom_headers) == (
        None,
        None,
        {},
    )

    manager._apply_own_state(
        tag({"fingerprint": "mine", "value": GLOBAL_CSP}),
        tag({"fingerprint": "mine", "value": {"max_age": 1}}),
        tag({"fingerprint": "mine", "value": {"X-A": "1"}}),
    )
    assert manager.csp_config == GLOBAL_CSP
    assert manager.hsts_config == {"max_age": 1}
    assert manager.custom_headers == {"X-A": "1"}

    manager._apply_own_state(None, None, None)
    assert manager.csp_config == GLOBAL_CSP


def test_the_cors_reader_resolves_its_config_hash_once_and_ignores_other_hashes(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config()
    cors_manager = SecurityHeadersManager.isolated()
    monkeypatch.setitem(
        override_module.PULLED_OVERRIDES,
        "some-other-hash",
        override_module.OverrideRecord(time.time() + 5, {"frame_options": "DENY"}),
    )

    assert cors_manager.override_for_reader(config).keys == {}
    assert cors_manager.override_for_reader(config).keys == {}
    assert cors_manager._reader_hash == (
        id(config),
        override_module.config_fingerprint(config),
    )


def test_a_dirty_global_manager_bound_to_another_config_is_not_flushed(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    redis = FakeRedis()
    shared = SecurityHeadersManager.isolated()
    monkeypatch.setattr(SecurityHeadersManager, "_instance", shared)
    shared.initialize_redis(redis, _config(frame_options="SAMEORIGIN"))
    shared.configure(csp=GLOBAL_CSP)
    assert shared._own_state_dirty
    app = _app(_config(), redis=redis)

    _response(app)
    _response(app)

    assert shared._own_state_dirty
    assert not [k for k in redis.store if k.endswith("csp_config")]


def test_an_unreadable_shared_own_state_is_logged_and_kept_out(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis()
    config = _config()
    security_headers_manager.initialize_redis(redis, config)
    app = _app(config, redis=redis)
    _response(app)
    redis.store["t:security_headers:csp_config"] = "not json"

    clock.now += 5.0
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        _response(app)

    assert "Ignoring unreadable cached header config in Redis" in caplog.text
    assert security_headers_manager.csp_config is None


NEW_ORIGIN = "https://new.example"
OLD_ORIGIN = "https://app.example"


def _cors_config(**overrides: Any) -> SecurityConfig:
    values: dict[str, Any] = {
        "enable_redis": False,
        "enable_cors": True,
        "cors_allow_origins": [OLD_ORIGIN],
        "cors_allow_methods": ["GET", "POST"],
        "security_headers": {"enabled": True},
    }
    values.update(overrides)
    return SecurityConfig(**values)


def _preflight(origin: str = NEW_ORIGIN, method: str = "POST") -> dict[str, str]:
    return {"origin": origin, "access-control-request-method": method}


def test_a_cors_only_flagged_call_is_recorded() -> None:
    security_headers_manager.configure(
        cors_origins=[NEW_ORIGIN], cors_max_age=60, override_apps=True
    )

    assert override_module.PROCESS_OVERRIDE.record.keys == {
        "cors_origins": [NEW_ORIGIN],
        "cors_max_age": 60,
    }


def test_a_call_without_the_flag_does_not_touch_the_cors_of_an_app() -> None:
    cors = CorsHandler(_cors_config())

    security_headers_manager.configure(cors_origins=[NEW_ORIGIN])

    assert cors.build_preflight_response(_preflight(OLD_ORIGIN)).status_code == 200
    assert cors.build_preflight_response(_preflight()).status_code == 400


def test_a_flagged_cors_call_changes_both_cors_emitters() -> None:
    config = _cors_config()
    cors = CorsHandler(config)
    app = _app(config)
    assert cors.build_preflight_response(_preflight()).status_code == 400
    assert (
        app.security_headers_manager.get_cors_headers(NEW_ORIGIN, config=config) == {}
    )

    _override(
        cors_origins=[NEW_ORIGIN],
        cors_allow_methods=["PUT"],
        cors_max_age=77,
        cors_expose_headers=["X-Seen"],
    )

    preflight = cors.build_preflight_response(_preflight(method="PUT"))
    assert preflight.status_code == 200
    assert preflight.headers["Access-Control-Allow-Origin"] == NEW_ORIGIN
    assert preflight.headers["Access-Control-Max-Age"] == "77"
    assert cors.build_preflight_response(_preflight(OLD_ORIGIN)).status_code == 400
    simple = cors.build_response_headers({"origin": NEW_ORIGIN})
    assert simple["Access-Control-Expose-Headers"] == "X-Seen"
    manager_headers = app.security_headers_manager.get_cors_headers(
        NEW_ORIGIN, config=config
    )
    assert manager_headers["Access-Control-Allow-Origin"] == NEW_ORIGIN
    assert manager_headers["Access-Control-Allow-Methods"] == "PUT"
    assert manager_headers["Access-Control-Max-Age"] == "77"


def test_a_flagged_clear_returns_the_cors_of_the_app() -> None:
    config = _cors_config()
    cors = CorsHandler(config)
    _override(cors_origins=[NEW_ORIGIN])
    assert cors.build_preflight_response(_preflight()).status_code == 200

    _override()

    assert cors.build_preflight_response(_preflight()).status_code == 400
    assert cors.build_preflight_response(_preflight(OLD_ORIGIN)).status_code == 200


def test_an_app_built_without_cors_needs_enable_cors_in_the_call(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _cors_config(enable_cors=False)
    cors = CorsHandler(config)
    app = _app(config)

    _override(cors_origins=[NEW_ORIGIN])
    assert not cors.is_enabled()
    assert (
        app.security_headers_manager.get_cors_headers(NEW_ORIGIN, config=config) == {}
    )

    with caplog.at_level(logging.INFO, logger=LOGGER):
        _override(cors_origins=[NEW_ORIGIN], enable_cors=True)
        assert cors.is_enabled()
        assert cors.build_preflight_response(_preflight()).status_code == 200
        cors.build_response_headers({"origin": NEW_ORIGIN})

    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "may run its own CORS layer" in warnings[0]


def test_a_passed_enable_cors_false_stops_the_cors_of_an_app() -> None:
    config = _cors_config()
    cors = CorsHandler(config)
    app = _app(config)

    _override(enable_cors=False)

    assert not cors.is_enabled()
    assert cors.build_response_headers({"origin": OLD_ORIGIN}) == {}
    assert (
        app.security_headers_manager.get_cors_headers(OLD_ORIGIN, config=config) == {}
    )


def test_the_headers_switch_never_governs_cors() -> None:
    config = _cors_config(security_headers=None)
    app = _app(config)
    request = SyncMockGuardRequest(path="/x", headers={"origin": OLD_ORIGIN})

    response = app.process_response(request, MockGuardResponse("ok", 200), 0.1, None)

    assert response.headers["Access-Control-Allow-Origin"] == OLD_ORIGIN
    assert "X-Frame-Options" not in response.headers

    _override(enabled=False)
    off = app.process_response(request, MockGuardResponse("ok", 200), 0.1, None)
    assert off.headers["Access-Control-Allow-Origin"] == OLD_ORIGIN
    assert "X-Frame-Options" not in off.headers
    assert (
        CorsHandler(config)
        .build_preflight_response(_preflight(OLD_ORIGIN))
        .headers["Access-Control-Allow-Origin"]
        == OLD_ORIGIN
    )


def test_a_wildcard_with_credentials_is_refused_and_the_app_keeps_its_cors(
    caplog: pytest.LogCaptureFixture,
) -> None:
    agent = MagicMock()
    agent.send_event = MagicMock()
    config = _cors_config()
    cors = CorsHandler(config)
    app = _app(config, agent=agent)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        _override(cors_origins=["*"], cors_allow_credentials=True)
        assert cors.build_preflight_response(_preflight(OLD_ORIGIN)).status_code == 200
        assert cors.build_preflight_response(_preflight()).status_code == 400
        app.security_headers_manager.get_cors_headers(OLD_ORIGIN, config=config)
        app.security_headers_manager.get_cors_headers(OLD_ORIGIN, config=config)

    refused = [r for r in caplog.records if "refused" in r.getMessage()]
    assert len(refused) == 1
    assert (
        "wildcard origin cannot be combined with credentials" in refused[0].getMessage()
    )
    events = [
        c.args[0]
        for c in agent.send_event.call_args_list
        if c.args[0].action_taken == "cors_override_refused"
    ]
    assert len(events) == 1
    assert events[0].metadata["reason"].startswith("a wildcard origin")


@pytest.mark.parametrize(
    "bad",
    [
        {"cors_origins": "https://x.example"},
        {"cors_allow_methods": ["GET", 1]},
        {"cors_allow_headers": None},
        {"cors_expose_headers": "X-A"},
        {"enable_cors": "yes"},
        {"cors_allow_credentials": 1},
        {"cors_max_age": -1},
        {"cors_max_age": True},
        {"cors_max_age": "60"},
    ],
)
def test_invalid_cors_keys_raise_in_a_flagged_call_and_change_nothing(
    bad: dict[str, Any],
) -> None:
    before = security_headers_manager.cors_config

    with pytest.raises(ValueError):
        security_headers_manager.configure(override_apps=True, **bad)

    assert override_module.PROCESS_OVERRIDE.record.keys == {}
    assert security_headers_manager.cors_config == before


def test_invalid_cors_keys_are_accepted_by_a_call_without_the_flag() -> None:
    security_headers_manager.configure(cors_max_age=-1)


def test_widening_warns_once_per_app_and_version_and_narrowing_informs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _cors_config()
    cors = CorsHandler(config)

    with caplog.at_level(logging.INFO, logger=LOGGER):
        _override(cors_origins=[OLD_ORIGIN, NEW_ORIGIN])
        for _ in range(3):
            cors.build_response_headers({"origin": NEW_ORIGIN})
        _override(cors_origins=[OLD_ORIGIN], cors_allow_methods=["GET"])
        cors.build_response_headers({"origin": NEW_ORIGIN})

    cors_lines = [r for r in caplog.records if "CORS override" in r.getMessage()]
    assert [r.levelno for r in cors_lines] == [logging.WARNING, logging.INFO]
    assert "widens" in cors_lines[0].getMessage()
    assert "narrows" in cors_lines[1].getMessage()


def test_a_pulled_cors_override_reaches_cors_handler_in_another_worker(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    config = _cors_config()
    app = _app(config, redis=redis)
    _response(app)
    manager = app.security_headers_manager
    redis.store[f"t:security_headers:{manager._override_key()}"] = (
        override_module.OverrideRecord(
            time.time() + 10, {"cors_origins": [NEW_ORIGIN]}
        ).to_json()
    )
    cors = CorsHandler(config)
    assert cors.build_preflight_response(_preflight()).status_code == 400

    clock.now += 5.0
    _response(app)

    assert cors.build_preflight_response(_preflight()).status_code == 200


def test_the_cors_note_registry_forgets_its_oldest_entry_when_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[tuple[int, float], None] = {}
    monkeypatch.setattr(override_module, "MAX_CORS_NOTES", 2)

    assert override_module.first_time(seen, (1, 1.0))
    assert override_module.first_time(seen, (2, 1.0))
    assert not override_module.first_time(seen, (1, 1.0))
    assert override_module.first_time(seen, (3, 1.0))

    assert list(seen) == [(2, 1.0), (3, 1.0)]


def _only(**passed: Any) -> dict[str, Any]:
    blank: dict[str, Any] = {
        name: override_module.NOT_PASSED
        for name in (
            "enabled",
            "csp",
            "hsts_max_age",
            "hsts_include_subdomains",
            "hsts_preload",
            "frame_options",
            "content_type_options",
            "xss_protection",
            "referrer_policy",
            "custom_headers",
        )
    }
    blank["permissions_policy"] = override_module.PERMISSIONS_POLICY_NOT_PASSED
    return override_module.override_from_call(**{**blank, **passed})


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("enable_cors", True),
        ("cors_origins", ["https://a.example"]),
        ("cors_allow_credentials", True),
        ("cors_allow_methods", ["GET"]),
        ("cors_allow_headers", ["X-A"]),
        ("cors_max_age", 30),
        ("cors_expose_headers", ["X-B"]),
    ],
)
def test_each_cors_key_alone_is_recorded_as_the_override(key: str, value: Any) -> None:
    assert _only(**{key: value}) == {key: value}
    assert key in override_module.CORS_OVERRIDE_KEYS


@pytest.mark.parametrize(
    ("key", "bad", "expected"),
    [
        ("cors_origins", "x", "a list of strings"),
        ("cors_allow_methods", [1], "a list of strings"),
        ("cors_allow_headers", None, "a list of strings"),
        ("cors_expose_headers", "x", "a list of strings"),
        ("enable_cors", "yes", "a bool"),
        ("cors_allow_credentials", 1, "a bool"),
        ("cors_max_age", -1, "a non-negative integer"),
        ("cors_max_age", True, "a non-negative integer"),
        ("cors_max_age", 1.5, "a non-negative integer"),
    ],
)
def test_a_bad_cors_override_value_names_the_key_and_the_expected_type(
    key: str, bad: Any, expected: str
) -> None:
    with pytest.raises(ValueError, match=f"^{key} must be {expected}$"):
        override_module.validate_cors_override({key: bad})


def test_cors_max_age_zero_and_one_are_valid() -> None:
    override_module.validate_cors_override({"cors_max_age": 0})
    override_module.validate_cors_override({"cors_max_age": 1})


def test_cors_params_of_reads_every_list_from_the_config() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_cors=True,
        cors_allow_origins=["https://a.example"],
        cors_allow_methods=["GET"],
        cors_allow_headers=["X-A"],
        cors_expose_headers=["X-B"],
        cors_allow_credentials=True,
        cors_max_age=7,
    )

    assert override_module.cors_params_of(config) == override_module.CorsParams(
        enabled=True,
        origins=("https://a.example",),
        credentials=True,
        methods=("GET",),
        headers=("X-A",),
        max_age=7,
        expose=("X-B",),
    )


def test_merge_cors_without_a_cors_key_returns_the_base_itself() -> None:
    base = override_module.cors_params_of(SecurityConfig(enable_redis=False))

    merged, refused = override_module.merge_cors(base, {"frame_options": "DENY"})

    assert merged is base
    assert refused is None


def test_merge_cors_applies_headers_and_the_other_passed_keys() -> None:
    base = override_module.cors_params_of(SecurityConfig(enable_redis=False))

    merged, refused = override_module.merge_cors(
        base,
        {
            "cors_allow_headers": ["X-A"],
            "cors_expose_headers": ["X-B"],
            "cors_max_age": 9,
        },
    )

    assert refused is None
    assert merged.headers == ("X-A",)
    assert merged.expose == ("X-B",)
    assert merged.max_age == 9


def test_switching_credentials_on_alone_widens_the_cors() -> None:
    config = SecurityConfig(
        enable_redis=False, enable_cors=True, cors_allow_origins=["https://a.example"]
    )
    base = override_module.cors_params_of(config)
    merged, _ = override_module.merge_cors(base, {"cors_allow_credentials": True})

    assert override_module.cors_widens(base, merged)
    assert not override_module.cors_widens(merged, merged)


def test_the_override_record_and_cors_params_are_immutable() -> None:
    record = override_module.OverrideRecord(1.0, {})
    params = override_module.cors_params_of(SecurityConfig(enable_redis=False))

    with pytest.raises(dataclasses.FrozenInstanceError):
        record.__setattr__("set_at", 2.0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        params.__setattr__("enabled", True)


def test_a_record_equals_another_with_the_same_stamp_and_keys_whatever_its_event() -> (
    None
):
    plain = override_module.OverrideRecord(1.0, {"a": 1})

    assert plain.event is None
    assert plain == override_module.OverrideRecord(1.0, {"a": 1}, {"x": 1})


def test_a_fresh_process_override_starts_empty_at_epoch_and_offset_zero() -> None:
    fresh = override_module._ProcessOverride()

    assert fresh.record == override_module.OverrideRecord(0.0, {})
    assert fresh.reset_epoch == 0
    assert fresh.clock_offset == 0.0


def test_a_record_stamped_exactly_one_day_ahead_is_kept_and_later_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(override_module, "approximate_now", lambda: 1000.0)
    monkeypatch.setattr(override_module.PROCESS_OVERRIDE, "clock_offset", 0.0)
    day = 86400.0

    assert override_module.OverrideRecord(1000.0 + day, {}).ordered_at() == 1000.0 + day
    assert override_module.OverrideRecord(1000.0 + day + 0.5, {}).ordered_at() == 0.0


def test_the_cors_note_registry_holds_exactly_its_limit_with_the_real_constant() -> (
    None
):
    seen: dict[tuple[int, float], None] = {}
    limit = override_module.MAX_CORS_NOTES

    for number in range(limit + 1):
        assert override_module.first_time(seen, (number, 1.0))

    assert len(seen) == limit
    assert (0, 1.0) not in seen
    assert all(value is None for value in seen.values())


def test_the_cache_key_of_a_config_keeps_its_headers_and_adds_the_override() -> None:
    manager = SecurityHeadersManager.isolated()
    first = SecurityConfig(
        enable_redis=False, security_headers={"frame_options": "DENY"}
    )
    second = SecurityConfig(
        enable_redis=False, security_headers={"frame_options": "SAMEORIGIN"}
    )
    record = override_module.OverrideRecord(1.0, {"frame_options": "DENY"})

    plain = manager._generate_cache_key(
        None, first, override_module.OverrideRecord(0.0, {})
    )
    with_override = manager._generate_cache_key(None, first, record)

    assert plain.startswith("cfg_")
    assert with_override.startswith("cfg_")
    assert with_override != plain
    assert manager._generate_cache_key(None, second, record) != with_override


def test_the_pull_is_one_plain_pipeline_that_reads_the_three_own_state_keys(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    config = _config()
    security_headers_manager.initialize_redis(redis, config)
    app = _app(config, redis=redis)
    _response(app)
    redis.get_keys.clear()
    redis.pipeline_options.clear()

    clock.now += 5.0
    _response(app)

    own = [k for k in redis.get_keys if not k.startswith("t:security_headers:override")]
    assert own == [
        "t:security_headers:csp_config",
        "t:security_headers:hsts_config",
        "t:security_headers:custom_headers",
    ]
    assert redis.pipeline_options == [{"transaction": False}]


def test_the_clock_offset_counts_the_microseconds_of_redis_time(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    redis = FakeRedis()
    redis.time_value = (100, 500_000)
    monkeypatch.setattr(override_module, "wall_now", lambda: 100.0)
    app = _app(redis=redis)

    _response(app)

    assert override_module.PROCESS_OVERRIDE.clock_offset == pytest.approx(0.5, abs=1e-8)


def test_own_state_work_does_nothing_without_a_global_manager(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(SecurityHeadersManager, "_instance", None)
    manager = SecurityHeadersManager.isolated()

    manager._flush_own_state()

    assert manager._global_sharing_state() is None


def test_an_unreadable_shared_own_state_is_logged_and_ignored(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager.isolated()
    shared = MagicMock()
    shared._apply_own_state.side_effect = ValueError("boom")

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        manager._apply_shared_own_state(shared, ["a", "b", "c"])

    assert [r.getMessage() for r in caplog.records] == [
        "Ignoring unreadable cached header config in Redis: boom"
    ]


def test_the_reader_override_is_the_pulled_one_only_when_it_orders_later() -> None:
    manager = SecurityHeadersManager.isolated()
    first = _config()
    second = _config(frame_options="SAMEORIGIN")
    now = time.time()
    older = override_module.OverrideRecord(now, {"frame_options": "A"})
    newer = override_module.OverrideRecord(now + 1, {"frame_options": "B"})
    PULLED_OVERRIDES[override_module.config_fingerprint(first)] = older
    PULLED_OVERRIDES[override_module.config_fingerprint(second)] = newer
    try:
        assert manager.override_for_reader(first) is older
        assert manager.override_for_reader(second) is newer
        current = override_module.OverrideRecord(now + 1, {"frame_options": "C"})
        assert manager.override_for_reader(second, current) is current
    finally:
        PULLED_OVERRIDES.clear()


def test_the_cors_override_log_lines_have_the_documented_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    on = CorsHandler(_cors_config())
    off = CorsHandler(_config())

    with caplog.at_level(logging.INFO, logger=LOGGER):
        _override(enable_cors=True, cors_origins=[OLD_ORIGIN, NEW_ORIGIN])
        on.build_response_headers({"origin": NEW_ORIGIN})
        _override(enable_cors=True, cors_origins=[])
        off.build_response_headers({"origin": NEW_ORIGIN})
        _override(cors_origins=[OLD_ORIGIN])
        on.build_response_headers({"origin": OLD_ORIGIN})
        _override(cors_origins=["*"], cors_allow_credentials=True)
        on.build_response_headers({"origin": OLD_ORIGIN})

    lines = [
        r.getMessage() for r in caplog.records if "CORS override" in r.getMessage()
    ]
    assert lines == [
        "CORS override widens the CORS of this app: enabled=True, "
        f"origins={OLD_ORIGIN}, {NEW_ORIGIN}, credentials=False",
        "CORS override widens the CORS of this app: enabled=True, origins=none, "
        "credentials=False; the app was built without CORS and may run its own "
        "CORS layer",
        "CORS override narrows or keeps the CORS of this app",
        "CORS override refused for this app, it keeps its own CORS: a wildcard "
        "origin cannot be combined with credentials",
    ]


def test_the_refusal_event_is_sent_once_per_app_and_version() -> None:
    agent = MagicMock()
    agent.send_event = MagicMock()
    config = _cors_config()
    app = _app(config, agent=agent)
    _override(cors_origins=["*"], cors_allow_credentials=True)

    for _ in range(3):
        app.security_headers_manager.send_cors_override_event(config)

    events = [
        c.args[0]
        for c in agent.send_event.call_args_list
        if c.args[0].action_taken == "cors_override_refused"
    ]
    assert len(events) == 1
    assert events[0].metadata["override_keys"] == [
        "cors_allow_credentials",
        "cors_origins",
    ]


def test_reset_advances_the_epoch_by_one_and_orders_after_the_old_override() -> None:
    manager = security_headers_manager
    _override(csp=GLOBAL_CSP)
    before = override_module.PROCESS_OVERRIDE.reset_epoch
    old = manager.resolve_override().ordered_at()

    manager.reset()

    assert override_module.PROCESS_OVERRIDE.reset_epoch == before + 1
    assert manager._override.ordered_at() > old


def test_the_next_set_time_is_exactly_one_microsecond_after_the_current_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = SecurityHeadersManager.isolated()
    manager._override = override_module.OverrideRecord(time.time() + 50, {})
    monkeypatch.setattr(override_module, "corrected_wall_now", lambda: 0.0)
    monkeypatch.setattr(f"{CLOCK_MODULE}.corrected_wall_now", lambda: 0.0)

    assert manager._next_set_at() - manager._override.set_at == pytest.approx(
        1e-6, abs=3e-7
    )


def test_a_cleared_override_in_redis_is_adopted_into_the_process_cache(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    config = _config()
    app = _app(config, redis=redis)
    _override(csp=GLOBAL_CSP)
    _response(app)
    manager = app.security_headers_manager
    assert _in_redis(manager)
    redis.store.clear()

    clock.now += 5.0
    _response(app)

    cached = PULLED_OVERRIDES[str(_hash_of(manager))]
    assert isinstance(cached, override_module.OverrideRecord)
    assert cached.keys == {}


@pytest.mark.parametrize(
    ("startup_hash", "handler", "dirty"),
    [("abc", None, False), (None, FakeRedis(), False), ("abc", FakeRedis(), True)],
)
def test_a_configure_marks_the_own_state_dirty_only_when_bound_to_redis(
    startup_hash: str | None, handler: Any, dirty: bool
) -> None:
    manager = SecurityHeadersManager.isolated()
    manager._startup_hash = startup_hash
    manager.redis_handler = handler

    manager.configure(csp=GLOBAL_CSP)

    assert manager._own_state_dirty is dirty


def test_resetting_an_app_manager_clears_its_state_and_its_process_cache_entry() -> (
    None
):
    manager = SecurityHeadersManager.isolated()
    manager._startup_hash = "abc"
    manager._redis_initialized = True
    manager._own_state_dirty = True
    manager._override_in_redis = True
    manager._override_next_lookup = 99.0
    manager._override_next_pull = 99.0
    PULLED_OVERRIDES["abc"] = override_module.OverrideRecord(time.time(), {"a": 1})
    before = manager._override.ordered_at()

    manager._reset_override()

    assert "abc" not in PULLED_OVERRIDES
    assert _hash_of(manager) is None
    assert vars(manager)["_redis_initialized"] is False
    assert vars(manager)["_own_state_dirty"] is False
    assert vars(manager)["_override_in_redis"] is False
    assert vars(manager)["_override_next_lookup"] == 0.0
    assert vars(manager)["_override_next_pull"] == 0.0
    assert manager._override.keys == {}
    assert manager._override.set_at == pytest.approx(before + 1e-6, abs=1e-9)
    assert manager._override_epoch == override_module.PROCESS_OVERRIDE.reset_epoch


def test_an_override_pulled_after_a_global_reset_stays_applied(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    config = _config()
    app = _app(config, redis=redis)
    _response(app)
    security_headers_manager.reset()
    redis.store[
        f"t:security_headers:override:{_hash_of(app.security_headers_manager)}"
    ] = override_module.OverrideRecord(
        time.time() + 10, {"frame_options": "SAMEORIGIN"}
    ).to_json()
    clock.now += 5.0

    first = _response(app)
    second = _response(app)

    assert first["X-Frame-Options"] == "SAMEORIGIN"
    assert second["X-Frame-Options"] == "SAMEORIGIN"


def test_a_new_epoch_clears_the_override_just_after_the_one_it_saved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = SecurityHeadersManager.isolated()
    manager._override_saved_at = 5.0
    monkeypatch.setattr(
        override_module.PROCESS_OVERRIDE,
        "reset_epoch",
        override_module.PROCESS_OVERRIDE.reset_epoch + 1,
    )

    cleared = manager.resolve_override()

    assert cleared.keys == {}
    assert cleared.set_at == pytest.approx(5.0 + 1e-6, abs=1e-9)
