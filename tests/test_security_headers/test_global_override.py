import json
import logging
import re
import time
from collections.abc import Callable, Iterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core import _security_headers_override as override_module
from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardResponse, MockGuardResponseFactory

LOGGER = "guard_core.handlers.security_headers"
APP_CSP = {"default-src": ["'self'", "https://app.example"]}
GLOBAL_CSP = {"default-src": ["'self'", "https://global.example"]}
OTHER_CSP = {"default-src": ["'none'"]}
CLOCK_MODULE = "guard_core.handlers._security_headers_override_state"


class FakeRedis:
    def __init__(self, prefix: str = "t:") -> None:
        self.config = MagicMock(redis_prefix=prefix)
        self.store: dict[str, Any] = {}
        self.ttls: dict[str, int | None] = {}
        self.gets = 0
        self.sets = 0
        self.down = False

    async def get_key(self, namespace: str, key: str) -> Any:
        self.gets += 1
        if self.down:
            raise ConnectionError("redis is down")
        return self.store.get(f"{self.config.redis_prefix}{namespace}:{key}")

    async def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool:
        self.sets += 1
        if self.down:
            raise ConnectionError("redis is down")
        full = f"{self.config.redis_prefix}{namespace}:{key}"
        self.store[full] = value
        self.ttls[full] = ttl
        return True

    @asynccontextmanager
    async def get_connection(self) -> Any:
        if self.down:
            raise ConnectionError("redis is down")
        store = self.store

        class Conn:
            async def keys(self, pattern: str) -> list[str]:
                prefix = pattern.rstrip("*")
                return [key for key in store if key.startswith(prefix)]

            async def delete(self, *keys: str) -> None:
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
    metrics.collect_request_metrics = AsyncMock()
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


def _override_events(agent: Any) -> list[Any]:
    events = [call.args[0] for call in agent.send_event.call_args_list]
    return [e for e in events if e.action_taken.startswith("override_")]


async def _response(app: ErrorResponseFactory, path: str = "/x") -> dict[str, str]:
    response = await app.apply_security_headers(MockGuardResponse("ok", 200), path)
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


async def test_the_global_call_changes_the_csp_of_a_guarded_app() -> None:
    app = _app()
    assert (await _response(app))["Content-Security-Policy"].endswith("app.example")

    security_headers_manager.configure(csp=GLOBAL_CSP)

    after = await _response(app)
    assert (
        after["Content-Security-Policy"] == "default-src 'self' https://global.example"
    )


async def test_a_path_never_requested_gets_the_override_too() -> None:
    app = _app()
    await _response(app, "/seen")

    security_headers_manager.configure(csp=GLOBAL_CSP)

    assert (await _response(app, "/never-seen"))["Content-Security-Policy"].endswith(
        "global.example"
    )


async def test_keys_the_call_did_not_pass_keep_the_value_of_the_app() -> None:
    app = _app()

    security_headers_manager.configure(csp=GLOBAL_CSP)

    after = await _response(app)
    assert after["X-Frame-Options"] == "DENY"
    assert after["Referrer-Policy"] == "no-referrer"
    assert after["X-Content-Type-Options"] == "nosniff"


async def test_the_override_reaches_every_app_in_the_process() -> None:
    first, second = _app(), _app(_config(frame_options="SAMEORIGIN"))

    security_headers_manager.configure(frame_options="DENY")

    assert (await _response(first))["X-Frame-Options"] == "DENY"
    assert (await _response(second))["X-Frame-Options"] == "DENY"


async def test_an_app_created_after_the_call_gets_the_override() -> None:
    security_headers_manager.configure(csp=GLOBAL_CSP)

    assert (await _response(_app()))["Content-Security-Policy"].endswith(
        "global.example"
    )


async def test_nobody_calling_configure_leaves_every_app_alone() -> None:
    first = _app()
    second = _app(_config(csp=OTHER_CSP))

    assert (await _response(first))["Content-Security-Policy"].endswith("app.example")
    assert (await _response(second))["Content-Security-Policy"] == "default-src 'none'"


async def test_the_managers_own_headers_keep_the_full_replace() -> None:
    security_headers_manager.configure(csp=GLOBAL_CSP, frame_options="DENY")
    security_headers_manager.configure(csp=GLOBAL_CSP)

    headers = await security_headers_manager.get_headers()

    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert "Content-Security-Policy" in headers


async def test_hsts_sub_keys_merge_over_the_hsts_of_the_app() -> None:
    app = _app()

    security_headers_manager.configure(hsts_max_age=100)

    assert (await _response(app))["Strict-Transport-Security"] == (
        "max-age=100; includeSubDomains"
    )


async def test_the_call_can_switch_a_header_off_for_every_app() -> None:
    app = _app()

    security_headers_manager.configure(frame_options=None)

    assert "X-Frame-Options" not in await _response(app)


async def test_an_app_with_headers_off_stays_off() -> None:
    app = _app(SecurityConfig(enable_redis=False, security_headers=None))

    security_headers_manager.configure(csp=GLOBAL_CSP)

    assert "Content-Security-Policy" not in await _response(app)


async def test_enabled_false_in_a_call_switches_every_app_off() -> None:
    app = _app()

    security_headers_manager.configure(enabled=False)

    assert await _response(app) == {}


async def test_a_second_call_that_omits_a_key_drops_it_with_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app()
    security_headers_manager.configure(csp=GLOBAL_CSP, frame_options="SAMEORIGIN")
    assert (await _response(app))["X-Frame-Options"] == "SAMEORIGIN"

    with caplog.at_level(logging.INFO, logger=LOGGER):
        security_headers_manager.configure(csp=OTHER_CSP)

    after = await _response(app)
    assert after["X-Frame-Options"] == "DENY"
    assert after["Content-Security-Policy"] == "default-src 'none'"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    dropped = re.search(r"dropped keys: ([^;]*);", warnings[0].getMessage())
    assert dropped is not None
    assert dropped.group(1) == "frame_options"


async def test_a_bare_call_clears_the_override_with_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app()
    security_headers_manager.configure(csp=GLOBAL_CSP, frame_options="SAMEORIGIN")

    with caplog.at_level(logging.INFO, logger=LOGGER):
        security_headers_manager.configure()

    after = await _response(app)
    assert after["Content-Security-Policy"].endswith("app.example")
    assert after["X-Frame-Options"] == "DENY"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "csp" in message
    assert "frame_options" in message


async def test_a_bare_call_with_nothing_to_clear_logs_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        security_headers_manager.configure()

    assert caplog.records == []


async def test_every_call_that_changes_the_override_logs_one_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger=LOGGER):
        security_headers_manager.configure(csp=GLOBAL_CSP)
        security_headers_manager.configure(csp=GLOBAL_CSP)

    assert [r.levelno for r in caplog.records] == [logging.INFO]


async def test_reset_clears_the_override_in_the_process() -> None:
    app = _app()
    security_headers_manager.configure(csp=GLOBAL_CSP)

    await security_headers_manager.reset()

    assert (await _response(app))["Content-Security-Policy"].endswith("app.example")


async def test_values_are_redacted_in_the_log_and_the_event(
    caplog: pytest.LogCaptureFixture,
) -> None:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    app = _app(agent=agent)

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        security_headers_manager.configure(
            custom_headers={"X-Auth-Token": "SEKRET-VALUE", "X-Build": "build-7"}
        )
    await _response(app)

    assert "SEKRET-VALUE" not in caplog.text
    assert "X-Auth-Token" in caplog.text
    agent.send_event.assert_awaited()
    event = _override_events(agent)[-1]
    assert "SEKRET-VALUE" not in json.dumps(event.metadata)
    assert event.metadata["override_keys"] == ["custom"]
    assert event.metadata["dropped_keys"] == []


async def test_the_event_lists_the_dropped_keys_with_redacted_values() -> None:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    app = _app(agent=agent)
    security_headers_manager.configure(
        csp=GLOBAL_CSP, custom_headers={"X-Auth-Token": "SEKRET-VALUE"}
    )
    await _response(app)

    security_headers_manager.configure(csp=GLOBAL_CSP)
    await _response(app)

    event = _override_events(agent)[-1]
    assert event.metadata["dropped_keys"] == ["custom"]
    assert "SEKRET-VALUE" not in json.dumps(event.metadata)


async def test_no_override_means_no_redis_traffic_beyond_the_pull(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)

    for _ in range(20):
        await _response(app)
    assert (redis.gets, redis.sets) == (1, 0)

    clock.now += 5.0
    await _response(app)
    assert (redis.gets, redis.sets) == (2, 0)


async def test_the_call_is_saved_without_a_ttl_under_the_prefix_and_config_hash(
    clock: Clock,
) -> None:
    redis = FakeRedis("svc:")
    app = _app(redis=redis)
    security_headers_manager.configure(csp=GLOBAL_CSP)

    await _response(app)

    keys = [key for key in redis.store if key.startswith("svc:security_headers:")]
    assert len(keys) == 1
    assert redis.ttls[keys[0]] is None
    assert json.loads(redis.store[keys[0]])["keys"] == {"csp": GLOBAL_CSP}


async def test_a_second_worker_applies_the_override_within_five_seconds(
    clock: Clock, other_worker: Callable[[], Any]
) -> None:
    redis = FakeRedis()
    worker_a = _app(redis=redis)
    worker_b = _app(redis=redis)
    with other_worker():
        assert (await _response(worker_b))["Content-Security-Policy"].endswith(
            "app.example"
        )
    security_headers_manager.configure(csp=GLOBAL_CSP)
    await _response(worker_a)

    clock.now += 4.9
    with other_worker():
        assert (await _response(worker_b))["Content-Security-Policy"].endswith(
            "app.example"
        )
        clock.now += 0.2
        assert (await _response(worker_b))["Content-Security-Policy"].endswith(
            "global.example"
        )


async def test_a_worker_started_with_another_config_ignores_the_override(
    clock: Clock, other_worker: Callable[[], Any]
) -> None:
    redis = FakeRedis()
    worker_a = _app(redis=redis)
    worker_b = _app(_config(frame_options="SAMEORIGIN"), redis=redis)
    security_headers_manager.configure(csp=GLOBAL_CSP)
    await _response(worker_a)

    clock.now += 10.0
    with other_worker():
        assert (await _response(worker_b))["Content-Security-Policy"].endswith(
            "app.example"
        )


async def test_redis_down_keeps_the_last_applied_override(
    clock: Clock, other_worker: Callable[[], Any]
) -> None:
    redis = FakeRedis()
    worker_a = _app(redis=redis)
    worker_b = _app(redis=redis)
    security_headers_manager.configure(csp=GLOBAL_CSP)
    await _response(worker_a)
    with other_worker():
        clock.now += 10.0
        assert (await _response(worker_b))["Content-Security-Policy"].endswith(
            "global.example"
        )

        redis.down = True
        clock.now += 10.0
        assert (await _response(worker_b))["Content-Security-Policy"].endswith(
            "global.example"
        )


async def test_reset_clears_the_override_in_redis_and_other_workers_follow(
    clock: Clock, other_worker: Callable[[], Any]
) -> None:
    redis = FakeRedis()
    worker_a = _app(redis=redis)
    worker_b = _app(redis=redis)
    security_headers_manager.configure(csp=GLOBAL_CSP)
    await _response(worker_a)
    with other_worker():
        clock.now += 10.0
        await _response(worker_b)

    security_headers_manager.redis_handler = redis
    await security_headers_manager.reset()

    assert [key for key in redis.store if "security_headers" in key] == []
    with other_worker():
        clock.now += 10.0
        assert (await _response(worker_b))["Content-Security-Policy"].endswith(
            "app.example"
        )


async def test_a_bare_call_deletes_the_saved_override(clock: Clock) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    security_headers_manager.configure(csp=GLOBAL_CSP)
    await _response(app)
    assert redis.store

    security_headers_manager.configure()
    await _response(app)

    assert redis.store == {}


async def test_the_factory_hands_the_context_redis_to_its_manager() -> None:
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
    SecurityHeadersManager.isolated().configure(csp=GLOBAL_CSP)

    assert override_module.PROCESS_OVERRIDE.record.keys == {}


async def test_a_failed_save_is_retried_after_five_seconds(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis()
    redis.down = True
    app = _app(redis=redis)
    security_headers_manager.configure(csp=GLOBAL_CSP)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        await _response(app)
        await _response(app)
    assert redis.sets == 1
    assert "Failed to save the security headers override" in caplog.text

    redis.down = False
    clock.now += 5.0
    await _response(app)
    assert redis.sets == 2
    assert len(redis.store) == 1


async def test_a_failed_pull_is_logged_and_retried_after_five_seconds(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis()
    redis.down = True
    app = _app(redis=redis)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        await _response(app)
        await _response(app)
    assert redis.gets == 1
    assert "keeping the last applied one" in caplog.text


async def test_an_unreadable_override_in_redis_is_ignored_with_a_warning(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    await _response(app)
    key = f"t:security_headers:{app.security_headers_manager._override_key()}"
    redis.store[key] = "not json"

    clock.now += 5.0
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        headers = await _response(app)

    assert headers["Content-Security-Policy"].endswith("app.example")
    assert "unreadable security headers override" in caplog.text


async def test_a_pulled_override_older_than_the_local_one_is_ignored(
    clock: Clock, other_worker: Callable[[], Any]
) -> None:
    redis = FakeRedis()
    app = _app(redis=redis)
    security_headers_manager.configure(csp=GLOBAL_CSP)
    await _response(app)
    manager = app.security_headers_manager
    stale = override_module.OverrideRecord(1.0, {"csp": OTHER_CSP})
    redis.store[f"t:security_headers:{manager._override_key()}"] = stale.to_json()

    clock.now += 5.0
    headers = await _response(app)

    assert headers["Content-Security-Policy"].endswith("global.example")


async def test_a_failing_agent_does_not_break_the_response() -> None:
    agent = MagicMock()
    agent.send_event = AsyncMock(side_effect=RuntimeError("agent down"))
    app = _app(agent=agent)
    security_headers_manager.configure(csp=GLOBAL_CSP)

    assert (await _response(app))["Content-Security-Policy"].endswith("global.example")


async def test_an_app_without_an_agent_still_applies_the_override() -> None:
    app = _app()
    security_headers_manager.configure(csp=GLOBAL_CSP)

    assert (await _response(app))["Content-Security-Policy"].endswith("global.example")


async def test_changing_a_value_of_the_same_keys_is_an_info_not_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    security_headers_manager.configure(csp=GLOBAL_CSP)

    with caplog.at_level(logging.INFO, logger=LOGGER):
        security_headers_manager.configure(csp=OTHER_CSP)

    assert [r.levelno for r in caplog.records] == [logging.INFO]


def test_resolve_headers_applies_the_override_and_the_off_switch() -> None:
    manager = SecurityHeadersManager.isolated()
    config = _config()

    security_headers_manager.configure(frame_options="SAMEORIGIN")
    assert manager.resolve_headers(config)["X-Frame-Options"] == "SAMEORIGIN"

    security_headers_manager.configure(enabled=False)
    assert manager.resolve_headers(config) == {}


async def test_resetting_another_manager_leaves_the_process_override() -> None:
    app = _app()
    security_headers_manager.configure(csp=GLOBAL_CSP)

    await SecurityHeadersManager.isolated().reset()

    assert (await _response(app))["Content-Security-Policy"].endswith("global.example")


async def test_an_empty_override_never_touches_a_redis_it_never_wrote(
    clock: Clock,
) -> None:
    redis = FakeRedis()
    await security_headers_manager.reset()
    app = _app(redis=redis)

    await _response(app)

    assert redis.sets == 0
