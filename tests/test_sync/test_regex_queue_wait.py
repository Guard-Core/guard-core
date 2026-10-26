import concurrent.futures
import logging
import re
import threading
import time
from collections.abc import Callable, Generator, Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.exceptions import BodyReadFailedError
from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.core.events.event_types import EVENT_SUSPICIOUS_REQUEST
from guard_core.sync.detection_engine import compiler as compiler_module
from guard_core.sync.handlers.suspatterns_handler import (
    _CTX_ALL,
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

CLIENT = "203.0.113.9"
_HARMLESS_CUSTOM_ROW = r"zzz_queue_wait_probe_zzz"
_CATASTROPHIC_CUSTOM_ROW = r"(a+)+$"
_COMPILER_TIMEOUT = 0.3


def _config(**overrides: Any) -> SyncSecurityConfig:
    settings: dict[str, Any] = {"fail_secure": True, **overrides}
    return SyncSecurityConfig(
        detection_compiler_timeout=_COMPILER_TIMEOUT, enable_redis=False, **settings
    )


@pytest.fixture
def custom_rows() -> Generator[SyncSecurityConfig, None]:
    config = _config()
    sus_patterns_handler.configure(config)
    sus_patterns_handler.add_pattern(_HARMLESS_CUSTOM_ROW, custom=True)
    catastrophic_row = (re.compile(_CATASTROPHIC_CUSTOM_ROW), _CTX_ALL, "custom")
    sus_patterns_handler.compiled_custom_patterns.add(catastrophic_row)
    yield config
    sus_patterns_handler.remove_pattern(_HARMLESS_CUSTOM_ROW, custom=True)
    sus_patterns_handler.compiled_custom_patterns.discard(catastrophic_row)
    sus_patterns_handler.configure(SyncSecurityConfig())


@pytest.fixture
def saturated_regex_pool(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Every worker of a private pool is held busy, so a scan only queues."""
    workers = compiler_module._SHARED_EXECUTOR_MAX_WORKERS
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    monkeypatch.setattr(compiler_module, "_shared_executor", pool)
    release = threading.Event()
    all_running = threading.Barrier(workers + 1)

    def hold() -> None:
        all_running.wait(10)
        release.wait(30)

    for _ in range(workers):
        pool.submit(hold)
    all_running.wait(10)
    yield
    release.set()
    pool.shutdown(wait=True)


@pytest.fixture
def fresh_regex_pool(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    pool = concurrent.futures.ThreadPoolExecutor(
        max_workers=compiler_module._SHARED_EXECUTOR_MAX_WORKERS
    )
    monkeypatch.setattr(compiler_module, "_shared_executor", pool)
    yield
    pool.shutdown(wait=False, cancel_futures=True)


def _check(
    config: SyncSecurityConfig | None = None,
) -> tuple[SuspiciousActivityCheck, MagicMock]:
    middleware = MagicMock()
    middleware.config = config or _config()
    middleware.logger = logging.getLogger("test_regex_queue_wait")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    middleware.ip_ban_manager = MagicMock()
    return SuspiciousActivityCheck(middleware), middleware


def _request(value: str) -> SyncMockGuardRequest:
    request = SyncMockGuardRequest(path="/api", query_params={"q": value})
    request.state.client_ip = CLIENT
    request.state.route_config = None
    return request


@pytest.mark.usefixtures("saturated_regex_pool")
def test_a_harmless_value_that_only_queued_is_an_incomplete_scan(
    custom_rows: SyncSecurityConfig,
) -> None:
    result = detect_penetration_attempt(_request("hello"), custom_rows)

    assert result.is_threat is False
    assert result.body_read_error == "failed"
    assert "no regex worker took the scan" in result.body_read_detail


@pytest.mark.usefixtures("saturated_regex_pool")
def test_a_queue_wait_answers_400_with_an_event_and_no_strike(
    custom_rows: SyncSecurityConfig,
) -> None:
    check, middleware = _check()

    response = check.check(_request("hello"))

    assert response is not None
    assert response.status_code == 400
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["event_type"] == EVENT_SUSPICIOUS_REQUEST
    assert event["action_taken"] == "request_blocked"
    assert middleware.suspicious_request_counts == {}


@pytest.mark.usefixtures("saturated_regex_pool")
def test_queue_waits_never_ban_a_client_on_the_default_threshold(
    custom_rows: SyncSecurityConfig,
) -> None:
    check, middleware = _check()
    attempts = SyncSecurityConfig().auto_ban_threshold + 2

    statuses = []
    for _ in range(attempts):
        response = check.check(_request("hello"))
        assert response is not None
        statuses.append(response.status_code)

    assert statuses == [400] * attempts
    assert middleware.ip_ban_manager.ban_ip.call_count == 0
    assert middleware.suspicious_request_counts == {}


@pytest.mark.usefixtures("saturated_regex_pool")
def test_a_queue_wait_with_fail_secure_off_passes_with_an_event(
    custom_rows: SyncSecurityConfig,
) -> None:
    check, middleware = _check(_config(fail_secure=False))

    response = check.check(_request("hello"))

    assert response is None
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["action_taken"] == "logged_only"
    assert middleware.suspicious_request_counts == {}


@pytest.mark.usefixtures("fresh_regex_pool")
def test_a_harmless_value_on_a_free_pool_is_clean(
    custom_rows: SyncSecurityConfig,
) -> None:
    result = detect_penetration_attempt(_request("hello"), custom_rows)

    assert result.is_threat is False
    assert result.body_read_error is None


@pytest.mark.usefixtures("fresh_regex_pool")
def test_a_pattern_that_really_runs_past_its_budget_is_still_a_timeout(
    custom_rows: SyncSecurityConfig,
) -> None:
    check, middleware = _check()
    value = "a" * 24 + "!"

    result = detect_penetration_attempt(_request(value), custom_rows)
    response = check.check(_request(value))

    assert result.is_threat is True
    assert result.body_read_error is None
    assert "Pattern exceeded scan time budget" in result.trigger_info
    assert response is not None
    assert response.status_code == 400
    assert middleware.suspicious_request_counts != {}


@pytest.fixture
def isolated_manager() -> Iterator[SusPatternsManager]:
    SusPatternsManager._instance = None
    yield SusPatternsManager(_config())
    SusPatternsManager._instance = None


@pytest.mark.usefixtures("saturated_regex_pool")
def test_the_compiler_path_ends_a_scan_that_only_queued(
    isolated_manager: SusPatternsManager,
) -> None:
    assert isolated_manager._compiler is not None

    with pytest.raises(BodyReadFailedError, match="no regex worker took the scan"):
        isolated_manager._check_regex_pattern(
            re.compile("evil"), "so evil", CLIENT, time.monotonic(), "custom"
        )


@pytest.mark.usefixtures("saturated_regex_pool")
def test_the_legacy_path_ends_a_scan_that_only_queued(
    isolated_manager: SusPatternsManager,
) -> None:
    isolated_manager._compiler = None

    with pytest.raises(BodyReadFailedError, match="no regex worker took the scan"):
        isolated_manager._check_pattern_with_timeout(
            re.compile("evil"), "so evil", CLIENT, time.monotonic()
        )


@pytest.mark.usefixtures("saturated_regex_pool")
def test_the_windowed_path_ends_a_scan_that_only_queued(
    isolated_manager: SusPatternsManager,
) -> None:
    with pytest.raises(BodyReadFailedError, match="no regex worker took the scan"):
        isolated_manager._check_windowed_pattern(
            re.compile("evil"),
            lambda content: iter(()),
            "so evil",
            time.monotonic(),
            "custom",
            "unknown",
        )


@pytest.mark.usefixtures("saturated_regex_pool")
def test_the_finditer_matcher_reports_a_queue_wait_and_no_matches() -> None:
    outcome: list[str] = []
    compiler = compiler_module.PatternCompiler(default_timeout=0.2)
    matcher = compiler.create_safe_finditer_matcher(re.compile("evil"), outcome=outcome)

    assert matcher("so evil") == []
    assert outcome == [compiler_module.SCAN_OUTCOME_QUEUE_WAIT]


@pytest.mark.usefixtures("fresh_regex_pool")
def test_the_finditer_matcher_reports_a_run_that_used_its_budget_without_a_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome: list[str] = []
    compiler = compiler_module.PatternCompiler(default_timeout=0.2)

    def slow(work: Callable[[], Any]) -> Callable[[], Any]:
        def run() -> Any:
            time.sleep(0.25)
            return work()

        return run

    def wait_without_bound(
        future: concurrent.futures.Future[Any], started: object, timeout: float
    ) -> Any:
        return future.result()

    matcher = compiler.create_safe_finditer_matcher(
        re.compile("zzz"), worker_wrapper=slow, outcome=outcome
    )
    monkeypatch.setattr(compiler_module, "wait_for_regex_run", wait_without_bound)

    assert matcher("so evil") == []
    assert outcome == [compiler_module.SCAN_OUTCOME_RUN_TIMEOUT]


def test_a_worker_that_started_after_the_queue_bound_still_gets_its_run_budget() -> (
    None
):
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    release = threading.Event()
    running = pool.submit(release.wait, 30)
    never_marked: list[float] = []
    try:
        with pytest.raises(concurrent.futures.TimeoutError):
            compiler_module.wait_for_regex_run(running, never_marked, 0.05)
    finally:
        release.set()
        pool.shutdown(wait=True)


def test_the_async_wait_gives_a_late_started_worker_its_run_budget() -> None:
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    release = threading.Event()
    running = pool.submit(release.wait, 30)
    never_marked: list[float] = []
    try:
        with pytest.raises(concurrent.futures.TimeoutError):
            compiler_module._await_regex_future(running, never_marked, 0.05)
    finally:
        release.set()
        pool.shutdown(wait=True)


def test_a_futures_own_timeout_is_a_run_timeout_not_a_queue_wait() -> None:
    future: concurrent.futures.Future[Any] = concurrent.futures.Future()
    future.set_exception(concurrent.futures.TimeoutError())

    with pytest.raises(concurrent.futures.TimeoutError):
        compiler_module.wait_for_regex_run(future, [], 0.05)


def test_the_async_wait_reports_a_futures_own_timeout_as_a_run_timeout() -> None:
    future: concurrent.futures.Future[Any] = concurrent.futures.Future()
    future.set_exception(concurrent.futures.TimeoutError())

    with pytest.raises(concurrent.futures.TimeoutError):
        compiler_module._await_regex_future(future, [], 0.05)
