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
from guard_core.sync._utils import detection_scan as scan_module
from guard_core.sync._utils.compiler_finditer import _compiler_finditer
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
            status_code=status_code, headers={}
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
    assert result.body_read_error == "queue_wait"
    assert result.queue_wait_surface == "query"
    assert "no regex worker took the scan" in result.body_read_detail


@pytest.mark.usefixtures("saturated_regex_pool")
def test_a_queue_wait_answers_503_with_retry_after_an_event_and_no_strike(
    custom_rows: SyncSecurityConfig,
) -> None:
    check, middleware = _check()

    response = check.check(_request("hello"))

    assert response is not None
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["event_type"] == EVENT_SUSPICIOUS_REQUEST
    assert event["action_taken"] == "request_blocked"
    assert middleware.suspicious_request_counts == {}


@pytest.mark.usefixtures("saturated_regex_pool")
def test_queue_waits_never_ban_a_client_on_the_default_threshold(
    custom_rows: SyncSecurityConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(compiler_module, "_consecutive_timeouts", 0)
    check, middleware = _check()
    attempts = SyncSecurityConfig().auto_ban_threshold + 2

    statuses = []
    for _ in range(attempts):
        response = check.check(_request("hello"))
        statuses.append(None if response is None else response.status_code)

    held = compiler_module._SHARED_EXECUTOR_MAX_WORKERS
    assert statuses[:held] == [503] * held
    assert set(statuses) <= {503, None}
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
def isolated_manager(monkeypatch: pytest.MonkeyPatch) -> Iterator[SusPatternsManager]:
    monkeypatch.setattr(SusPatternsManager, "_instance", None)
    monkeypatch.setattr(SusPatternsManager, "_config", None)
    yield SusPatternsManager(_config())


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
def test_the_windowed_path_never_queues_for_a_worker(
    isolated_manager: SusPatternsManager,
) -> None:
    threat, timed_out = isolated_manager._check_windowed_pattern(
        re.compile("evil"),
        lambda content: iter(()),
        "so evil",
        time.monotonic(),
        "custom",
        "unknown",
    )

    assert (threat, timed_out) == (None, False)


@pytest.mark.usefixtures("saturated_regex_pool")
def test_the_finditer_matcher_reports_a_queue_wait_and_no_matches() -> None:
    outcome: list[str] = []
    compiler = compiler_module.PatternCompiler(default_timeout=0.2)
    matcher = compiler.create_safe_finditer_matcher(re.compile("evil"), outcome=outcome)

    assert matcher("so evil") == []
    assert outcome == [compiler_module.SCAN_OUTCOME_QUEUE_WAIT]


def _wait_without_bound(
    future: concurrent.futures.Future[Any],
    started: object,
    timeout: float,
    backstop: float | None = None,
) -> Any:
    return future.result()


def _finditer_outcome_of_a_run_that(
    monkeypatch: pytest.MonkeyPatch, pause: Callable[[], None]
) -> list[str]:
    outcome: list[str] = []
    compiler = compiler_module.PatternCompiler(default_timeout=0.2)

    def paused(work: Callable[[], Any]) -> Callable[[], Any]:
        def run() -> Any:
            pause()
            return work()

        return run

    matcher = compiler.create_safe_finditer_matcher(
        re.compile("zzz"), worker_wrapper=paused, outcome=outcome
    )
    monkeypatch.setattr(compiler_module, "wait_for_regex_run", _wait_without_bound)
    assert matcher("so evil") == []
    return outcome


def _burn_cpu(seconds: float) -> None:
    end = time.thread_time() + seconds
    while time.thread_time() < end:
        pass


@pytest.mark.usefixtures("fresh_regex_pool")
def test_the_finditer_matcher_reports_a_run_that_used_its_cpu_budget_without_a_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome = _finditer_outcome_of_a_run_that(monkeypatch, lambda: _burn_cpu(0.25))

    assert outcome == [compiler_module.SCAN_OUTCOME_RUN_TIMEOUT]


@pytest.mark.usefixtures("fresh_regex_pool")
def test_the_finditer_matcher_does_not_charge_a_worker_that_only_waited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome = _finditer_outcome_of_a_run_that(monkeypatch, lambda: time.sleep(0.25))

    assert outcome == []


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


_INLINE_BUDGET = 0.1
_CATASTROPHIC_INLINE_CONTENT = "a" * 25 + "!"


@pytest.fixture
def scan_cpu_marked() -> Iterator[None]:
    token = scan_module._scan_cpu_mark.set(time.thread_time())
    yield
    scan_module._scan_cpu_mark.reset(token)


@pytest.mark.usefixtures("scan_cpu_marked")
def test_an_inline_pattern_that_only_waited_for_the_gil_stays_clean() -> None:
    compiler = compiler_module.PatternCompiler(default_timeout=_INLINE_BUDGET)
    holding = threading.Event()

    def hold_the_gil() -> None:
        holding.set()
        re.match(r"(a+)+$", _CATASTROPHIC_INLINE_CONTENT)

    holder = threading.Thread(target=hold_the_gil)
    pattern_start = time.monotonic()
    holder.start()
    holding.wait(10)
    try:
        _, outcome = _compiler_finditer(
            compiler, re.compile("zzz"), "sqli", "so evil", pattern_start
        )
    finally:
        holder.join()

    assert time.monotonic() - pattern_start >= 0.9 * _INLINE_BUDGET
    assert outcome is None


@pytest.mark.usefixtures("scan_cpu_marked")
def test_an_inline_pattern_that_used_its_cpu_past_the_budget_is_a_timeout() -> None:
    compiler = compiler_module.PatternCompiler(default_timeout=_INLINE_BUDGET)

    _, outcome = _compiler_finditer(
        compiler,
        re.compile(r"(a+)+$"),
        "sqli",
        _CATASTROPHIC_INLINE_CONTENT,
        time.monotonic(),
    )

    assert outcome == compiler_module.SCAN_OUTCOME_RUN_TIMEOUT


def test_an_inline_pattern_outside_a_request_scope_is_judged_by_wall_time() -> None:
    compiler = compiler_module.PatternCompiler(default_timeout=_INLINE_BUDGET)

    _, outcome = _compiler_finditer(
        compiler, re.compile("zzz"), "sqli", "so evil", time.monotonic() - 5
    )

    assert outcome == compiler_module.SCAN_OUTCOME_RUN_TIMEOUT


@pytest.mark.usefixtures("fresh_regex_pool")
def test_one_queue_expiry_on_a_free_pool_is_the_flag_with_no_fallback(
    custom_rows: SyncSecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    expired = MagicMock(side_effect=BodyReadFailedError("no regex worker took it"))
    monkeypatch.setattr(SusPatternsManager, "detect", expired)

    with caplog.at_level(logging.ERROR):
        result = detect_penetration_attempt(_request("1' OR '1'='1"), custom_rows)

    assert result.is_threat is False
    assert result.body_read_error == "failed"
    assert "Enhanced detection failed" not in caplog.text


def _scanned_pattern_count(
    config: SyncSecurityConfig, monkeypatch: pytest.MonkeyPatch
) -> int:
    scanned = 0
    original = SusPatternsManager._check_regex_pattern

    def counting(self: SusPatternsManager, *args: Any, **kwargs: Any) -> Any:
        nonlocal scanned
        scanned += 1
        return original(self, *args, **kwargs)

    monkeypatch.setattr(SusPatternsManager, "_check_regex_pattern", counting)
    result = detect_penetration_attempt(_request("hello"), config)
    monkeypatch.setattr(SusPatternsManager, "_check_regex_pattern", original)
    assert result.body_read_error is None
    return scanned


@pytest.mark.usefixtures("saturated_regex_pool")
def test_a_pool_held_by_stuck_workers_is_replaced_and_scans_in_full(
    custom_rows: SyncSecurityConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(compiler_module, "_consecutive_timeouts", 0)
    held_pool = compiler_module._shared_executor
    check, _ = _check()
    for _ in range(compiler_module._SHARED_EXECUTOR_MAX_WORKERS):
        response = check.check(_request("hello"))
        assert response is not None
        assert response.status_code == 503
    replacement = compiler_module._shared_executor

    try:
        assert replacement is not held_pool
        after_replacement = _scanned_pattern_count(custom_rows, monkeypatch)
        compiler_module._shared_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=compiler_module._SHARED_EXECUTOR_MAX_WORKERS
        )
        free_pool = _scanned_pattern_count(custom_rows, monkeypatch)
        compiler_module._shared_executor.shutdown(wait=True)
    finally:
        assert replacement is not None
        replacement.shutdown(wait=True)

    assert after_replacement == free_pool > 0


def _request_with(
    *,
    path: str = "/api",
    headers: dict[str, str] | None = None,
    query: dict[str, str] | None = None,
    body: bytes = b"",
) -> SyncMockGuardRequest:
    request = SyncMockGuardRequest(
        path=path,
        method="POST" if body else "GET",
        headers=headers or {},
        query_params=query or {},
        body_content=body,
    )
    request.state.client_ip = CLIENT
    request.state.route_config = None
    return request


@pytest.mark.usefixtures("saturated_regex_pool")
@pytest.mark.parametrize(
    ("context", "surface"),
    [
        ("url_path", "url path"),
        ("query_param:q", "query"),
        ("header:x-note", "header"),
        ("request_body", "body field"),
        ("request_body:form_field", "body field"),
    ],
)
def test_a_queue_wait_names_the_surface_that_was_being_scanned(
    custom_rows: SyncSecurityConfig, context: str, surface: str
) -> None:
    with pytest.raises(compiler_module.RegexQueueWaitError) as caught:
        scan_module._check_value_enhanced("hello", context, CLIENT, "cid")

    assert caught.value.surface == surface


@pytest.mark.usefixtures("saturated_regex_pool")
def test_a_queue_wait_on_the_path_is_reported_with_its_surface(
    custom_rows: SyncSecurityConfig,
) -> None:
    result = detect_penetration_attempt(_request_with(path="/hello-there"), custom_rows)

    assert result.body_read_error == "queue_wait"
    assert result.queue_wait_surface == "url path"


@pytest.mark.usefixtures("saturated_regex_pool")
def test_a_queue_wait_logs_its_own_line_and_event_naming_the_surface(
    custom_rows: SyncSecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    check, middleware = _check()

    with caplog.at_level(logging.WARNING, logger="test_regex_queue_wait"):
        check.check(_request("hello"))

    assert (
        f"Request scan waited for a regex worker for IP: {CLIENT} (surface: query)"
        in caplog.text
    )
    assert "Request body read" not in caplog.text
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["reason"].startswith(
        "Request scan queue wait (query): no regex worker"
    )


@pytest.mark.usefixtures("saturated_regex_pool")
def test_a_queue_wait_in_passive_mode_passes_with_an_event(
    custom_rows: SyncSecurityConfig,
) -> None:
    check, middleware = _check(_config(passive_mode=True))

    response = check.check(_request("hello"))

    assert response is None
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["action_taken"] == "logged_only"
    assert middleware.suspicious_request_counts == {}


def test_a_real_body_read_failure_keeps_its_400_line_and_event(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync._utils.detection_result_builders import _build_body_read_error
    from guard_core.sync.core.checks.implementations.suspicious_activity import (
        body_read_outcome,
    )

    check, middleware = _check()
    result = _build_body_read_error(False, "the connection dropped")

    with caplog.at_level(logging.WARNING, logger="test_regex_queue_wait"):
        response = body_read_outcome(check, _request("hello"), CLIENT, result)

    assert response is not None
    assert response.status_code == 400
    assert "Reason: Request body read failed for IP: 203.0.113.9" in caplog.text
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["reason"] == "Request body read failed: the connection dropped"
    assert event["action_taken"] == "request_blocked"
    middleware.create_error_response.assert_called_once_with(
        status_code=400, default_message="Request body could not be read"
    )


def test_a_queue_wait_error_is_a_body_read_failure_with_the_wait_and_no_surface() -> (
    None
):
    error = compiler_module.no_regex_worker_time(2.0)

    assert isinstance(error, BodyReadFailedError)
    assert (error.waited, error.surface) == (2.0, None)
