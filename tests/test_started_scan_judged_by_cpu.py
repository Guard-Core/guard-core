import concurrent.futures
import re
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from guard_core._utils.detection_scan import (
    _close_cpu_pass,
    _open_cpu_pass,
    _scan_value_budget,
)
from guard_core.detection_engine import compiler as compiler_module
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig

CLIENT = "203.0.113.9"
_TIMEOUT = 0.3


@pytest.fixture
def manager(monkeypatch: pytest.MonkeyPatch) -> Iterator[SusPatternsManager]:
    monkeypatch.setattr(SusPatternsManager, "_instance", None)
    monkeypatch.setattr(SusPatternsManager, "_config", None)
    yield SusPatternsManager(
        SecurityConfig(detection_compiler_timeout=_TIMEOUT, enable_redis=False)
    )


@pytest.fixture
def fresh_regex_pool(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    pool = concurrent.futures.ThreadPoolExecutor(
        max_workers=compiler_module._SHARED_EXECUTOR_MAX_WORKERS
    )
    monkeypatch.setattr(compiler_module, "_shared_executor", pool)
    yield
    pool.shutdown(wait=False, cancel_futures=True)


def _waits_without_cpu(seconds: float) -> Callable[[str], Iterator[re.Match]]:
    def finder(content: str) -> Iterator[re.Match]:
        time.sleep(seconds)
        return iter(())

    return finder


def _burns_cpu(seconds: float) -> Callable[[str], Iterator[re.Match]]:
    def finder(content: str) -> Iterator[re.Match]:
        end = time.thread_time() + seconds
        while time.thread_time() < end:
            pass
        return iter(())

    return finder


async def _windowed(
    manager: SusPatternsManager, finder: Callable[[str], Iterator[re.Match]]
) -> tuple[dict | None, bool]:
    with _scan_value_budget(100):
        token = _open_cpu_pass()
        try:
            return await manager._check_windowed_pattern(
                re.compile("evil"),
                finder,
                "so evil",
                time.monotonic(),
                "sqli",
                "unknown",
            )
        finally:
            _close_cpu_pass(token)


@pytest.mark.usefixtures("fresh_regex_pool")
async def test_a_windowed_row_that_waited_for_the_gil_stays_clean(
    manager: SusPatternsManager,
) -> None:
    result = await _windowed(manager, _waits_without_cpu(_TIMEOUT * 1.5))

    assert result == (None, False)


@pytest.mark.usefixtures("fresh_regex_pool")
async def test_a_windowed_row_that_used_its_cpu_budget_is_a_pattern_timeout(
    manager: SusPatternsManager,
) -> None:
    result = await _windowed(manager, _burns_cpu(_TIMEOUT * 1.2))

    assert result == (None, True)


@pytest.mark.usefixtures("fresh_regex_pool")
def test_a_started_custom_job_that_waited_for_the_gil_is_not_a_timeout() -> None:
    outcome: list[str] = []
    compiler = compiler_module.PatternCompiler(default_timeout=0.2)

    def starved(work: Callable[[], Any]) -> Callable[[], Any]:
        def run() -> Any:
            time.sleep(0.5)
            return work()

        return run

    matcher = compiler.create_safe_finditer_matcher(
        re.compile("zzz"), worker_wrapper=starved, outcome=outcome
    )

    assert matcher("so evil") == []
    assert outcome == []


def _slow_start(monkeypatch: pytest.MonkeyPatch, pause: Callable[[], None]) -> None:
    from guard_core.handlers import _suspatterns_regex

    real = _suspatterns_regex._timed_in_worker

    def paused(work: Callable[[], Any], cpu_sink: list[float]) -> Callable[[], Any]:
        def run() -> Any:
            pause()
            return work()

        return real(run, cpu_sink)

    monkeypatch.setattr(_suspatterns_regex, "_timed_in_worker", paused)


@pytest.mark.usefixtures("fresh_regex_pool")
async def test_a_started_job_on_the_legacy_path_that_waited_is_not_a_timeout(
    manager: SusPatternsManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager._compiler = None
    _slow_start(monkeypatch, lambda: time.sleep(_TIMEOUT * 1.5))

    result = await manager._check_pattern_with_timeout(
        re.compile("zzz"), "so evil", CLIENT, time.monotonic()
    )

    assert result == (None, False)


@pytest.mark.usefixtures("fresh_regex_pool")
async def test_a_started_job_on_the_legacy_path_that_used_its_cpu_is_a_timeout(
    manager: SusPatternsManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager._compiler = None

    def burn() -> None:
        end = time.thread_time() + _TIMEOUT * 1.2
        while time.thread_time() < end:
            pass

    _slow_start(monkeypatch, burn)

    result = await manager._check_pattern_with_timeout(
        re.compile("zzz"), "so evil", CLIENT, time.monotonic()
    )

    assert result == (None, True)


def test_a_started_job_that_never_ends_is_cut_at_the_wall_backstop() -> None:
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    release = threading.Event()
    future, started = compiler_module.submit_to_regex_executor(
        lambda: release.wait(30), pool
    )
    try:
        begun = time.monotonic()
        with pytest.raises(concurrent.futures.TimeoutError):
            compiler_module.wait_for_regex_run(future, started, 0.05, 0.4)
        assert 0.3 <= time.monotonic() - begun < 2.0
    finally:
        release.set()
        pool.shutdown(wait=True)


def test_the_wall_backstop_is_the_scan_cap_and_never_below_the_cpu_bound() -> None:
    assert compiler_module.wall_backstop(2.0) == 10.0
    with _scan_value_budget(100, max_scan_seconds=25.0):
        assert compiler_module.wall_backstop(2.0) == 25.0
    with _scan_value_budget(100, max_scan_seconds=1.0):
        assert compiler_module.wall_backstop(2.0) == 2.0
