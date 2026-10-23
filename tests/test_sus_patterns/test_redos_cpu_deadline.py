import itertools
import json
import re
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from guard_core.detection_engine import _redos_cost_arbiter as arbiter
from guard_core.detection_engine import _redos_limited_child as limited_child
from guard_core.detection_engine import _redos_stray_chooser
from guard_core.detection_engine._redos_cost_arbiter import (
    _DEFAULT_PATTERN_FLAGS,
    _REACH_PROBE_COMBINED_TIMEOUT_SECONDS,
    _REACH_PROBE_TIMING_CHILD_SCRIPT,
    _run_reach_probe_child,
)
from guard_core.detection_engine._redos_cpu_budget import ReachProbeCpuBudget
from guard_core.detection_engine._redos_limited_child import (
    communicate_until_stalled,
)

_QUADRATIC_UA_PATTERN = r"(?:foo|bar)+$"
_USER_AGENT_CAP = 512


def test_child_is_killed_by_its_own_cpu_limit_not_by_the_wall_clock() -> None:
    budget = ReachProbeCpuBudget(_REACH_PROBE_COMBINED_TIMEOUT_SECONDS)
    start = time.monotonic()
    timing = _run_reach_probe_child(
        r"(a+)+b", ["a" * 40], budget, 0.3, _DEFAULT_PATTERN_FLAGS
    )
    assert timing is None
    assert time.monotonic() - start < 30.0
    assert budget.remaining_seconds == _REACH_PROBE_COMBINED_TIMEOUT_SECONDS


def test_child_charges_the_budget_with_the_cpu_it_reports() -> None:
    budget = ReachProbeCpuBudget(30.0)
    timing = _run_reach_probe_child(
        "abc", ["abcabc"], budget, 10.0, _DEFAULT_PATTERN_FLAGS
    )
    assert timing is not None
    assert timing.cpu_seconds > 0.0
    assert budget.remaining_seconds == pytest.approx(30.0 - timing.cpu_seconds)


def test_child_beats_on_stderr_per_cpu_heartbeat_and_reports_its_cpu() -> None:
    payload = json.dumps([r"(?:a|b)+c", ["ab" * 5000] * 3, 5, 30.0, 0, 0.0, 0.01])
    completed = subprocess.run(
        [sys.executable, "-S", "-I", "-c", _REACH_PROBE_TIMING_CHILD_SCRIPT],
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr.count(".") >= 1
    assert json.loads(completed.stdout)["cpu"] > 0.0


def test_a_sleeping_child_with_no_cpu_progress_is_killed_after_the_stall_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(limited_child, "STALL_POLL_SECONDS", 0.1)
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    start = time.monotonic()
    assert communicate_until_stalled(process, "", lambda: 0, 0.4) is None
    assert time.monotonic() - start < 30.0
    assert process.returncode != 0


def test_a_child_that_keeps_reporting_progress_is_never_stalled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(limited_child, "STALL_POLL_SECONDS", 0.1)
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(1.0); print('done')"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    marks = iter(range(1, 1000))

    def next_mark() -> int:
        return next(marks)

    output = communicate_until_stalled(process, "", next_mark, 0.3)
    assert output is not None
    assert output[0].strip() == "done"


def test_a_platform_without_interval_timers_keeps_the_cpu_limit_as_wall_backstop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stall_windows: list[float] = []

    def record_stall_window(
        process: "subprocess.Popen[str]",
        payload: str,
        marks: Callable[[], int],
        stall_seconds: float,
    ) -> None:
        stall_windows.append(stall_seconds)
        process.kill()
        process.communicate()

    monkeypatch.setattr(limited_child, "signal", SimpleNamespace())
    monkeypatch.setattr(limited_child, "communicate_until_stalled", record_stall_window)
    budget = ReachProbeCpuBudget(30.0)
    assert _run_reach_probe_child("abc", ["abc"], budget, 7.0, re.IGNORECASE) is None
    assert stall_windows == [7.0]


def test_run_limited_child_returns_the_exit_code_stdout_and_stderr_without_beats() -> (
    None
):
    result = limited_child.run_limited_child(
        "import sys; print('out'); sys.stderr.write('boom.'); sys.exit(3)",
        "",
        5.0,
    )
    assert result == limited_child.ChildResult(3, "out\n", "boom")


def test_killed_by_cpu_limit_needs_the_cpu_signal_on_this_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = limited_child.ChildResult(-signal.SIGPROF, "", "")
    assert limited_child.killed_by_cpu_limit(result) is True
    assert (
        limited_child.killed_by_cpu_limit(limited_child.ChildResult(1, "", "")) is False
    )
    monkeypatch.setattr(limited_child, "signal", SimpleNamespace())
    assert limited_child.killed_by_cpu_limit(result) is False


def test_probe_with_test_strings_is_killed_by_its_cpu_limit_not_the_wall_clock() -> (
    None
):
    start = time.monotonic()
    is_safe, reason = arbiter._run_pattern_safety_probe_subprocess(
        r"(a+)+b", ["a" * 40], re.IGNORECASE
    )
    assert is_safe is False
    assert "killable-subprocess timeout" in reason
    assert time.monotonic() - start < 60.0


def test_probe_with_test_strings_stops_a_child_with_no_cpu_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(limited_child, "STALL_WALL_SECONDS", 0.5)
    monkeypatch.setattr(limited_child, "STALL_POLL_SECONDS", 0.1)
    monkeypatch.setattr(
        arbiter,
        "_PATTERN_SAFETY_PROBE_CHILD_SCRIPT",
        "import time; time.sleep(60)\n",
    )
    is_safe, reason = arbiter._run_pattern_safety_probe_subprocess(
        r"abc", ["abc"], re.IGNORECASE
    )
    assert is_safe is False
    assert "killable-subprocess timeout" in reason


def test_probe_with_test_strings_reports_a_pattern_that_does_not_compile() -> None:
    is_safe, reason = arbiter._run_pattern_safety_probe_subprocess(
        "[", ["a"], re.IGNORECASE
    )
    assert is_safe is False
    assert reason.startswith("Pattern validation failed")


def test_probe_with_test_strings_reports_a_string_over_the_per_string_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        arbiter, "_PATTERN_SAFETY_PROBE_PER_STRING_THRESHOLD_SECONDS", -1.0
    )
    is_safe, reason = arbiter._run_pattern_safety_probe_subprocess(
        r"abc", ["abc"], re.IGNORECASE
    )
    assert is_safe is False
    assert reason == "Pattern timed out on test string of length 3"


def test_construction_deadline_counts_the_parent_threads_cpu_time() -> None:
    assert arbiter._remaining_budget(time.thread_time() + 5.0) == pytest.approx(
        5.0, abs=0.5
    )
    assert arbiter._remaining_budget(time.thread_time() - 1.0) < 0.0


def test_stray_verification_refuses_only_when_the_cpu_deadline_has_passed() -> None:
    ample = _redos_stray_chooser._build_stray_context("a+", 0, time.thread_time() + 60)
    assert _redos_stray_chooser._stray_verification_timeout(ample) > 0
    spent = _redos_stray_chooser._build_stray_context("a+", 0, time.thread_time() - 1)
    with pytest.raises(TimeoutError, match="exceeded its deadline"):
        _redos_stray_chooser._stray_verification_timeout(spent)


def test_the_wall_backstop_ends_construction_that_makes_no_cpu_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = itertools.count()
    monkeypatch.setattr(
        arbiter,
        "time",
        SimpleNamespace(
            monotonic=lambda: next(ticks) * 1000.0, thread_time=time.thread_time
        ),
    )
    is_safe, reason = arbiter._reach_probe_cost_verdict(r"[a-z]+[a-z]+$", None)
    assert is_safe is False
    assert reason == "Pattern validation probe construction exceeded its deadline"
