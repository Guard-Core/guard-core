import json
import re
import subprocess
import sys
import time
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from guard_core.detection_engine import _redos_cost_arbiter as arbiter
from guard_core.detection_engine._redos_cost_arbiter import (
    _DEFAULT_PATTERN_FLAGS,
    _REACH_PROBE_COMBINED_TIMEOUT_SECONDS,
    _REACH_PROBE_TIMING_CHILD_SCRIPT,
    _communicate_until_stalled,
    _run_reach_probe_child,
)
from guard_core.detection_engine._redos_cpu_budget import ReachProbeCpuBudget

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
    monkeypatch.setattr(arbiter, "_REACH_PROBE_STALL_POLL_SECONDS", 0.1)
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    start = time.monotonic()
    assert _communicate_until_stalled(process, "", lambda: 0, 0.4) is None
    assert time.monotonic() - start < 30.0
    assert process.returncode != 0


def test_a_child_that_keeps_reporting_progress_is_never_stalled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(arbiter, "_REACH_PROBE_STALL_POLL_SECONDS", 0.1)
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(1.0); print('done')"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    marks = iter(range(1, 1000))

    def next_mark() -> int:
        return next(marks)

    output = _communicate_until_stalled(process, "", next_mark, 0.3)
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

    monkeypatch.setattr(arbiter, "signal", SimpleNamespace())
    monkeypatch.setattr(arbiter, "_communicate_until_stalled", record_stall_window)
    budget = ReachProbeCpuBudget(30.0)
    assert _run_reach_probe_child("abc", ["abc"], budget, 7.0, re.IGNORECASE) is None
    assert stall_windows == [7.0]
