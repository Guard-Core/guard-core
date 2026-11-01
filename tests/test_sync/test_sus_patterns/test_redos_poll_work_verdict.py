import subprocess
import sys

import pytest

from guard_core.sync.detection_engine import _redos_cost_arbiter as arbiter
from guard_core.sync.detection_engine._redos_cost_arbiter import (
    _reach_probe_timing_child_script,
    _time_reach_probes_subprocess,
)
from guard_core.sync.detection_engine._redos_cpu_budget import ReachProbeCpuBudget
from guard_core.sync.detection_engine._redos_work_counter import (
    POLL_COUNTER_SOURCE,
    POLL_UNIT_SECONDS,
)
from guard_core.sync.detection_engine.compiler import PatternCompiler

_CDATA_PATTERN = r"<!\[CDATA\[.*?\]\]>"
_SCAN_BOUND_PATTERN = r"'\s*(?:ab)*\s*--"
_V440_SAFE_CAP = 10000
_LOWEST_MIRROR_CAP = 13000 if sys.version_info < (3, 11) else 12000
_REFUSED_CAPS = sorted({_LOWEST_MIRROR_CAP, 13000, 14000, 16000})
_NO_INSTRUCTION_COUNTER = "def build_work_counter():\n    return None\n"
_CPU_CLOCK_READS_NOTHING = "probe_times = [time.process_time() - start]"
_FIXED_POLL_COUNTER = (
    "def build_poll_counter():\n    return lambda compiled, probe: len(probe)\n"
)


def _use_child(monkeypatch: pytest.MonkeyPatch, script: str) -> None:
    monkeypatch.setattr(arbiter, "_REACH_PROBE_TIMING_CHILD_SCRIPT", script)


def _poll_child(*, cpu_clock_reads_nothing: bool) -> str:
    script = _reach_probe_timing_child_script(
        _NO_INSTRUCTION_COUNTER, POLL_COUNTER_SOURCE
    )
    if cpu_clock_reads_nothing:
        assert _CPU_CLOCK_READS_NOTHING in script
        script = script.replace(_CPU_CLOCK_READS_NOTHING, "probe_times = [0.0]")
    return script


@pytest.mark.redos_timing
def test_the_safe_cdata_cap_is_accepted_by_the_poll_count_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_child(monkeypatch, _poll_child(cpu_clock_reads_nothing=True))
    safe, reason = PatternCompiler().validate_pattern_safety(
        _CDATA_PATTERN, max_content_length=_V440_SAFE_CAP
    )
    assert safe, reason


@pytest.mark.redos_timing
@pytest.mark.parametrize("cap", _REFUSED_CAPS)
def test_the_cdata_mirror_caps_are_refused_by_the_poll_count_alone(
    monkeypatch: pytest.MonkeyPatch, cap: int
) -> None:
    _use_child(monkeypatch, _poll_child(cpu_clock_reads_nothing=True))
    safe, reason = PatternCompiler().validate_pattern_safety(
        _CDATA_PATTERN, max_content_length=cap
    )
    assert not safe, reason


@pytest.mark.redos_timing
def test_a_scan_the_poll_count_cannot_see_is_still_refused_by_cpu_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_child(monkeypatch, _poll_child(cpu_clock_reads_nothing=False))
    safe, reason = PatternCompiler().validate_pattern_safety(_SCAN_BOUND_PATTERN)
    assert not safe, reason


def _time_probes(script: str, probes: list[str]) -> list[list[float]]:
    timing = _time_reach_probes_subprocess(
        "abc", probes, ReachProbeCpuBudget(60.0), arbiter._DEFAULT_PATTERN_FLAGS
    )
    assert timing is not None
    assert timing.load_factor == 1.0
    return timing.samples_by_size


def test_the_child_reports_the_poll_work_when_the_cpu_time_stays_near_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_child(
        monkeypatch,
        _reach_probe_timing_child_script(_NO_INSTRUCTION_COUNTER, _FIXED_POLL_COUNTER),
    )
    probes = ["abcabc", "abcabcabcabc"]
    samples = _time_probes("", probes)
    assert [row[0] for row in samples] == pytest.approx(
        [len(probe) * POLL_UNIT_SECONDS for probe in probes], rel=1e-9, abs=0.0
    )


def test_a_probe_over_the_budget_by_poll_work_is_one_sample_without_a_cpu_search(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_child(
        monkeypatch,
        _reach_probe_timing_child_script(_NO_INSTRUCTION_COUNTER, _FIXED_POLL_COUNTER),
    )
    probe = "a" * int(arbiter._REACH_PROBE_BUDGET_SECONDS / POLL_UNIT_SECONDS + 10)
    assert _time_probes("", [probe]) == [[len(probe) * POLL_UNIT_SECONDS]]


@pytest.mark.parametrize("platform", ["win32"])
def test_the_poll_counter_is_absent_where_the_signal_hook_is_not_supported(
    platform: str,
) -> None:
    child = (
        "import re, sys\n"
        f"sys.platform = {platform!r}\n"
        + POLL_COUNTER_SOURCE
        + "print(build_poll_counter())\n"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", child],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert completed.stdout.strip() == "None"


_THROUGH_THE_LOAD_FACTOR_FLOOR = 1e9
_BUDGET = arbiter._REACH_PROBE_BUDGET_SECONDS


@pytest.mark.parametrize(
    ("polls", "cpu_seconds", "expected"),
    [
        (1000, 0.012, 1000 * POLL_UNIT_SECONDS),
        (800, 0.013, 800 * POLL_UNIT_SECONDS),
        (800, 0.0135, 0.0135 / arbiter._LOAD_FACTOR_FLOOR),
        (800, 0.0185, 0.0185 / arbiter._LOAD_FACTOR_FLOOR),
        (800, 0.02, 0.02 / arbiter._LOAD_FACTOR_FLOOR),
        (0, 0.012, 0.012 / arbiter._LOAD_FACTOR_FLOOR),
        (700, 0.02, 0.02 / arbiter._LOAD_FACTOR_FLOOR),
        (1000, 0.03, 0.03 / arbiter._LOAD_FACTOR_FLOOR),
    ],
)
def test_the_cpu_time_decides_only_where_it_reads_far_above_the_poll_work(
    monkeypatch: pytest.MonkeyPatch,
    polls: int,
    cpu_seconds: float,
    expected: float,
) -> None:
    monkeypatch.setattr(
        arbiter, "_REFERENCE_SCAN_SECONDS", _THROUGH_THE_LOAD_FACTOR_FLOOR
    )
    monkeypatch.setattr(arbiter, "_REACH_PROBE_FULL_SAMPLE_TRIGGER_SECONDS", 10.0)
    poll_source = (
        f"def build_poll_counter():\n    return lambda compiled, probe: {polls}\n"
    )
    script = _reach_probe_timing_child_script(_NO_INSTRUCTION_COUNTER, poll_source)
    script = script.replace(_CPU_CLOCK_READS_NOTHING, f"probe_times = [{cpu_seconds}]")
    _use_child(monkeypatch, script)
    assert _time_probes(script, ["abc"]) == [[pytest.approx(expected)]]
