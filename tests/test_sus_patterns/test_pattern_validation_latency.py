import json
import resource
import subprocess
import sys
import time
from collections.abc import Callable
from unittest.mock import patch

import pytest

from guard_core.detection_engine import _redos_cost_arbiter as arbiter
from guard_core.detection_engine._redos_limited_child import ChildResult
from guard_core.detection_engine.compiler import PatternCompiler
from guard_core.handlers.suspatterns_handler import (
    _PATTERN_SCAN_WINDOW_MATCHERS,
    _SCAN_WINDOW_PATTERNS,
    _WINDOWED_PATTERN_FINDERS,
    SusPatternsManager,
)

_CPU_CEILING_SECONDS = 4.0
# CPU seconds move with the load of the host (contention, a probe whose timing
# noise makes the arbiter take its full sample count), so the CPU ceiling is 4.0
# CPU seconds on an idle host and is scaled by how much slower the host is right
# now, measured in the same test and process tree by a fixed stdlib workload that
# shares no code with the validator (a slowed validator therefore does not scale
# its own ceiling). The factor is never below 1.0, so the ceiling never drops
# below 4.0. The work the validator does is also bounded in numbers that do not
# depend on the host at all: the probe subprocesses it starts and the probe
# characters times samples it hands them (measured: 51 and 8,880,000 for the first
# accepted pattern, 21 and 3,840,000 for the second, identical on every run).
_CALIBRATION_IDLE_CPU_SECONDS = 0.29
_CALIBRATION_SCRIPT = (
    "import re\n"
    "compiled = re.compile(r'(?i)/[0-9]*\\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|"
    "DROP|CONCAT|CHAR|UPDATE)\\b')\n"
    "probe = '/' + '0' * 32000\n"
    "for _ in range(100):\n"
    "    compiled.search(probe)\n"
)
_REACH_PROBE_PAYLOAD_FIELDS = 7
_ACCEPTED_PATTERN_SPAWN_CEILING = 64
_ACCEPTED_PATTERN_PROBE_WORK_CEILING = 11_000_000
_CATASTROPHIC_PATTERN_SPAWN_CEILING = 16
_CATASTROPHIC_PATTERN_PROBE_WORK_CEILING = 400_000


def _cpu_seconds_including_probe_subprocesses() -> float:
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return time.process_time() + children.ru_utime + children.ru_stime


class _Measured:
    def __init__(self) -> None:
        self.verdict: tuple[bool, str] = (False, "")
        self.cpu_seconds = 0.0
        self.cpu_ceiling = _CPU_CEILING_SECONDS
        self.spawns = 0
        self.probe_work = 0


def _calibration_cpu_seconds() -> float:
    start = _cpu_seconds_including_probe_subprocesses()
    subprocess.run(
        [sys.executable, "-S", "-I", "-c", _CALIBRATION_SCRIPT],
        check=True,
        capture_output=True,
    )
    return _cpu_seconds_including_probe_subprocesses() - start


def _validate_measuring(compiler: PatternCompiler, pattern: str) -> _Measured:
    measured = _Measured()
    real_run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run

    real_limited = arbiter.run_limited_child

    def counting_run(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        measured.spawns += 1
        return real_run(*args, **kwargs)

    def counting_limited(
        script: str, payload: str, cpu_limit: float
    ) -> ChildResult | None:
        measured.spawns += 1
        decoded = json.loads(payload)
        if len(decoded) == _REACH_PROBE_PAYLOAD_FIELDS:
            measured.probe_work += sum(len(probe) for probe in decoded[1]) * decoded[2]
        return real_limited(script, payload, cpu_limit)

    before = _calibration_cpu_seconds()
    start = _cpu_seconds_including_probe_subprocesses()
    with (
        patch.object(subprocess, "run", counting_run),
        patch.object(arbiter, "run_limited_child", counting_limited),
    ):
        measured.verdict = compiler.validate_pattern_safety(pattern)
    measured.cpu_seconds = _cpu_seconds_including_probe_subprocesses() - start
    slowdown = max(before, _calibration_cpu_seconds()) / _CALIBRATION_IDLE_CPU_SECONDS
    measured.cpu_ceiling = _CPU_CEILING_SECONDS * max(slowdown, 1.0)
    return measured


_CATASTROPHIC_PATTERNS = [
    r"(?P<x>\d{1,3}\d{1,3})+$",
    r"((\d{1,3}\d{1,3}))+$",
    r"(?:(?:a|aa))+$",
    r"(?P<a>(?P<b>\d\d?))+$",
    r"(a+)+$",
    r"(\w+\s?)*$",
]


def _first_accepted_builtin_patterns(count: int) -> list[str]:
    excluded = set(_WINDOWED_PATTERN_FINDERS)
    excluded |= set(_PATTERN_SCAN_WINDOW_MATCHERS)
    excluded |= set(_SCAN_WINDOW_PATTERNS)
    accepted = [
        pattern
        for pattern, _ctx, _category in SusPatternsManager._pattern_definitions
        if pattern not in excluded
    ]
    return accepted[:count]


def test_catastrophic_patterns_are_rejected_well_under_the_old_forty_second_stall() -> (
    None
):
    compiler = PatternCompiler()
    for pattern in _CATASTROPHIC_PATTERNS:
        measured = _validate_measuring(compiler, pattern)
        assert measured.verdict[0] is False, (
            f"{pattern!r} should have been rejected: {measured.verdict[1]}"
        )
        assert measured.cpu_seconds < measured.cpu_ceiling, (
            f"{pattern!r} used {measured.cpu_seconds:.3f} CPU seconds to reject, "
            f"expected under {measured.cpu_ceiling:.3f}"
        )
        assert measured.spawns <= _CATASTROPHIC_PATTERN_SPAWN_CEILING
        assert measured.probe_work <= _CATASTROPHIC_PATTERN_PROBE_WORK_CEILING


def test_accepted_builtin_patterns_stay_accepted_and_validate_quickly() -> None:
    compiler = PatternCompiler()
    for pattern in _first_accepted_builtin_patterns(2):
        measured = _validate_measuring(compiler, pattern)
        is_safe, reason = measured.verdict
        assert is_safe is True, f"{pattern!r} should stay accepted, got: {reason}"
        assert measured.cpu_seconds < measured.cpu_ceiling, (
            f"{pattern!r} used {measured.cpu_seconds:.3f} CPU seconds to validate, "
            f"expected under {measured.cpu_ceiling:.3f}"
        )
        assert measured.spawns <= _ACCEPTED_PATTERN_SPAWN_CEILING
        assert measured.probe_work <= _ACCEPTED_PATTERN_PROBE_WORK_CEILING


def test_a_validator_doing_twice_the_work_is_over_both_work_ceilings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.detection_engine import compiler as compiler_module

    real_verdict: Callable[..., tuple[bool, str]] = (
        compiler_module._reach_probe_cost_verdict
    )

    def twice(*args: object, **kwargs: object) -> tuple[bool, str]:
        real_verdict(*args, **kwargs)
        return real_verdict(*args, **kwargs)

    monkeypatch.setattr(compiler_module, "_reach_probe_cost_verdict", twice)
    pattern = _first_accepted_builtin_patterns(1)[0]

    measured = _validate_measuring(PatternCompiler(), pattern)

    assert measured.spawns > _ACCEPTED_PATTERN_SPAWN_CEILING
    assert measured.probe_work > _ACCEPTED_PATTERN_PROBE_WORK_CEILING
