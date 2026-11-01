import pytest

from guard_core.sync.detection_engine import _redos_cost_arbiter as arbiter
from guard_core.sync.detection_engine._redos_cost_arbiter import (
    _REACH_PROBE_CHILD_TIMEOUT_SECONDS,
    _REACH_PROBE_COMBINED_TIMEOUT_SECONDS,
    _time_reach_probes_subprocess,
    _time_single_reach_probe_subprocess,
)
from guard_core.sync.detection_engine._redos_cpu_budget import ReachProbeCpuBudget
from guard_core.sync.detection_engine._redos_limited_child import ChildResult
from guard_core.sync.detection_engine.compiler import PatternCompiler


def _record_limits(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    limits: list[float] = []

    def refuse(script: str, payload: str, cpu_limit: float) -> ChildResult | None:
        limits.append(cpu_limit)
        return None

    monkeypatch.setattr(arbiter, "run_limited_child", refuse)
    return limits


def test_a_slow_host_stretches_the_combined_child_cpu_limit_like_its_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limits = _record_limits(monkeypatch)
    _time_reach_probes_subprocess("a", ["a"], ReachProbeCpuBudget(1000.0, 3.0))
    assert limits == [_REACH_PROBE_COMBINED_TIMEOUT_SECONDS * 3.0]


def test_a_slow_host_stretches_the_single_probe_child_cpu_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limits = _record_limits(monkeypatch)
    _time_single_reach_probe_subprocess("a", "a", ReachProbeCpuBudget(1000.0, 3.0))
    assert limits == [_REACH_PROBE_CHILD_TIMEOUT_SECONDS * 3.0]


def test_a_fast_host_keeps_the_idle_child_cpu_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limits = _record_limits(monkeypatch)
    _time_reach_probes_subprocess("a", ["a"], ReachProbeCpuBudget(1000.0, 0.25))
    _time_reach_probes_subprocess("a", ["a"], ReachProbeCpuBudget(1000.0))
    assert limits == [_REACH_PROBE_COMBINED_TIMEOUT_SECONDS] * 2


def test_the_stretched_child_cpu_limit_never_passes_the_remaining_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limits = _record_limits(monkeypatch)
    _time_reach_probes_subprocess("a", ["a"], ReachProbeCpuBudget(7.0, 3.0))
    assert limits == [7.0]


def test_the_validator_gives_its_children_the_load_factor_it_measured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limits = _record_limits(monkeypatch)
    monkeypatch.setattr(arbiter, "_measure_host_load_factor", lambda: 2.5)
    safe, _ = PatternCompiler().validate_pattern_safety(r"(\w|\d)*;")
    assert not safe
    assert limits[0] == _REACH_PROBE_COMBINED_TIMEOUT_SECONDS * 2.5
