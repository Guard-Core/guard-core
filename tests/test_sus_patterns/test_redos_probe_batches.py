from collections.abc import Callable
from types import SimpleNamespace
from typing import cast

import pytest

from guard_core.detection_engine._redos_cost_arbiter import (
    _PATTERN_SAFETY_DEFAULT_CAP,
    _REACH_VERDICT_PROBE_SIZES,
    ReachProbeTiming,
    _first_over_budget_reason,
    _parse_reach_probe_child_output,
)
from guard_core.detection_engine._redos_cpu_budget import ReachProbeCpuBudget
from guard_core.detection_engine._redos_probe_batches import (
    _REACH_PROBE_BATCH_SIZE,
    _batched_reach_probe_timings,
    _probe_set_digest,
    _ReachProbeTimingLike,
)


def _timing(rows: list[list[float]]) -> ReachProbeTiming:
    return ReachProbeTiming(rows, 1.0)


def _tagged_builder(prefix: str, index: int) -> Callable[[int], str]:
    def builder(size: int) -> str:
        return f"{prefix}-{index}-{size}"

    return builder


def test_probe_set_digest_preserves_tuple_boundaries_and_surrogate_bytes() -> None:
    assert _probe_set_digest(("a", "bc")) != _probe_set_digest(("ab", "c"))
    assert _probe_set_digest(("\ud800",)) != _probe_set_digest(("\ud801",))


def test_batched_timings_preserve_probe_order_and_all_rows() -> None:
    calls: list[list[str]] = []
    probe_sets = [
        (f"probe-{index}-a", f"probe-{index}-b")
        for index in range(_REACH_PROBE_BATCH_SIZE + 1)
    ]

    def fake_timing(
        _pattern: str, probes: list[str], _budget: ReachProbeCpuBudget, _flags: int
    ) -> ReachProbeTiming:
        calls.append(probes)
        return _timing([[float(index)] for index, _probe in enumerate(probes)])

    result = list(
        _batched_reach_probe_timings(
            "pattern", probe_sets, ReachProbeCpuBudget(100.0), 0, fake_timing
        )
    )

    assert len(calls) == 2
    assert calls[0] == [
        probe
        for probe_set in probe_sets[:_REACH_PROBE_BATCH_SIZE]
        for probe in probe_set
    ]
    assert calls[1] == list(probe_sets[_REACH_PROBE_BATCH_SIZE])
    assert [probes for probes, _rows, _load in result] == probe_sets
    assert result[0][1] == [[0.0], [1.0]]
    assert result[-1][1] == [[0.0], [1.0]]


@pytest.mark.parametrize(
    "timing",
    [
        None,
        object(),
        _timing([[0.1]]),
        SimpleNamespace(samples_by_size=[[0.1], [0.2]], load_factor="bad"),
        SimpleNamespace(samples_by_size=[[0.1], [float("nan")]], load_factor=1.0),
        SimpleNamespace(samples_by_size=[[-0.1], [0.2]], load_factor=1.0),
    ],
)
def test_batched_timings_fail_closed_for_malformed_child_results(
    timing: object,
) -> None:
    probe_sets = [("a", "b")]

    def fake_timing(
        _pattern: str, _probes: list[str], _budget: ReachProbeCpuBudget, _flags: int
    ) -> _ReachProbeTimingLike | None:
        return cast(_ReachProbeTimingLike, timing)

    result = list(
        _batched_reach_probe_timings(
            "pattern", probe_sets, ReachProbeCpuBudget(100.0), 0, fake_timing
        )
    )
    assert result == [(probe_sets[0], None, 1.0)]


def test_first_over_budget_reason_rejects_a_later_dangerous_batch_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    quadratic = [0.064] * 5

    def fake_timing(
        _pattern: str, probes: list[str], _budget: ReachProbeCpuBudget, _flags: int
    ) -> ReachProbeTiming:
        calls.append(probes)
        rows = []
        for probe in probes:
            rows.append(
                [0.001] * 5
                if probe.startswith("safe") or probe.endswith("16000")
                else quadratic
            )
        return _timing(rows)

    monkeypatch.setattr(
        "guard_core.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        fake_timing,
    )

    def dangerous_builder(size: int) -> str:
        return f"danger-{size}"

    safe_builders = [
        _tagged_builder("safe", index) for index in range(_REACH_PROBE_BATCH_SIZE)
    ]

    reason = _first_over_budget_reason(
        "pattern",
        safe_builders + [dangerous_builder],
        _PATTERN_SAFETY_DEFAULT_CAP,
        None,
        ReachProbeCpuBudget(100.0),
    )

    assert reason is not None
    assert "extrapolated CPU cost" in reason
    assert calls == [
        [
            f"safe-{index}-{size}"
            for index in range(_REACH_PROBE_BATCH_SIZE)
            for size in _REACH_VERDICT_PROBE_SIZES
        ],
        [f"danger-{size}" for size in _REACH_VERDICT_PROBE_SIZES],
        [f"danger-{size}" for size in _REACH_VERDICT_PROBE_SIZES],
    ]


def test_first_over_budget_reason_fails_closed_on_short_batch_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "guard_core.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        lambda *_args: _timing([[0.1]]),
    )

    reason = _first_over_budget_reason(
        "pattern",
        [_tagged_builder("x", index) for index in range(_REACH_PROBE_BATCH_SIZE)],
        _PATTERN_SAFETY_DEFAULT_CAP,
        None,
        ReachProbeCpuBudget(100.0),
    )

    assert reason is not None
    assert "killable-subprocess timeout" in reason


def test_first_over_budget_reason_fails_closed_on_malformed_retry_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    builders = [
        _tagged_builder("safe", index) for index in range(_REACH_PROBE_BATCH_SIZE - 1)
    ] + [_tagged_builder("danger", 0)]

    def fake_timing(
        _pattern: str, probes: list[str], _budget: ReachProbeCpuBudget, _flags: int
    ) -> ReachProbeTiming:
        nonlocal calls
        calls += 1
        if calls == 2:
            return ReachProbeTiming([[0.1]], 1.0)
        return _timing(
            [
                ([0.001] * 5 if "danger" not in probe else [0.064] * 5)
                for probe in probes
            ]
        )

    monkeypatch.setattr(
        "guard_core.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        fake_timing,
    )

    reason = _first_over_budget_reason(
        "pattern",
        builders,
        _PATTERN_SAFETY_DEFAULT_CAP,
        None,
        ReachProbeCpuBudget(100.0),
    )

    assert calls == 2
    assert reason is not None
    assert "extrapolated CPU cost" in reason


@pytest.mark.parametrize(
    "stdout",
    [
        '{"results": [["invalid"]], "reference": 0.1}',
        '{"results": [[]], "reference": 0.1}',
        '{"results": [], "reference": 0.1}',
        '{"results": [[0.1]], "reference": NaN}',
        '{"results": [[' + str(10**400) + ']], "reference": 0.1}',
        '{"results": [[0.1]], "reference": ' + str(10**400) + "}",
    ],
)
def test_reach_probe_child_parser_fails_closed_for_malformed_rows(
    stdout: str,
) -> None:
    assert _parse_reach_probe_child_output(stdout) is None


def test_first_over_budget_reason_preserves_budget_and_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    budgets: list[ReachProbeCpuBudget] = []
    caps: list[int] = []

    def fake_timing(
        _pattern: str, probes: list[str], budget: ReachProbeCpuBudget, _flags: int
    ) -> ReachProbeTiming:
        budgets.append(budget)
        return _timing([[0.001] * 5 for _probe in probes])

    def fake_verdict(
        _samples: list[list[float]], cap: int, _load_factor: float
    ) -> tuple[bool, float, float, float, float]:
        caps.append(cap)
        return False, 0.0, 1.0, 0.001, 0.001

    monkeypatch.setattr(
        "guard_core.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        fake_timing,
    )
    monkeypatch.setattr(
        "guard_core.detection_engine._redos_cost_arbiter._reach_probe_verdict_from_samples",
        fake_verdict,
    )
    budget = ReachProbeCpuBudget(123.5)

    reason = _first_over_budget_reason(
        "pattern",
        [_tagged_builder("x", index) for index in range(_REACH_PROBE_BATCH_SIZE)],
        54321,
        None,
        budget,
    )

    assert reason is None
    assert budgets == [budget]
    assert caps == [54321] * _REACH_PROBE_BATCH_SIZE
