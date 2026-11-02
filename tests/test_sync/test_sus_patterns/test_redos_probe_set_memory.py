import functools
import tracemalloc
from collections.abc import Callable, Iterator

import pytest

from guard_core.sync.detection_engine import _redos_cost_arbiter as arbiter
from guard_core.sync.detection_engine._redos_cpu_budget import ReachProbeCpuBudget

_DIRECT_PATH_VIOLATION = "a structural rule"


def _distinct_fill(index: int, size: int) -> str:
    return chr(0x4E00 + index) * size


def _paired_fill(group: int, size: int) -> str:
    return f"{group:05d}".ljust(size, "z")


def _record_probes_instead_of_timing(
    monkeypatch: pytest.MonkeyPatch, seen: list[tuple[str, ...]]
) -> None:
    def time_probes(
        pattern: str, probes: list[str], budget: object, flags: int
    ) -> None:
        seen.append(tuple(probes))

    monkeypatch.setattr(
        arbiter, "_reach_probe_timing_strategy", lambda *_args: time_probes
    )


def _results(
    builders: list[Callable[[int], str]], cap: int
) -> Iterator[tuple[tuple[str, ...], list[list[float]] | None, float]]:
    return arbiter._timed_probe_results(
        "x",
        builders,
        cap,
        ReachProbeCpuBudget(30.0),
        0,
        _DIRECT_PATH_VIOLATION,
        False,
    )


def test_the_first_timed_probe_set_does_not_wait_for_every_probe_set_to_be_built(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _record_probes_instead_of_timing(monkeypatch, [])
    builders: list[Callable[[int], str]] = [
        functools.partial(_distinct_fill, index) for index in range(120)
    ]
    tracemalloc.start()
    try:
        next(_results(builders, 262144))
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 4_000_000, peak


def test_timed_probe_sets_are_the_unique_sets_every_stride_step_in_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[str, ...]] = []
    _record_probes_instead_of_timing(monkeypatch, seen)
    builders: list[Callable[[int], str]] = [
        functools.partial(_paired_fill, index // 2) for index in range(1400)
    ]
    list(_results(builders, 100))
    unique = [
        tuple(builders[position](size) for size in (50, 100))
        for position in range(0, 1400, 2)
    ]
    assert seen == unique[::2]


def test_probe_sets_built_again_after_the_memory_bound_equal_the_first_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[str, ...]] = []
    _record_probes_instead_of_timing(monkeypatch, seen)
    builders: list[Callable[[int], str]] = [
        functools.partial(_distinct_fill, index) for index in range(40)
    ]
    list(_results(builders, 262144))
    sizes = arbiter._REACH_PROBE_SIZES
    assert seen == [tuple(builder(size) for size in sizes) for builder in builders]
