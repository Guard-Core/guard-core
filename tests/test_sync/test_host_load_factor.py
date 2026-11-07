from collections.abc import Callable

import pytest

from tests import host_load_factor as module


@pytest.mark.parametrize(
    ("scan_seconds", "expected"),
    [
        (0.0001, 1.0),
        (module._REFERENCE_SCAN_SECONDS, 1.0),
        (module._REFERENCE_SCAN_SECONDS * 2.9, 2.9),
        (module._REFERENCE_SCAN_SECONDS * 100, module._LOAD_FACTOR_CEILING),
    ],
)
def test_the_local_load_factor_never_relaxes_below_the_nominal_budget(
    monkeypatch: pytest.MonkeyPatch, scan_seconds: float, expected: float
) -> None:
    monkeypatch.setattr(module, "_reference_scan_seconds", lambda: scan_seconds)
    assert module.local_load_factor() == pytest.approx(expected)


def test_the_reference_scan_reports_the_fastest_of_its_samples(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    readings = iter([0.0, 0.004, 1.0, 1.0025, 2.0, 2.003])
    monkeypatch.setattr(module.time, "process_time", lambda: next(readings))
    assert module._reference_scan_seconds() == pytest.approx(0.0025)


def test_a_sample_is_divided_by_the_load_factor_measured_just_before_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(module, "_fastest_factor", float("inf"))
    order: list[str] = []

    def factor() -> float:
        order.append("factor")
        return 2.0

    def run() -> str:
        order.append("run")
        return "done"

    monkeypatch.setattr(module, "local_load_factor", factor)
    readings = iter([10.0, 10.5])
    monkeypatch.setattr(module.time, "process_time", lambda: next(readings))
    assert module.timed_normalized(run) == ("done", 0.25)
    assert order == ["factor", "run"]


def test_a_slower_reading_never_raises_the_factor_of_a_later_sample(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(module, "_fastest_factor", float("inf"))
    factors = iter([2.0, 4.0, 1.5])
    monkeypatch.setattr(module, "local_load_factor", lambda: next(factors))
    readings = iter([0.0, 1.0, 0.0, 1.0, 0.0, 1.0])
    monkeypatch.setattr(module.time, "process_time", lambda: next(readings))
    seconds = [module.timed_normalized(lambda: None)[1] for _ in range(3)]
    assert seconds == [pytest.approx(0.5), pytest.approx(0.5), pytest.approx(1 / 1.5)]


def test_the_minimum_over_interleaved_rounds_absorbs_a_slow_stretch_at_one_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(module, "_fastest_factor", float("inf"))
    monkeypatch.setattr(module, "local_load_factor", lambda: 1.0)
    # Round 0 runs sizes 0, 1; round 1 runs 1, 0; the first round is slow at size 1.
    durations = iter([1.0, 4.0, 2.0, 1.0])
    clock = [0.0]

    def tick() -> float:
        return clock[0]

    def run() -> None:
        clock[0] += next(durations)

    monkeypatch.setattr(module.time, "process_time", tick)
    assert module.minimum_normalized([run, run], rounds=2) == [
        pytest.approx(1.0),
        pytest.approx(2.0),
    ]


def test_the_minimum_still_shows_work_that_grows_faster_than_the_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(module, "_fastest_factor", float("inf"))
    monkeypatch.setattr(module, "local_load_factor", lambda: 1.0)
    clock = [0.0]
    monkeypatch.setattr(module.time, "process_time", lambda: clock[0])

    def quadratic(size: int) -> Callable[[], None]:
        def run() -> None:
            clock[0] += size * size / 1e9

        return run

    sizes = (16384, 32768, 65536, 131072)
    lowest = module.minimum_normalized([quadratic(size) for size in sizes], rounds=9)
    assert lowest[-1] >= max(0.01, lowest[-2] * 3)
