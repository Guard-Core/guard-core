from types import SimpleNamespace

import generate_safety_gates
import pytest

_CASE = {
    "pattern": generate_safety_gates.STRING_TIMEOUT_PATTERN,
    "test_strings": [generate_safety_gates.STRING_TIMEOUT_TEST_STRING],
}
_ONE_BILLION_INSTRUCTIONS = (
    "def build_work_counter():\n    return lambda compiled, probe: 10**9\n"
)
_NO_COUNTER = "def build_work_counter():\n    return None\n"


def test_a_counted_cost_is_judged_against_the_counted_margin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        generate_safety_gates, "WORK_COUNTER_SOURCE", _ONE_BILLION_INSTRUCTIONS
    )
    cost, margin = generate_safety_gates._string_timeout_cost_seconds(_CASE)
    assert cost == pytest.approx(10**9 * generate_safety_gates.WORK_UNIT_SECONDS)
    assert margin == generate_safety_gates.STRING_TIMEOUT_COUNTED_MARGIN


def test_a_timed_cost_is_judged_against_the_clock_margin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(generate_safety_gates, "WORK_COUNTER_SOURCE", _NO_COUNTER)
    cost, margin = generate_safety_gates._string_timeout_cost_seconds(_CASE)
    assert cost > generate_safety_gates.PROBE_THRESHOLD_SECONDS
    assert margin == generate_safety_gates.STRING_TIMEOUT_MARGIN


def test_the_counted_margin_covers_the_measured_cost_on_python_3_14() -> None:
    over_on_python_3_14 = 0.158 / generate_safety_gates.PROBE_THRESHOLD_SECONDS
    assert over_on_python_3_14 >= generate_safety_gates.STRING_TIMEOUT_COUNTED_MARGIN
    assert generate_safety_gates.STRING_TIMEOUT_COUNTED_MARGIN > 1.0


def test_the_clock_margin_covers_the_cpu_time_of_the_case_on_both_pythons() -> None:
    for cpu_seconds in (0.122, 0.142, 0.295, 0.302):
        over = cpu_seconds / generate_safety_gates.PROBE_THRESHOLD_SECONDS
        under = generate_safety_gates.PROBE_KILL_SECONDS / cpu_seconds
        assert min(over, under) >= generate_safety_gates.STRING_TIMEOUT_MARGIN


def _clock_reading(seconds: float) -> SimpleNamespace:
    readings = iter((0.0, seconds))
    return SimpleNamespace(process_time=lambda: next(readings))


def test_a_slow_core_reading_is_judged_by_the_work_it_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Python 3.10 read 1.10 s of CPU for the case on an efficiency core (LEDGER 6.472),
    # 1.8x under the 2.0 s kill; the reference scan ran 4x slower there too.
    monkeypatch.setattr(generate_safety_gates, "WORK_COUNTER_SOURCE", _NO_COUNTER)
    monkeypatch.setattr(
        generate_safety_gates,
        "_reference_scan_seconds",
        lambda: 4 * generate_safety_gates._REFERENCE_SCAN_SECONDS,
        raising=False,
    )
    monkeypatch.setattr(generate_safety_gates, "time", _clock_reading(1.10))
    fixed = next(
        case
        for case in generate_safety_gates.FIXED_CASES
        if case["reason_class"] == "probe_string_timeout"
    )
    reference = generate_safety_gates._fixed_reference(fixed, "")
    assert reference["observed_cpu_seconds"] == pytest.approx(0.275)


def test_a_host_faster_than_the_calibration_never_inflates_the_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(generate_safety_gates, "WORK_COUNTER_SOURCE", _NO_COUNTER)
    monkeypatch.setattr(
        generate_safety_gates,
        "_reference_scan_seconds",
        lambda: generate_safety_gates._REFERENCE_SCAN_SECONDS / 4,
        raising=False,
    )
    monkeypatch.setattr(generate_safety_gates, "time", _clock_reading(0.125))
    cost, _margin = generate_safety_gates._string_timeout_cost_seconds(_CASE)
    assert cost == pytest.approx(0.125)
