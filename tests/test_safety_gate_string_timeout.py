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
