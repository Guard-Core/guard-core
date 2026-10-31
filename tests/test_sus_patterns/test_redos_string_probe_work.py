import re

import pytest

from guard_core.detection_engine import _redos_cost_arbiter as arbiter

_QUADRATIC_PATTERN = r"\d+/"
_QUADRATIC_STRING = "1" * 12000
_ONE_BILLION_INSTRUCTIONS = (
    "def build_work_counter():\n    return lambda compiled, probe: 10**9\n"
)
_NO_INSTRUCTIONS = "def build_work_counter():\n    return lambda compiled, probe: 0\n"
_NO_COUNTER = "def build_work_counter():\n    return None\n"


def _run_with_counter(
    monkeypatch: pytest.MonkeyPatch, counter_source: str, pattern: str, string: str
) -> tuple[bool, str]:
    monkeypatch.setattr(
        arbiter,
        "_PATTERN_SAFETY_PROBE_CHILD_SCRIPT",
        arbiter._pattern_safety_probe_child_script(counter_source),
    )
    return arbiter._run_pattern_safety_probe_subprocess(pattern, [string], re.I)


def test_a_string_over_the_work_budget_is_refused_whatever_the_clock_says(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    safe, reason = _run_with_counter(
        monkeypatch, _ONE_BILLION_INSTRUCTIONS, "abc", "abc"
    )
    assert safe is False
    assert reason == "Pattern timed out on test string of length 3"


def test_a_string_under_the_work_budget_is_accepted_however_long_it_takes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    safe, reason = _run_with_counter(
        monkeypatch, _NO_INSTRUCTIONS, _QUADRATIC_PATTERN, _QUADRATIC_STRING
    )
    assert safe is True, reason


def test_a_host_without_a_counter_still_refuses_a_slow_string_by_cpu_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    safe, reason = _run_with_counter(
        monkeypatch, _NO_COUNTER, _QUADRATIC_PATTERN, _QUADRATIC_STRING
    )
    assert safe is False
    assert reason == "Pattern timed out on test string of length 12000"
