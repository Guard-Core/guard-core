import time
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from guard_core.detection_engine import _redos_cost_arbiter as arbiter
from guard_core.detection_engine import (
    _redos_repeat_alphabet,
    _redos_repeat_prefix,
    _redos_stray_chooser,
)
from guard_core.detection_engine.compiler import PatternCompiler

_PATTERN_WITH_AN_ALPHABET_TO_BUILD = r"[\s\S]+[^☃]"
_SECONDS_THE_RUN_QUEUE_KEEPS_CONSTRUCTION_WAITING = 100.0
_SECONDS_THE_PROBE_CHILD_WAITS_FOR_ITS_FIRST_SLICE = 3.0


def _wall_clock_jumps_while_construction_waits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skew = [0.0]
    real_monotonic = time.monotonic
    clock = SimpleNamespace(
        monotonic=lambda: real_monotonic() + skew[0], thread_time=time.thread_time
    )
    for module in (
        arbiter,
        _redos_repeat_alphabet,
        _redos_repeat_prefix,
        _redos_stray_chooser,
    ):
        monkeypatch.setattr(module, "time", clock)
    build_probes = arbiter._reach_probe_candidate_builders

    def wait_then_build(
        pattern: str, flags: int, deadline: float | None = None
    ) -> list[Callable[[int], str]]:
        skew[0] += _SECONDS_THE_RUN_QUEUE_KEEPS_CONSTRUCTION_WAITING
        return build_probes(pattern, flags, deadline)

    monkeypatch.setattr(arbiter, "_reach_probe_candidate_builders", wait_then_build)


@pytest.mark.redos_timing
def test_validator_does_not_refuse_when_the_run_queue_eats_the_construction_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _wall_clock_jumps_while_construction_waits(monkeypatch)
    is_safe, reason = PatternCompiler().validate_pattern_safety(
        _PATTERN_WITH_AN_ALPHABET_TO_BUILD, max_content_length=512
    )
    assert "exceeded its deadline" not in reason, reason


def test_probe_with_test_strings_does_not_refuse_a_child_that_waits_for_its_first_slice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        arbiter,
        "_PATTERN_SAFETY_PROBE_CHILD_SCRIPT",
        "import time\n"
        f"time.sleep({_SECONDS_THE_PROBE_CHILD_WAITS_FOR_ITS_FIRST_SLICE})\n"
        + arbiter._PATTERN_SAFETY_PROBE_CHILD_SCRIPT,
    )
    is_safe, reason = PatternCompiler().validate_pattern_safety(
        r"abc", test_strings=["abc"]
    )
    assert is_safe is True, reason
