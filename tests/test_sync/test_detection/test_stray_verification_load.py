import pytest

from guard_core.sync.detection_engine import _redos_stray_chooser as chooser
from guard_core.sync.detection_engine._redos_stray_chooser import (
    _build_stray_context,
    _first_bounded_forcing_candidate,
)

PROBES = [["xx", "xxxx", "xxxxxxxx"]]


def _verify(pattern: str = "ab") -> str | None:
    return _first_bounded_forcing_candidate(
        _build_stray_context(pattern, 0), ["\x00"], PROBES
    )


def test_a_slow_child_start_does_not_reject_a_safe_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slow_start = "import time\ntime.sleep(0.8)\n" + chooser._STRAY_VERIFY_CHILD_SCRIPT
    monkeypatch.setattr(chooser, "_STRAY_VERIFY_CHILD_SCRIPT", slow_start)

    assert _verify() == "\x00"


def test_a_child_that_burns_its_cpu_budget_is_rejected_quickly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spin = (
        chooser._STRAY_VERIFY_CHILD_SCRIPT.split("pattern, flags")[0]
        + "while True:\n    pass\n"
    )
    monkeypatch.setattr(chooser, "_STRAY_VERIFY_CHILD_SCRIPT", spin)

    with pytest.raises(TimeoutError, match="CPU budget"):
        _verify()


def test_a_catastrophic_pattern_is_still_rejected() -> None:
    context = _build_stray_context(r"(a+)+$", 0)
    probes = [["a" * 40 + "\x00"] * 3]

    with pytest.raises(TimeoutError):
        _first_bounded_forcing_candidate(context, ["\x00"], probes)
