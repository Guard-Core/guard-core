import time

import pytest

from guard_core.sync.detection_engine._redos_class_intersection import (
    _class_intersection_probe_units,
    _include_bounded_repeats,
)
from guard_core.sync.detection_engine._redos_parse_slots import (
    _NonPairingSlot,
    _PairingAtom,
    _pattern_slots,
)
from guard_core.sync.detection_engine._redos_reach_probe import (
    _reach_symbol_quantifier_range,
    _synthesize_reaching_probe,
)
from guard_core.sync.detection_engine._redos_stray_chooser import (
    _build_stray_context,
    _pattern_complement_chars,
    _stray_verification_timeout,
)


def test_reach_symbol_question_quantifier_uses_single_repeat() -> None:
    assert _reach_symbol_quantifier_range("a?", 1, "?") == (0, 1, 2)


def test_reach_probe_synthesizes_a_dot_atom() -> None:
    assert _synthesize_reaching_probe(".") == "a\x01"


def test_class_intersection_includes_finite_repeats() -> None:
    assert _class_intersection_probe_units("a{2}a+", 0, include_bounded=True) == [
        ("a", "\x00")
    ]


def test_class_intersection_marks_nested_finite_repeats_as_repeating() -> None:
    slots = _pattern_slots(r"(a{2}){2}", 0)
    assert slots is not None
    assert isinstance(slots[0], _NonPairingSlot)
    assert slots[0].inner is not None
    nested = _include_bounded_repeats(slots)
    assert isinstance(nested[0], _NonPairingSlot)
    assert nested[0].unbounded is True
    inner = nested[0].inner
    assert inner is not None
    assert isinstance(inner[0][0], _PairingAtom)
    assert inner[0][0].unbounded is True


def test_pattern_complement_chars_fails_closed_for_unparsable_pattern() -> None:
    assert _pattern_complement_chars("[unterminated", 0) == []


def test_pattern_complement_chars_deduplicates_nested_class_complements() -> None:
    assert _pattern_complement_chars(r"(?:[a-z]|[0-9])", 0) == ["\x00"]


def test_stray_verification_timeout_rejects_an_expired_deadline() -> None:
    context = _build_stray_context("a", 0, time.thread_time() - 1.0)
    with pytest.raises(TimeoutError, match="probe construction"):
        _stray_verification_timeout(context)
