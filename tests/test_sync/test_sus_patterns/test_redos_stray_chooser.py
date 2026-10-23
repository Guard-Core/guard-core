import re
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from guard_core.sync.detection_engine._redos_class_intersection import (
    _class_intersection_probe_units,
)
from guard_core.sync.detection_engine._redos_intervals import _IntervalSet
from guard_core.sync.detection_engine._redos_parse_slots import (
    _PairingAtom,
    _pattern_slots,
)
from guard_core.sync.detection_engine._redos_stray_chooser import (
    _REACH_PROBE_STRAY_BYTE,
    _build_stray_context,
    _choose_stray,
    _class_intersection_probe_forces_failure,
    _class_intersection_stray_candidates,
    _dedup_capped_candidates,
    _leading_literal_prefix,
    _pattern_class_union,
    _repeat_probe_to_length,
    _stray_for_pair,
    _unwrap_leading_transparent_group,
    choose_class_intersection_stray,
    choose_repeat_unit_stray,
)
from guard_core.sync.detection_engine.compiler import PatternCompiler


def test_choose_intersection_stray_tail_complement_beats_nul_for_narrow_tail() -> None:
    pattern = r"\s*[\s\S]+[\x00-\x08]"
    flags = re.IGNORECASE | re.MULTILINE
    slots = _pattern_slots(pattern, flags)
    assert slots is not None
    left, middle, tail_atom = slots
    assert isinstance(left, _PairingAtom)
    assert isinstance(middle, _PairingAtom)
    assert isinstance(tail_atom, _PairingAtom)
    fill_member = left.intervals.intersection(middle.intervals).first_member()
    assert fill_member is not None
    fill_char = chr(fill_member)
    ctx = _build_stray_context(pattern, flags)
    stray = choose_class_intersection_stray(
        ctx, fill_char, left.intervals, middle.intervals, [tail_atom.intervals]
    )
    assert stray != "\x00"
    compiled = re.compile(pattern, flags)
    assert compiled.search(fill_char * 50 + stray) is None


def test_choose_intersection_stray_universal_right_fails_the_literal_tail() -> None:
    pattern = r"a*[\s\S]+X"
    slots = _pattern_slots(pattern, 0)
    assert slots is not None
    left, right, tail_atom = slots
    assert isinstance(left, _PairingAtom)
    assert isinstance(right, _PairingAtom)
    assert isinstance(tail_atom, _PairingAtom)
    ctx = _build_stray_context(pattern, 0)
    stray = choose_class_intersection_stray(
        ctx, "a", left.intervals, right.intervals, [tail_atom.intervals]
    )
    assert stray != "X"
    compiled = re.compile(pattern, 0)
    assert compiled.search("a" * 50 + stray) is None


def test_choose_intersection_stray_falls_back_when_unforceable() -> None:
    pattern = r"[\x00-\xff]*[\x00-\xfe]+"
    units_first = _class_intersection_probe_units(pattern, 0)
    units_second = _class_intersection_probe_units(pattern, 0)
    assert units_first
    assert units_first == units_second
    _fill, stray = units_first[0]
    left = _IntervalSet.from_range(0, 0xFF)
    right = _IntervalSet.from_range(0, 0xFE)
    assert stray == _stray_for_pair(left, right)


def test_choose_stray_returns_the_first_verified_candidate() -> None:
    assert _choose_stray(["a", "b", "c"], lambda c: c == "b", fallback="z") == "b"


def test_choose_stray_returns_the_fallback_when_nothing_verifies() -> None:
    assert _choose_stray(["a", "b"], lambda _c: False, fallback="z") == "z"


def test_dedup_capped_candidates_skips_none_and_duplicates() -> None:
    assert _dedup_capped_candidates(["a", None, "b", "a"]) == ["a", "b"]


def test_dedup_capped_candidates_stops_at_the_cap() -> None:
    candidates = [chr(ord("a") + i) for i in range(20)]
    result = _dedup_capped_candidates(candidates)
    assert result == candidates[:16]


def test_class_intersection_stray_candidates_orders_tail_before_fallback_list() -> None:
    tail = [_IntervalSet.from_range(0, 8)]
    universal = _IntervalSet.full()
    candidates = _class_intersection_stray_candidates(
        tail, universal, universal, universal
    )
    assert candidates[0] == "\t"
    assert candidates[-1] == "/"
    assert len(candidates) == 16


def test_class_intersection_probe_forces_failure_true_when_probe_never_matches() -> (
    None
):
    ctx = _build_stray_context(r"^a+$", 0)
    assert _class_intersection_probe_forces_failure(ctx, "a", "\x00") is True


def test_class_intersection_probe_forces_failure_false_when_probe_matches() -> None:
    ctx = _build_stray_context(r"a+", 0)
    assert _class_intersection_probe_forces_failure(ctx, "a", "a") is False


def test_choose_repeat_unit_stray_returns_default_stray_byte_for_empty_unit() -> None:
    ctx = _build_stray_context(r"a+", 0)
    assert choose_repeat_unit_stray(ctx, "") == _REACH_PROBE_STRAY_BYTE


def test_choose_repeat_unit_stray_picks_a_forcing_candidate_when_available() -> None:
    pattern = r"^a+$"
    ctx = _build_stray_context(pattern, 0)
    stray = choose_repeat_unit_stray(ctx, "a")
    compiled = re.compile(pattern, 0)
    assert compiled.search(_repeat_probe_to_length("a", 24, stray)) is None


def test_choose_repeat_unit_stray_falls_back_to_nul_when_unforceable() -> None:
    ctx = _build_stray_context(r"[\s\S]*", 0)
    assert choose_repeat_unit_stray(ctx, "a") == _REACH_PROBE_STRAY_BYTE


@pytest.mark.parametrize(
    "side_effect,returncode,stdout",
    [
        (subprocess.TimeoutExpired(["python"], 0.5), None, None),
        (OSError("no forkable subprocess slot"), None, None),
        (None, 1, ""),
        (None, 0, "not json"),
        (None, 0, '"unrequested candidate"'),
    ],
)
def test_choose_repeat_unit_stray_fails_closed_when_verification_is_unavailable(
    side_effect: Exception | None, returncode: int | None, stdout: str | None
) -> None:
    ctx = _build_stray_context(r"^a+$", 0)
    completed = MagicMock(returncode=returncode, stdout=stdout)
    with patch(
        "guard_core.sync.detection_engine._redos_stray_chooser.subprocess.run",
        side_effect=side_effect,
        return_value=completed,
    ):
        with pytest.raises(TimeoutError, match="stray verification"):
            choose_repeat_unit_stray(ctx, "a")


def test_choose_repeat_unit_stray_accepts_verified_unforceable_result() -> None:
    ctx = _build_stray_context(r"[\s\S]*", 0)
    completed = MagicMock(returncode=0, stdout="null")
    with patch(
        "guard_core.sync.detection_engine._redos_stray_chooser.subprocess.run",
        return_value=completed,
    ):
        assert choose_repeat_unit_stray(ctx, "a") == _REACH_PROBE_STRAY_BYTE


def test_pattern_class_union_collects_nested_group_intervals_and_skips_boundaries() -> (
    None
):
    union = _pattern_class_union(r"^a(b|c)\1", 0)
    assert union.contains(ord("a")) is True
    assert union.contains(ord("b")) is True
    assert union.contains(ord("c")) is True
    assert union.contains(ord("d")) is False


def test_pattern_class_union_returns_empty_for_an_unparsable_pattern() -> None:
    assert _pattern_class_union(r"[unterminated", 0) == _IntervalSet.empty()


def test_unwrap_leading_transparent_group_breaks_when_group_not_at_end() -> None:
    assert _unwrap_leading_transparent_group(r"(?:abc)def") == "(?:abc)def"


def test_unwrap_leading_transparent_group_returns_text_unchanged_without_a_group() -> (
    None
):
    assert _unwrap_leading_transparent_group("abc") == "abc"


def test_leading_literal_prefix_empty_when_unwrapped_text_is_empty() -> None:
    assert _leading_literal_prefix(r"(?:)") == ""


_STRAY_CHOOSER_TIMING_REJECT_PATTERNS: tuple[str, ...] = (
    r"\s*[\s\S]+[\x00-\x08]",
    r"\s*[\s\S]+--",
    r"\s*[\s\S]+\t",
    r"\s*[\s\S]+[^\x00-\x08]",
)

_STRAY_CHOOSER_TIMING_ACCEPT_PATTERNS: tuple[str, ...] = (r"^\s*[\s\S]+$",)


@pytest.mark.redos_timing
@pytest.mark.parametrize("pattern", _STRAY_CHOOSER_TIMING_REJECT_PATTERNS)
def test_validate_pattern_safety_rejects_stray_chooser_forcing_patterns(
    pattern: str,
) -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(pattern)
    assert is_safe is False, f"{pattern!r} was accepted: {reason}"


@pytest.mark.redos_timing
@pytest.mark.parametrize("pattern", _STRAY_CHOOSER_TIMING_ACCEPT_PATTERNS)
def test_validate_pattern_safety_accepts_stray_chooser_safe_patterns(
    pattern: str,
) -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(pattern)
    assert is_safe is True, f"{pattern!r} was rejected: {reason}"
