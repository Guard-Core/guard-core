import itertools
import json
import logging
import re
import signal
import time
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.sync.detection_engine._redos_ambiguous_tail import _atom_char_set
from guard_core.sync.detection_engine._redos_class_intersection import (
    _advance_pairing_chain,
    _append_pairing_unit,
    _class_intersection_fills,
    _class_intersection_probe_units,
    _cross_non_pairing_slot,
    _fill_confirmed,
    _group_crossing_result,
    _left_confirms_fill,
    _pairing_units_from,
    _tail_pairing_intervals,
)
from guard_core.sync.detection_engine._redos_cost_arbiter import (
    _LOAD_FACTOR_CEILING,
    _LOAD_FACTOR_FLOOR,
    _PATTERN_SAFETY_DEFAULT_CAP,
    _REACH_PROBE_COMBINED_TIMEOUT_SECONDS,
    _REACH_PROBE_DEADLINE_SCALE_CEILING_SECONDS,
    _REACH_PROBE_LARGE_SAMPLE_SECONDS,
    _REACH_PROBE_SAMPLE_COUNT,
    _REACH_PROBE_SIZES,
    _REFERENCE_SCAN_SECONDS,
    ReachProbeTiming,
    _clipped_timeout,
    _first_over_budget_reason,
    _load_factor,
    _measure_host_load_factor,
    _median,
    _parse_reach_probe_child_output,
    _reach_probe_cost_reason,
    _reach_probe_cost_verdict,
    _reach_probe_timing_child_script,
    _reach_probe_timing_strategy,
    _reach_probe_unreachable_reason,
    _reach_probe_verdict_from_samples,
    _remaining_budget,
    _scaled_probe_deadline_seconds,
    _stride_sampled_probe_sets,
    _time_reach_probes_ascending,
    _time_reach_probes_subprocess,
    _time_single_reach_probe_subprocess,
)
from guard_core.sync.detection_engine._redos_cpu_budget import ReachProbeCpuBudget
from guard_core.sync.detection_engine._redos_exact_state import (
    _exact_overlap_fill_raw,
    _isolated_alternative_exact_state,
    _isolated_group_exact_state,
    _narrow_exact_state_raw,
)
from guard_core.sync.detection_engine._redos_intervals import _IntervalSet
from guard_core.sync.detection_engine._redos_parse_slots import (
    _ATOMIC_GROUP,
    _atomic_group_body_and_flags,
    _category_intervals,
    _class_node_predicate,
    _node_intervals,
    _NonPairingSlot,
    _PairingAtom,
    _pattern_slots,
    _regex_parser,
)
from guard_core.sync.detection_engine._redos_probe_fill import (
    _fill_to_length,
    _leading_literal_prefix,
    _reach_probe_candidate_builders,
    _repeat_probe_to_length,
)
from guard_core.sync.detection_engine._redos_stray_chooser import (
    _build_stray_context,
    _stray_for_pair,
)
from guard_core.sync.detection_engine.compiler import PatternCompiler
from guard_core.sync.handlers._suspatterns_sources import _SQLI_COMMENT_TERMINATOR_RE

_EVENT_HANDLER_PATTERN = (
    r"(?:<[^<>]*(?<!=)(?<!=\")(?<!=')[\s/]+on\w+\s*="
    r"(?:[\"'][^\"']*[\"']|[^\s>]+))"
)

_NEAR_BUDGET_SQLI_BUILTIN_PATTERN = (
    r"(?i)(?:\/\*![0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP"
    r"|CONCAT|CHAR|UPDATE)\b)"
)
_NEAR_BUDGET_SQLI_BUILTIN_PROBE = "/*!" + "0" * 31997


def _ample_budget() -> ReachProbeCpuBudget:
    return ReachProbeCpuBudget(30.0)


def _fake_popen(returncode: int, stdout: str) -> MagicMock:
    process = MagicMock()
    process.returncode = returncode
    process.communicate.return_value = (stdout, "")
    return MagicMock(return_value=process)


def _timing(
    samples_by_size: list[list[float]], load_factor: float = 1.0
) -> ReachProbeTiming:
    return ReachProbeTiming(samples_by_size, load_factor)


def test_pattern_slots_marks_a_capturing_group_as_a_boundary_slot() -> None:
    slots = _pattern_slots(r"[^<>]*(x)[\s/]+", 0)
    not_lt_gt = (
        _IntervalSet.full()
        .difference(_IntervalSet.single(ord("<")))
        .difference(_IntervalSet.single(ord(">")))
    )
    slash_or_space = _category_intervals(_regex_parser.CATEGORY_SPACE, 0).union(
        _IntervalSet.single(ord("/"))
    )
    assert slots == [
        _PairingAtom(not_lt_gt, allows_zero=True, unbounded=True),
        _NonPairingSlot(
            is_boundary=True,
            inner=[
                [
                    _PairingAtom(
                        _IntervalSet.single(ord("x")),
                        allows_zero=False,
                        unbounded=False,
                    )
                ]
            ],
        ),
        _PairingAtom(slash_or_space, allows_zero=False, unbounded=True),
    ]


def test_pattern_slots_returns_none_when_the_pattern_fails_to_parse() -> None:
    assert _pattern_slots(r"[unterminated", 0) is None
    assert _class_intersection_probe_units(r"[unterminated", 0) == []


def test_pattern_slots_treats_a_bare_negation_as_a_not_literal_pairing_atom() -> None:
    slots = _pattern_slots(r"[^a]", 0)
    expected = _IntervalSet.full().difference(_IntervalSet.single(ord("a")))
    assert slots == [_PairingAtom(expected, allows_zero=False, unbounded=False)]


def test_pattern_slots_widens_any_to_the_full_alphabet_under_dotall() -> None:
    dotall_slots = _pattern_slots(r"(?s).", 0)
    plain_slots = _pattern_slots(r".", 0)
    assert dotall_slots == [
        _PairingAtom(_IntervalSet.full(), allows_zero=False, unbounded=False)
    ]
    assert plain_slots == [
        _PairingAtom(
            _IntervalSet.full().difference(_IntervalSet.single(ord("\n"))),
            allows_zero=False,
            unbounded=False,
        )
    ]


def test_pattern_slots_treats_a_backreference_as_a_hard_boundary() -> None:
    slots = _pattern_slots(r"(a)\1", 0)
    assert slots is not None
    assert slots[1] == _NonPairingSlot(is_boundary=True, inner=None)


def test_class_intersection_fills_crosses_a_multi_slot_transparent_group() -> None:
    fills = _class_intersection_fills(r"'\s*(?:\d*(?!y)(z))+\s*--", 0)
    assert fills == []


def test_class_intersection_fills_stops_crossing_at_a_nested_backreference() -> None:
    fills = _class_intersection_fills(r"'\s*(?:(\s)\1z)+\s*--", 0)
    assert fills == []


def test_category_intervals_falls_back_to_the_full_range_for_an_unmapped_category() -> (
    None
):
    assert _category_intervals(object(), 0) == _IntervalSet.full()


def test_node_intervals_handles_a_bare_category_op_directly() -> None:
    intervals = _node_intervals(_regex_parser.CATEGORY, _regex_parser.CATEGORY_DIGIT, 0)
    assert intervals == _category_intervals(_regex_parser.CATEGORY_DIGIT, 0)
    assert intervals.contains(ord("5")) is True
    assert intervals.contains(ord("x")) is False


def test_class_node_predicate_handles_a_bare_category_op_directly() -> None:
    predicate = _class_node_predicate(
        _regex_parser.CATEGORY, _regex_parser.CATEGORY_DIGIT, 0
    )
    assert predicate(ord("5")) is True
    assert predicate(ord("x")) is False


def test_group_crossing_result_rejects_past_the_max_depth() -> None:
    atom = _PairingAtom(
        _IntervalSet.single(ord("a")), allows_zero=False, unbounded=False
    )
    alternatives: list[list[Any]] = [[atom]]
    assert (
        _group_crossing_result(alternatives, _IntervalSet.single(ord("a")), 999) is None
    )


def test_pairing_units_from_returns_empty_when_the_start_slot_is_not_pairing() -> None:
    slots: list[Any] = [_NonPairingSlot(is_boundary=True, inner=None)]
    ctx = _build_stray_context("a*z", 0)
    assert _pairing_units_from(slots, 0, ctx) == []


def test_tail_pairing_intervals_collects_only_pairing_atoms_from_start() -> None:
    slots = _pattern_slots(r"a[b]c(d)", 0)
    assert slots is not None
    tail = _tail_pairing_intervals(slots, 1)
    assert tail == [
        _IntervalSet.single(ord("b")),
        _IntervalSet.single(ord("c")),
    ]


def test_tail_pairing_intervals_returns_empty_past_the_end_of_the_slots() -> None:
    slots = _pattern_slots(r"a", 0)
    assert slots is not None
    assert _tail_pairing_intervals(slots, len(slots)) == []


def test_pairing_atom_eq_returns_notimplemented_for_a_non_pairing_atom() -> None:
    atom = _PairingAtom(
        _IntervalSet.single(ord("a")), allows_zero=False, unbounded=False
    )
    other = _NonPairingSlot(is_boundary=True, inner=None)
    assert atom.__eq__(other) is NotImplemented
    assert atom != other


def test_fill_confirmed_returns_true_when_either_predicate_is_missing() -> None:
    with_predicate = _PairingAtom(
        _IntervalSet.single(ord("a")),
        allows_zero=False,
        unbounded=False,
        predicate=lambda code_point: True,
    )
    without_predicate = _PairingAtom(
        _IntervalSet.single(ord("a")), allows_zero=False, unbounded=False
    )
    assert _fill_confirmed(with_predicate, without_predicate, "a") is True
    assert _fill_confirmed(without_predicate, with_predicate, "a") is True


def test_fill_confirmed_rejects_a_predicate_disagreement() -> None:
    always_false = _PairingAtom(
        _IntervalSet.single(ord("a")),
        allows_zero=False,
        unbounded=False,
        predicate=lambda code_point: False,
    )
    always_true = _PairingAtom(
        _IntervalSet.single(ord("a")),
        allows_zero=False,
        unbounded=False,
        predicate=lambda code_point: True,
    )
    assert _fill_confirmed(always_false, always_true, "a") is False


def test_left_confirms_fill_returns_true_when_predicate_is_missing() -> None:
    atom = _PairingAtom(
        _IntervalSet.single(ord("a")), allows_zero=False, unbounded=False
    )
    assert _left_confirms_fill(atom, "a") is True


def test_left_confirms_fill_rejects_a_predicate_disagreement() -> None:
    always_false = _PairingAtom(
        _IntervalSet.single(ord("a")),
        allows_zero=False,
        unbounded=False,
        predicate=lambda code_point: False,
    )
    assert _left_confirms_fill(always_false, "a") is False


def test_pairing_atom_hash_ignores_the_predicate() -> None:
    intervals = _IntervalSet.single(ord("a"))
    with_predicate = _PairingAtom(
        intervals,
        allows_zero=False,
        unbounded=False,
        predicate=lambda code_point: True,
    )
    without_predicate = _PairingAtom(intervals, allows_zero=False, unbounded=False)
    assert hash(with_predicate) == hash(without_predicate)
    assert with_predicate == without_predicate


def test_atomic_group_body_and_flags_returns_the_body_and_flags_unchanged() -> None:
    body: list[Any] = [(_regex_parser.LITERAL, ord("a"))]
    assert _atomic_group_body_and_flags(body, re.IGNORECASE) == (body, re.IGNORECASE)


@pytest.mark.skipif(
    _ATOMIC_GROUP is None,
    reason="atomic groups require re._parser (Python 3.11+)",
)
def test_pattern_slots_treats_an_atomic_group_as_a_group_slot() -> None:
    slots = _pattern_slots(r"(?>a)+", 0)
    assert slots == [
        _NonPairingSlot(
            is_boundary=True,
            inner=[
                [
                    _PairingAtom(
                        _IntervalSet.single(ord("a")),
                        allows_zero=False,
                        unbounded=False,
                    )
                ]
            ],
            unbounded=True,
        )
    ]


def test_class_intersection_fills_finds_space_or_slash_for_event_handler() -> None:
    fills = _class_intersection_fills(_EVENT_HANDLER_PATTERN, 0)
    assert fills
    assert all(c in " \t\n\r\x0b\x0c/" for c in fills)


def test_class_intersection_fills_ignores_disjoint_adjacent_classes() -> None:
    assert _class_intersection_fills(r"[a-c]+[x-z]+", 0) == []


def test_class_intersection_fills_skips_pairs_across_alternation_boundary() -> None:
    assert _class_intersection_fills(r"[a-z]+|[a-z]+", 0) == []


def test_class_intersection_fills_pairs_across_an_empty_capable_middle_atom() -> None:
    fills = _class_intersection_fills(r"'\s*[\);]*\s*--", 0)
    assert fills == [sorted(_atom_char_set(r"\s"))[0]]


def test_class_intersection_fills_does_not_pair_across_a_mandatory_middle_atom() -> (
    None
):
    assert _class_intersection_fills(r"\s*[\);]+\s*", 0) == []


def test_class_intersection_fills_pairs_across_a_zero_admitting_group_middle() -> None:
    assert _class_intersection_fills(r"'\s*(?:ab)*\s*--", 0) == [
        sorted(_atom_char_set(r"\s"))[0]
    ]


def test_class_intersection_fills_pairs_across_a_negative_lookahead_middle() -> None:
    assert _class_intersection_fills(r"'\s*(?!x)\s*--", 0) == [
        sorted(_atom_char_set(r"\s"))[0]
    ]


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_zero_admitting_group_and_lookahead_middles() -> None:
    compiler = PatternCompiler()
    for pattern in (r"'\s*(?:ab)*\s*--", r"'\s*(?!x)\s*--"):
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False, (
            f"expected {pattern!r} to be rejected once a zero-admitting group or "
            f"lookaround is crossed by the class-intersection walk, got safe="
            f"{is_safe} ({reason})"
        )


def test_class_intersection_fills_crosses_a_mandatory_group_of_overlapping_atoms() -> (
    None
):
    assert _class_intersection_fills(r"'\s*(\s+)\s*--", 0) == [
        sorted(_atom_char_set(r"\s"))[0]
    ]


def test_class_intersection_fills_crosses_group_with_one_crossable_alt() -> None:
    assert _class_intersection_fills(r"'\s*(?:\s+|,)\s*--", 0) == [
        sorted(_atom_char_set(r"\s"))[0]
    ]


def test_class_intersection_fills_emits_a_fill_for_an_unbounded_crossable_group() -> (
    None
):
    assert _class_intersection_fills(r"'\s*(?:\s+|,)+\s*--", 0)


def test_class_intersection_fills_skips_a_non_overlapping_mandatory_group() -> None:
    assert _class_intersection_fills(r"'\s*(?:AND|OR)\s*--", 0) == []


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_mandatory_group_crossed_by_overlapping_atoms() -> (
    None
):
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(r"'\s*(?:\s+)\s*--")
    assert is_safe is False, (
        "expected the mandatory group '(?:\\s+)' to be crossed by the surrounding "
        f"\\s* pair, got safe={is_safe} ({reason})"
    )


def test_class_intersection_fills_emits_a_fill_for_a_multi_char_alternation_group() -> (
    None
):
    fills = _class_intersection_fills(r"^[c-w]*(?:[g-z][g-z]|[g-z][g-z][g-z])*$", 0)
    assert fills == ["g"]


def test_class_intersection_fills_skips_a_non_crossable_multi_char_alternation() -> (
    None
):
    assert (
        _class_intersection_fills(r"^[a-f]*(?:[g-z][g-z]|[g-z][g-z][g-z])*$", 0) == []
    )


@pytest.mark.redos_timing
def test_compiler_rejects_unbounded_multi_char_alternation_zero_admitting_group() -> (
    None
):
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(
        r"^[c-w]*(?:[g-z][g-z]|[g-z][g-z][g-z])*$"
    )
    assert is_safe is False, (
        "expected the unbounded multi-character alternation group to be "
        f"crossed by the surrounding [c-w]* atom, got safe={is_safe} ({reason})"
    )
    assert "cost" in reason.lower() or "timeout" in reason.lower(), (
        f"expected a cost-arbiter rejection reason, got {reason!r}"
    )


def test_node_intervals_folds_not_literal_case_under_ignorecase() -> None:
    intervals = _node_intervals(_regex_parser.NOT_LITERAL, ord("a"), re.IGNORECASE)
    assert intervals.contains(ord("a")) is False
    assert intervals.contains(ord("A")) is False


def test_intersection_probe_units_no_fill_for_disjoint_case_sensitive_pair() -> None:
    assert _class_intersection_probe_units(r"[a-z]*[A-Z]+", 0) == []


def test_intersection_probe_units_fill_once_ignorecase_folds_the_pair() -> None:
    units = _class_intersection_probe_units(r"[a-z]*[A-Z]+", re.IGNORECASE)
    assert units
    fill, _stray = units[0]
    assert fill in "aA"


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_case_disjoint_pair_only_under_ignorecase() -> None:
    compiler = PatternCompiler()
    pattern = r"^[a-z]*[A-Z]+X$"
    is_safe_no_fold, reason_no_fold = compiler.validate_pattern_safety(pattern, flags=0)
    assert is_safe_no_fold is True, (
        f"expected the case-disjoint pair to be safe without IGNORECASE, got "
        f"safe={is_safe_no_fold} ({reason_no_fold})"
    )
    is_safe_folded, reason_folded = compiler.validate_pattern_safety(
        pattern, flags=re.IGNORECASE | re.MULTILINE
    )
    assert is_safe_folded is False, (
        "expected the pair to become crossable once IGNORECASE folds both "
        f"classes to overlap, got safe={is_safe_folded} ({reason_folded})"
    )
    assert "cost" in reason_folded.lower() or "timeout" in reason_folded.lower(), (
        f"expected a cost-arbiter rejection reason, got {reason_folded!r}"
    )


def test_class_intersection_probe_units_finds_a_latin1_fill() -> None:
    units = _class_intersection_probe_units(r"[a\x80-\xff]*[b\x80-\xff]+", 0)
    assert units
    fill, _stray = units[0]
    assert ord(fill) >= 0x80


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_latin1_only_overlap() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(r"^[a\x80-\xff]*[b\x80-\xff]+$")
    assert is_safe is False, (
        "expected the Latin-1-only overlap between the two classes to be "
        f"caught once the alphabet extends past code point 127, got "
        f"safe={is_safe} ({reason})"
    )
    assert "cost" in reason.lower() or "timeout" in reason.lower(), (
        f"expected a cost-arbiter rejection reason, got {reason!r}"
    )


def test_stray_for_pair_reaches_past_the_full_byte_range_when_it_is_all_excluded() -> (
    None
):
    left = _IntervalSet.from_range(0, 0xFF)
    right = _IntervalSet.from_range(0, 0xFE)
    stray = _stray_for_pair(left, right)
    assert ord(stray) >= 0x100
    assert left.contains(ord(stray)) is False
    assert right.contains(ord(stray)) is False


def test_stray_for_pair_falls_back_to_nul_when_the_union_is_the_full_range() -> None:
    assert _stray_for_pair(_IntervalSet.full(), _IntervalSet.full()) == "\x00"


def test_class_intersection_probe_units_finds_a_fill_for_the_full_byte_range() -> None:
    units = _class_intersection_probe_units(r"[\x00-\xff]*[\x00-\xfe]+", 0)
    assert units
    _fill, stray = units[0]
    assert ord(stray) >= 0x100


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_full_byte_range_class_intersection() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(r"^[\x00-\xff]*[\x00-\xfe]+$")
    assert is_safe is False, (
        "expected the full-byte-range overlap to be caught once the stray probe "
        f"byte reaches past code point 0xff, got safe={is_safe} ({reason})"
    )
    assert "cost" in reason.lower() or "timeout" in reason.lower(), (
        f"expected a cost-arbiter rejection reason, got {reason!r}"
    )


def test_pattern_compiler_accepts_universal_class_pair_with_no_possible_stray() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(r"[\s\S]*[\s\S]+$")
    assert is_safe is True, (
        "a fully universal class pair anchored at the end cannot be forced to "
        f"fail and must stay linear, got safe={is_safe} ({reason})"
    )


def test_class_intersection_probe_units_astral_gap_stray_is_a_real_forcing_point() -> (
    None
):
    pattern = r"[\x00-\U0001F600]*[\x00-\U0001F5FF]+"
    units = _class_intersection_probe_units(pattern, 0)
    assert units
    _fill, stray = units[0]
    slots = _pattern_slots(pattern, 0)
    assert slots is not None
    left, right = slots[0], slots[1]
    assert isinstance(left, _PairingAtom)
    assert isinstance(right, _PairingAtom)
    assert left.predicate is not None
    assert right.predicate is not None
    assert left.predicate(ord(stray)) is False
    assert right.predicate(ord(stray)) is False


def test_class_intersection_probe_units_finds_an_astral_only_overlap_fill() -> None:
    pattern = r"[\U0001F601-\U0001F700]*[\U0001F650-\U0001F800]+"
    units = _class_intersection_probe_units(pattern, 0)
    assert units
    fill, _stray = units[0]
    slots = _pattern_slots(pattern, 0)
    assert slots is not None
    left, right = slots[0], slots[1]
    assert isinstance(left, _PairingAtom)
    assert isinstance(right, _PairingAtom)
    assert left.predicate is not None
    assert right.predicate is not None
    assert left.predicate(ord(fill)) is True
    assert right.predicate(ord(fill)) is True


def test_class_intersection_probe_units_keeps_exact_state_across_an_optional_atom() -> (
    None
):
    pattern = r"[\U0001F601-\U0001F700]*\U0001F650?[\U0001F650-\U0001F800]+"
    units = _class_intersection_probe_units(pattern, 0)
    assert units
    fill, _stray = units[0]
    assert fill == "\U0001f650"


def test_class_intersection_probe_units_finds_a_fill_for_the_kelvin_sign_pair() -> None:
    pattern = r"[k]*[K]+"
    units = _class_intersection_probe_units(pattern, re.IGNORECASE)
    assert units
    fill, _stray = units[0]
    slots = _pattern_slots(pattern, re.IGNORECASE)
    assert slots is not None
    left, right = slots[0], slots[1]
    assert isinstance(left, _PairingAtom)
    assert isinstance(right, _PairingAtom)
    assert left.predicate is not None
    assert right.predicate is not None
    assert left.predicate(ord(fill)) is True
    assert right.predicate(ord(fill)) is True


def test_stray_for_pair_finds_an_exact_stray_beyond_the_fixed_alphabet() -> None:
    pattern = r"[^\U00050000][^\U00050000]"
    slots = _pattern_slots(pattern, 0)
    assert slots is not None
    left, right = slots[0], slots[1]
    assert isinstance(left, _PairingAtom)
    assert isinstance(right, _PairingAtom)
    stray = _stray_for_pair(left.intervals, right.intervals)
    assert ord(stray) == 0x50000


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_astral_gap_class_intersection() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(
        r"[\x00-\U0001F600]*[\x00-\U0001F5FF]+$"
    )
    assert is_safe is False, (
        "expected the astral-range class intersection to be rejected once the "
        f"stray probe reaches past the fixed alphabet, got safe={is_safe} ({reason})"
    )


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_astral_only_class_overlap() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(
        r"[\U0001F601-\U0001F700]*[\U0001F650-\U0001F800]+$"
    )
    assert is_safe is False, (
        "expected an overlap that exists only outside the fixed alphabet to be "
        f"detected via endpoint-derived candidates, got safe={is_safe} ({reason})"
    )


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_dotless_i_ignorecase_fold_overlap() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(r"(?i)[a-z]*\u0131+$")
    assert is_safe is False, (
        "expected the dotless-i literal to overlap [a-z] once the engine's real "
        f"IGNORECASE fold is used instead of str.lower/upper/casefold, got "
        f"safe={is_safe} ({reason})"
    )


@pytest.mark.redos_timing
def test_pattern_compiler_accepts_full_unicode_range_class_pair() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(
        r"[\x00-\U0010FFFF]*[\x00-\U0010FFFF]+$"
    )
    assert is_safe is True, (
        "a class pair covering the entire Unicode range anchored at the end "
        f"cannot be forced to fail and must stay linear, got safe={is_safe} "
        f"({reason})"
    )


_H1_ASTRAL_GROUP_CROSSING_PATTERN = (
    r"^[\U0001F900-\U0001FAA0a]*([\U0001F900-\U0001FAA0b])+$"
)
_H2_DIGIT_VERSUS_ASTRAL_RANGE_PATTERN = r"^\d*[\U00010000-\U0010FFFEz]+$"


def test_class_intersection_probe_units_crosses_a_group_via_astral_exact_state() -> (
    None
):
    units = _class_intersection_probe_units(_H1_ASTRAL_GROUP_CROSSING_PATTERN, 0)
    assert units
    fill, stray = units[0]
    assert re.fullmatch(r"[\U0001F900-\U0001FAA0a]", fill)
    assert re.fullmatch(r"[\U0001F900-\U0001FAA0b]", fill)
    assert re.fullmatch(r"[\U0001F900-\U0001FAA0a]", stray) is None
    assert re.fullmatch(r"[\U0001F900-\U0001FAA0b]", stray) is None


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_astral_group_crossing() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(
        _H1_ASTRAL_GROUP_CROSSING_PATTERN
    )
    assert is_safe is False, (
        "expected the exact astral state to survive the group crossing and "
        f"force a class-intersection unit, got safe={is_safe} ({reason})"
    )


def test_class_intersection_probe_units_finds_digit_versus_astral_range_overlap() -> (
    None
):
    units = _class_intersection_probe_units(_H2_DIGIT_VERSUS_ASTRAL_RANGE_PATTERN, 0)
    assert units
    fill, _stray = units[0]
    assert re.fullmatch(r"\d", fill)
    assert re.fullmatch(r"[\U00010000-\U0010FFFEz]", fill)


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_digit_category_versus_astral_range() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(
        _H2_DIGIT_VERSUS_ASTRAL_RANGE_PATTERN
    )
    assert is_safe is False, (
        "expected the bare \\d category to contribute its own dense candidate "
        f"pool and catch the astral-range overlap, got safe={is_safe} ({reason})"
    )


_H3_ANCHORED_UNICODE_CLASS_PATTERNS = (
    r"^[Ѐ-ӿ]+$",
    r"^[一-鿿]+$",
    r"^[\U0001F600-\U0001F64F]+$",
    r"^[^\x00-\x7f]+$",
)


@pytest.mark.redos_timing
def test_pattern_compiler_accepts_anchored_non_ascii_class_patterns() -> None:
    compiler = PatternCompiler()
    for pattern in _H3_ANCHORED_UNICODE_CLASS_PATTERNS:
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is True, (
            f"expected {pattern!r} to be certified linear once the reach-probe "
            f"can represent a non-ASCII class, got safe={is_safe} ({reason})"
        )


@pytest.mark.redos_timing
def test_pattern_compiler_rejects_cyrillic_class_intersection() -> None:
    compiler = PatternCompiler()
    pattern = r"[Ѐ-ӿ]*[а-я]+$"
    is_safe, reason = compiler.validate_pattern_safety(pattern)
    assert is_safe is False, (
        f"expected the Cyrillic class-intersection overlap to be caught now "
        f"that the reach-probe can represent it, got safe={is_safe} ({reason})"
    )


def test_isolated_alternative_exact_state_skips_a_zero_admitting_atom() -> None:
    zero_atom = _PairingAtom(
        _IntervalSet.single(ord("a")), allows_zero=True, unbounded=False
    )
    state = _isolated_alternative_exact_state([zero_atom], 0)
    assert state == _IntervalSet.full()


def test_isolated_alternative_exact_state_narrows_through_a_mandatory_atom() -> None:
    slots = _pattern_slots(r"z", 0)
    assert slots is not None
    atom = slots[0]
    assert isinstance(atom, _PairingAtom)
    state = _isolated_alternative_exact_state([atom], 0)
    assert state is not None
    assert state.contains(ord("z")) is True
    assert state.contains(ord("y")) is False
    assert state == atom.intervals


def test_isolated_alternative_exact_state_returns_none_for_a_hard_boundary_slot() -> (
    None
):
    hard_boundary = _NonPairingSlot(is_boundary=True, inner=None)
    assert _isolated_alternative_exact_state([hard_boundary], 0) is None


def test_isolated_alternative_exact_state_passes_through_a_transparent_slot() -> None:
    transparent = _NonPairingSlot(is_boundary=False, inner=None)
    state = _isolated_alternative_exact_state([transparent], 0)
    assert state == _IntervalSet.full()


def test_isolated_alternative_exact_state_recurses_into_a_nested_group() -> None:
    slots = _pattern_slots(r"(z)", 0)
    assert slots is not None
    nested_group = slots[0]
    assert isinstance(nested_group, _NonPairingSlot)
    state = _isolated_alternative_exact_state([nested_group], 0)
    assert state is not None
    assert state.contains(ord("z")) is True
    assert state.contains(ord("y")) is False


def test_isolated_alternative_exact_state_returns_none_for_a_none_group_state() -> None:
    hard_boundary = _NonPairingSlot(is_boundary=True, inner=None)
    inner_group = _NonPairingSlot(is_boundary=True, inner=[[hard_boundary]])
    assert _isolated_alternative_exact_state([inner_group], 0) is None


def test_isolated_group_exact_state_rejects_past_the_max_depth() -> None:
    slots = _pattern_slots(r"z", 0)
    assert slots is not None
    atom = slots[0]
    assert isinstance(atom, _PairingAtom)
    assert _isolated_group_exact_state([[atom]], 999) is None


def test_isolated_group_exact_state_skips_alternatives_that_cannot_narrow() -> None:
    slots = _pattern_slots(r"z", 0)
    assert slots is not None
    live_atom = slots[0]
    assert isinstance(live_atom, _PairingAtom)
    hard_boundary_alt: list[Any] = [_NonPairingSlot(is_boundary=True, inner=None)]
    state = _isolated_group_exact_state([hard_boundary_alt, [live_atom]], 0)
    assert state is not None
    assert state.contains(ord("z")) is True
    assert state == live_atom.intervals


def test_isolated_group_exact_state_unions_two_alternatives() -> None:
    slots_a = _pattern_slots(r"a", 0)
    slots_b = _pattern_slots(r"b", 0)
    assert slots_a is not None
    assert slots_b is not None
    atom_a, atom_b = slots_a[0], slots_b[0]
    assert isinstance(atom_a, _PairingAtom)
    assert isinstance(atom_b, _PairingAtom)
    state = _isolated_group_exact_state([[atom_a], [atom_b]], 0)
    assert state is not None
    assert state.contains(ord("a")) is True
    assert state.contains(ord("b")) is True
    assert state.contains(ord("c")) is False
    assert state == atom_a.intervals.union(atom_b.intervals)


def test_isolated_group_exact_state_returns_none_when_every_alternative_fails() -> None:
    hard: list[Any] = [_NonPairingSlot(is_boundary=True, inner=None)]
    assert _isolated_group_exact_state([hard, hard], 0) is None


def test_exact_overlap_fill_raw_returns_none_when_either_state_is_missing() -> None:
    assert _exact_overlap_fill_raw(None, _IntervalSet.full()) is None
    assert _exact_overlap_fill_raw(_IntervalSet.full(), None) is None


def test_exact_overlap_fill_raw_returns_none_when_the_states_do_not_overlap() -> None:
    fill = _exact_overlap_fill_raw(
        _IntervalSet.single(ord("a")), _IntervalSet.single(ord("b"))
    )
    assert fill is None


def test_exact_overlap_fill_raw_finds_the_overlap() -> None:
    fill = _exact_overlap_fill_raw(
        _IntervalSet.single(ord("z")), _IntervalSet.single(ord("z"))
    )
    assert fill == "z"


def test_narrow_exact_state_raw_returns_none_when_either_state_is_missing() -> None:
    assert _narrow_exact_state_raw(None, _IntervalSet.full()) is None
    assert _narrow_exact_state_raw(_IntervalSet.full(), None) is None


def test_narrow_exact_state_raw_intersects_two_states() -> None:
    narrowed = _narrow_exact_state_raw(
        _IntervalSet.from_range(0, 10), _IntervalSet.from_range(5, 15)
    )
    assert narrowed == _IntervalSet.from_range(5, 10)


def test_cross_non_pairing_slot_hard_boundary_with_no_inner_returns_none() -> None:
    slot = _NonPairingSlot(is_boundary=True, inner=None)
    assert _cross_non_pairing_slot(slot, _IntervalSet.single(ord("a")), None) is None


def test_cross_non_pairing_slot_transparent_with_no_inner_passes_shared_through() -> (
    None
):
    slot = _NonPairingSlot(is_boundary=False, inner=None)
    shared = _IntervalSet.single(ord("a"))
    result = _cross_non_pairing_slot(slot, shared, None)
    assert result == (shared, None, None)


def test_cross_non_pairing_slot_boundary_crosses_directly_via_exact_intervals() -> None:
    slots = _pattern_slots(_H1_ASTRAL_GROUP_CROSSING_PATTERN, 0)
    assert slots is not None
    left = next(slot for slot in slots if isinstance(slot, _PairingAtom))
    group = next(
        slot
        for slot in slots
        if isinstance(slot, _NonPairingSlot) and slot.inner is not None
    )
    result = _cross_non_pairing_slot(group, left.intervals, left.intervals)
    assert result is not None
    shared, fill, group_state = result
    assert shared.is_empty() is False
    assert fill is not None
    assert group_state is not None
    assert group_state.is_empty() is False


def test_cross_non_pairing_slot_boundary_uses_the_exact_state_when_crossing_fails() -> (
    None
):
    slots = _pattern_slots(r"(z)+", 0)
    assert slots is not None
    group = next(slot for slot in slots if isinstance(slot, _NonPairingSlot))
    disjoint_shared = _IntervalSet.single(ord("q"))
    exact_state = _IntervalSet.single(ord("z"))
    result = _cross_non_pairing_slot(group, disjoint_shared, exact_state)
    assert result is not None
    shared, fill, group_state = result
    assert shared.is_empty() is True
    assert fill == "z"
    assert group_state == _IntervalSet.single(ord("z"))


def test_cross_non_pairing_slot_boundary_returns_none_when_exact_fallback_fails() -> (
    None
):
    slots = _pattern_slots(r"'\s*(?:(\s)\1z)+\s*--", 0)
    assert slots is not None
    left = next(slot for slot in slots if isinstance(slot, _PairingAtom))
    group = next(
        slot
        for slot in slots
        if isinstance(slot, _NonPairingSlot) and slot.inner is not None
    )
    result = _cross_non_pairing_slot(group, left.intervals, left.intervals)
    assert result is None


def test_pairing_units_from_suppresses_a_group_fill_the_predicate_rejects() -> None:
    left = _PairingAtom(
        _IntervalSet.single(ord("a")),
        allows_zero=False,
        unbounded=True,
        predicate=lambda code_point: False,
    )
    inner_atom = _PairingAtom(
        _IntervalSet.single(ord("a")), allows_zero=False, unbounded=False
    )
    group = _NonPairingSlot(
        is_boundary=True,
        inner=[[inner_atom]],
        unbounded=True,
    )
    ctx = _build_stray_context("a*z", 0)
    assert _pairing_units_from([left, group], 0, ctx) == []


def test_append_pairing_unit_skips_when_the_fill_is_not_confirmed() -> None:
    units: list[tuple[str, str]] = []
    always_false = _PairingAtom(
        _IntervalSet.single(ord("a")),
        allows_zero=False,
        unbounded=True,
        predicate=lambda code_point: False,
    )
    ctx = _build_stray_context("a*z", 0)
    _append_pairing_unit(units, always_false, always_false, "a", [], ctx)
    assert units == []


def test_advance_pairing_chain_uses_the_exact_state_when_shared_overlap_is_empty() -> (
    None
):
    left = _PairingAtom(
        _IntervalSet.single(ord("a")), allows_zero=False, unbounded=True
    )
    slot = _PairingAtom(
        _IntervalSet.single(ord("z")), allows_zero=False, unbounded=True
    )
    units: list[tuple[str, str]] = []
    disjoint_shared = _IntervalSet.single(ord("q"))
    exact_state = _IntervalSet.single(ord("z"))
    ctx = _build_stray_context("a*z", 0)
    shared, new_exact_state, should_stop = _advance_pairing_chain(
        units, left, disjoint_shared, slot, exact_state, [], ctx
    )
    assert units == [("z", "\x00")]
    assert should_stop is False
    assert new_exact_state is None
    assert shared.is_empty() is True


def test_advance_pairing_chain_exact_fallback_skips_append_when_not_unbounded() -> None:
    left = _PairingAtom(
        _IntervalSet.single(ord("a")), allows_zero=False, unbounded=True
    )
    slot = _PairingAtom(
        _IntervalSet.single(ord("z")), allows_zero=False, unbounded=False
    )
    units: list[tuple[str, str]] = []
    ctx = _build_stray_context("a*z", 0)
    shared, exact_state, should_stop = _advance_pairing_chain(
        units,
        left,
        _IntervalSet.single(ord("q")),
        slot,
        _IntervalSet.single(ord("z")),
        [],
        ctx,
    )
    assert units == []
    assert should_stop is False
    assert exact_state is None
    assert shared.is_empty() is True


def test_advance_pairing_chain_exact_fallback_keeps_state_when_slot_allows_zero() -> (
    None
):
    left = _PairingAtom(
        _IntervalSet.single(ord("a")), allows_zero=False, unbounded=True
    )
    slot = _PairingAtom(_IntervalSet.single(ord("z")), allows_zero=True, unbounded=True)
    units: list[tuple[str, str]] = []
    disjoint_shared = _IntervalSet.single(ord("q"))
    exact_state_in = _IntervalSet.single(ord("z"))
    ctx = _build_stray_context("a*z", 0)
    shared, exact_state, should_stop = _advance_pairing_chain(
        units, left, disjoint_shared, slot, exact_state_in, [], ctx
    )
    assert units == [("z", "\x00")]
    assert should_stop is False
    assert exact_state is exact_state_in
    assert shared is disjoint_shared


def test_category_intervals_finds_every_digit_and_caches_the_result() -> None:
    intervals = _category_intervals(_regex_parser.CATEGORY_DIGIT, 0)
    assert intervals.contains(ord("0")) is True
    assert intervals.contains(0x104A0) is True
    assert intervals is _category_intervals(_regex_parser.CATEGORY_DIGIT, 0)


def test_category_intervals_finds_unicode_whitespace() -> None:
    intervals = _category_intervals(_regex_parser.CATEGORY_SPACE, 0)
    assert intervals.contains(ord(" ")) is True
    assert intervals.contains(ord("a")) is False


def test_word_category_intervals_are_not_empty_and_include_far_members() -> None:
    intervals = _category_intervals(_regex_parser.CATEGORY_WORD, 0)
    assert intervals.contains(ord("a")) is True
    assert intervals.contains(0x2460) is True
    assert intervals.contains(0x2000) is False


def test_pattern_slots_negated_digit_class_excludes_far_digit_members() -> None:
    slots = _pattern_slots(r"[^\d]", 0)
    assert slots is not None
    atom = slots[0]
    assert isinstance(atom, _PairingAtom)
    assert atom.intervals.contains(0x104A0) is False
    assert atom.intervals.contains(ord("a")) is True


def test_word_category_versus_narrow_range_finds_overlap_when_one_exists() -> None:
    right = "[ -⁯]"
    assert any(re.fullmatch(r"\w", chr(cp)) for cp in range(0x20, 0x2070))
    units = _class_intersection_probe_units(f"'\\w*{right}+--", 0)
    assert units
    fill, _stray = units[0]
    assert re.fullmatch(r"\w", fill)
    assert re.fullmatch(right, fill)


_TEST_ALPHABET_EXTRA_CODE_POINTS: tuple[int, ...] = (
    0x100,
    0x400,
    0x4E00,
    0xFFFD,
    0x1F600,
    0xE000,
    0x10FFFF,
    0x1F601,
    0x131,
    0x17F,
    0x212A,
    0x3D1,
)
_TEST_ALPHABET: frozenset[str] = frozenset(chr(c) for c in range(256)) | frozenset(
    chr(c) for c in _TEST_ALPHABET_EXTRA_CODE_POINTS
)


def _element_charset(element: str) -> frozenset[str]:
    return frozenset(ch for ch in _TEST_ALPHABET if re.fullmatch(element, ch))


def _quantifier_free_atom_text(element: str) -> str:
    return element[:-1] if element and element[-1] in "*+" else element


def _interval_set_for_element(element: str) -> _IntervalSet:
    atom_text = _quantifier_free_atom_text(element)
    parsed = _regex_parser.parse(atom_text, 0)
    op, av = parsed.data[0]
    return _node_intervals(op, av, parsed.state.flags)


def _element_allows_zero(element: str) -> bool:
    return re.fullmatch(element, "") is not None


def _element_unbounded(element: str, charset: frozenset[str]) -> bool:
    if not charset:
        return False
    sample = sorted(charset)[0]
    return bool(re.fullmatch(element, sample * 200)) and bool(
        re.fullmatch(element, sample * 201)
    )


def _charset_slot(element: str) -> tuple[Any, ...]:
    charset = _element_charset(element)
    return (
        "charset",
        charset,
        _element_allows_zero(element),
        _element_unbounded(element, charset),
    )


_GRAMMAR_LEFT_ATOMS = [
    r"\s*",
    r"[a-z ]+",
    r"[^<>]*",
    r"\w*",
    r"[\x00-\xff]*",
    r"[\s\S]*",
]
_GRAMMAR_RIGHT_ATOMS = [
    r"\s*",
    r"[ a-z]*",
    r"[^\"']+",
    r"\w+",
    r"[\x00-\xfe]+",
    r"[\s\S]+",
]
_GRAMMAR_ZERO_ADMITTING_MIDDLES = [
    "",
    r"[\);]*",
    r"x?",
    r"[0-9]{0,3}",
    r"(?:ab)*",
    r"(?:aa|bb)*",
    r"(?!x)",
    r"\d*?",
]
_GRAMMAR_MANDATORY_MIDDLES = [
    r"[\);]+",
    r"x",
    r"\.",
    r"[0-9]{1,3}",
    r"(?:ab)+",
    r"-",
    r"(?:\s+)",
    r"(?:\s|,)",
    r"(?:AND|OR)",
]
_GRAMMAR_HAND_SPECIFIED_MIDDLES = frozenset(
    {r"(?:ab)*", r"(?:aa|bb)*", r"(?!x)", r"(?:ab)+", r"(?:AND|OR)"}
)

_GRAMMAR_LEFT_META = {a: _charset_slot(a) for a in _GRAMMAR_LEFT_ATOMS}
_GRAMMAR_RIGHT_META = {a: _charset_slot(a) for a in _GRAMMAR_RIGHT_ATOMS}
_GRAMMAR_MIDDLE_META = {
    mid: _charset_slot(mid)
    for mid in _GRAMMAR_ZERO_ADMITTING_MIDDLES + _GRAMMAR_MANDATORY_MIDDLES
    if mid not in _GRAMMAR_HAND_SPECIFIED_MIDDLES
}
_GRAMMAR_MIDDLE_META[r"(?:ab)*"] = ("transparent",)
_GRAMMAR_MIDDLE_META[r"(?!x)"] = ("transparent",)
_GRAMMAR_MIDDLE_META[r"(?:ab)+"] = (
    "boundary_group",
    [[(_element_charset("a"), False), (_element_charset("b"), False)]],
    True,
    True,
)
_GRAMMAR_MIDDLE_META[r"(?:AND|OR)"] = (
    "boundary_group",
    [
        [
            (_element_charset("A"), False),
            (_element_charset("N"), False),
            (_element_charset("D"), False),
        ],
        [(_element_charset("O"), False), (_element_charset("R"), False)],
    ],
    False,
    True,
)
_GRAMMAR_MIDDLE_META[r"(?:aa|bb)*"] = (
    "boundary_group",
    [
        [(_element_charset("a"), False), (_element_charset("a"), False)],
        [(_element_charset("b"), False), (_element_charset("b"), False)],
    ],
    True,
    False,
)


def _oracle_alternative_crossing(
    atoms: list[tuple[frozenset[str], bool]], shared: frozenset[str]
) -> frozenset[str] | None:
    local = shared
    for atom_charset, atom_allows_zero in atoms:
        if atom_allows_zero:
            continue
        overlap = atom_charset & local
        if not overlap:
            return None
        local = overlap
    return local


def _oracle_group_crossing(
    alternatives: list[list[tuple[frozenset[str], bool]]], shared: frozenset[str]
) -> frozenset[str] | None:
    crossed = [
        result
        for alt in alternatives
        if (result := _oracle_alternative_crossing(alt, shared)) is not None
    ]
    if not crossed:
        return None
    return frozenset[str]().union(*crossed)


def _grammar_walk_hits_fill(
    charset: frozenset[str],
    allows_zero: bool,
    unbounded: bool,
    rest: list[tuple[Any, ...]],
) -> bool:
    if not unbounded:
        return False
    shared = charset
    for slot in rest:
        if slot[0] == "transparent":
            continue
        if slot[0] == "boundary_group":
            _, alternatives, group_unbounded, group_mandatory = slot
            crossing = _oracle_group_crossing(alternatives, shared)
            if crossing is None:
                if group_mandatory:
                    return False
                continue
            if group_unbounded:
                return True
            if group_mandatory:
                shared = crossing
            continue
        _, slot_charset, slot_allows_zero, slot_unbounded = slot
        overlap = slot_charset & shared
        if not overlap:
            if not slot_allows_zero:
                return False
            continue
        if slot_unbounded:
            return True
        if not slot_allows_zero:
            shared = overlap
    return False


def _grammar_expects_nonempty_fills(slots: list[tuple[Any, ...]]) -> bool:
    return any(
        _grammar_walk_hits_fill(slot[1], slot[2], slot[3], slots[i + 1 :])
        for i, slot in enumerate(slots)
        if slot[0] == "charset"
    )


@pytest.mark.redos_timing
@pytest.mark.parametrize("left", _GRAMMAR_LEFT_ATOMS)
@pytest.mark.parametrize("right", _GRAMMAR_RIGHT_ATOMS)
def test_class_intersection_fills_matches_char_set_expectation_across_grammar(
    left: str, right: str
) -> None:
    combos = itertools.product(
        _GRAMMAR_ZERO_ADMITTING_MIDDLES + _GRAMMAR_MANDATORY_MIDDLES,
        _GRAMMAR_ZERO_ADMITTING_MIDDLES + _GRAMMAR_MANDATORY_MIDDLES,
    )
    for mid1, mid2 in combos:
        pattern = left + mid1 + mid2 + right
        slots = [
            _GRAMMAR_LEFT_META[left],
            _GRAMMAR_MIDDLE_META[mid1],
            _GRAMMAR_MIDDLE_META[mid2],
            _GRAMMAR_RIGHT_META[right],
        ]
        expected = _grammar_expects_nonempty_fills(slots)
        fills = _class_intersection_fills(pattern, 0)
        assert bool(fills) == expected, (
            f"pattern={pattern!r} expected_nonempty={expected} fills={fills}"
        )


_GRAMMAR_TIMING_MIDDLES = [
    "",
    r"[\);]*",
    r"x?",
    r"(?:ab)*",
    r"(?!x)",
    r"[\);]+",
    r"(?:ab)+",
    r"(?:AND|OR)",
    r"(?:\s+)",
]
_TIMING_PROBE_ALARM_SECONDS = 1


class _TimingProbeTimedOut(Exception):
    pass


def _timing_probe_alarm_handler(*_signal_args: object) -> None:
    raise _TimingProbeTimedOut


def _min_process_time(compiled: re.Pattern, probe: str, samples: int = 3) -> float:
    best = float(_TIMING_PROBE_ALARM_SECONDS)
    previous_handler = signal.signal(signal.SIGALRM, _timing_probe_alarm_handler)
    try:
        for _ in range(samples):
            signal.alarm(_TIMING_PROBE_ALARM_SECONDS)
            try:
                start = time.process_time()
                compiled.search(probe)
                elapsed = time.process_time() - start
            except _TimingProbeTimedOut:
                elapsed = float(_TIMING_PROBE_ALARM_SECONDS)
            finally:
                signal.alarm(0)
            best = min(best, elapsed)
            if elapsed >= _TIMING_PROBE_ALARM_SECONDS:
                break
    finally:
        signal.signal(signal.SIGALRM, previous_handler)
    return best


def _growth_ratio(pattern: str, fill: str, stray: str) -> float:
    compiled = re.compile(pattern)
    t2000 = _min_process_time(compiled, "'" + fill * 2000 + stray)
    if t2000 >= _TIMING_PROBE_ALARM_SECONDS:
        return float("inf")
    if t2000 < 0.001:
        return 1.0
    t4000 = _min_process_time(compiled, "'" + fill * 4000 + stray)
    return t4000 / t2000


def _timing_ground_truth_candidates(left: str, mid: str, right: str) -> set[str]:
    chars: set[str] = set()
    for element in (left, mid, right):
        charset = _element_charset(element)
        if charset:
            chars.add(sorted(charset)[0])
    return chars


_STRAY_ORACLE_STEP = 251
_STRAY_ORACLE_REPRESENTATIVE_CODE_POINTS = (
    0x100,
    0x400,
    0x4E00,
    0xFFFD,
    0x1F600,
    0x10FFFF,
)
_STRAY_ORACLE_CODE_POINTS: tuple[int, ...] = tuple(
    sorted(
        set(range(256))
        | set(range(256, 0x110000, _STRAY_ORACLE_STEP))
        | set(_STRAY_ORACLE_REPRESENTATIVE_CODE_POINTS)
    )
)


def _oracle_stray_for_pair(left: str, right: str, flags: int) -> str | None:
    for code_point in _STRAY_ORACLE_CODE_POINTS:
        candidate = chr(code_point)
        if re.fullmatch(left, candidate, flags) or re.fullmatch(
            right, candidate, flags
        ):
            continue
        return candidate
    return None


@pytest.mark.redos_timing
@pytest.mark.parametrize("left", _GRAMMAR_LEFT_ATOMS)
@pytest.mark.parametrize("right", _GRAMMAR_RIGHT_ATOMS)
def test_class_intersection_probe_units_are_ground_truthed_against_real_timing(
    left: str, right: str
) -> None:
    oracle_stray = _oracle_stray_for_pair(left, right, 0)
    if oracle_stray is not None:
        module_stray = _stray_for_pair(
            _interval_set_for_element(left), _interval_set_for_element(right)
        )
        assert re.fullmatch(left, module_stray) is None
        assert re.fullmatch(right, module_stray) is None
    for mid in _GRAMMAR_TIMING_MIDDLES:
        pattern = "'" + left + mid + right + "--"
        units = _class_intersection_probe_units(pattern, 0)
        found_fills = {fill for fill, _stray in units}
        for candidate in _timing_ground_truth_candidates(left, mid, right):
            if candidate == " ":
                stray = "\x00"
            elif oracle_stray is not None:
                stray = oracle_stray
            else:
                stray = candidate
            ratio = _growth_ratio(pattern, candidate, stray)
            if ratio >= 3.0:
                assert units, (
                    f"pattern={pattern!r} fill={candidate!r} stray={stray!r} "
                    f"measured super-linear growth (ratio={ratio:.2f}x) but "
                    f"the module produced no unit at all: {found_fills}"
                )
        if not units:
            ratio = _growth_ratio(pattern, " ", "\x00")
            assert ratio < 3.0, (
                f"pattern={pattern!r} produced no class-intersection unit but "
                f"the space/NUL probe measured super-linear growth "
                f"(ratio={ratio:.2f}x); a quadratic escape without a unit"
            )


_GRAMMAR_ASTRAL_PAIRS: list[tuple[str, str, str, str]] = [
    (
        r"[\x00-\U0001F600]*",
        r"[\x00-\U0001F5FF]+",
        "\U0001f5ff",
        "\U0001f601",
    ),
    (
        r"[\U0001F601-\U0001F700]*",
        r"[\U0001F650-\U0001F800]+",
        "\U0001f650",
        "\x00",
    ),
    (
        r"\d*",
        r"[\U00010000-\U0010FFFEz]+",
        "\U000104a0",
        "\x00",
    ),
]


@pytest.mark.redos_timing
def test_class_intersection_probe_units_are_ground_truthed_for_astral_pairs() -> None:
    for left, right, fill, stray in _GRAMMAR_ASTRAL_PAIRS:
        pattern = "'" + left + right + "--"
        units = _class_intersection_probe_units(pattern, 0)
        ratio = _growth_ratio(pattern, fill, stray)
        if ratio >= 3.0:
            assert units, (
                f"pattern={pattern!r} fill={fill!r} stray={stray!r} measured "
                f"super-linear growth (ratio={ratio:.2f}x) but the module "
                f"produced no unit at all"
            )


_GRAMMAR_ASTRAL_GROUP_PATTERN = (
    "'" + r"[\U0001F900-\U0001FAA0a]*([\U0001F900-\U0001FAA0b])+" + "--"
)


@pytest.mark.redos_timing
def test_class_intersection_probe_units_are_ground_truthed_for_an_astral_group() -> (
    None
):
    fill, stray = "\U0001f900", "\x00"
    units = _class_intersection_probe_units(_GRAMMAR_ASTRAL_GROUP_PATTERN, 0)
    ratio = _growth_ratio(_GRAMMAR_ASTRAL_GROUP_PATTERN, fill, stray)
    if ratio >= 3.0:
        assert units, (
            f"pattern={_GRAMMAR_ASTRAL_GROUP_PATTERN!r} fill={fill!r} "
            f"stray={stray!r} measured super-linear growth (ratio={ratio:.2f}x) "
            f"but the module produced no unit for the astral group crossing"
        )


def test_repeat_probe_to_length_forces_non_alignment_on_exact_multiples() -> None:
    result = _repeat_probe_to_length("ab", 10)
    assert len(result) == 10
    assert result[-1] == "\x00"


def test_repeat_probe_to_length_stays_pure_repetition_when_not_aligned() -> None:
    result = _repeat_probe_to_length("abc", 10)
    assert len(result) == 10
    assert "\x00" not in result


def test_repeat_probe_to_length_empty_unit_returns_unit() -> None:
    assert _repeat_probe_to_length("", 10) == ""


def test_leading_literal_prefix_unwraps_transparent_group() -> None:
    assert _leading_literal_prefix(r"(?:<[^<>]*)") == "<"


def test_leading_literal_prefix_handles_escaped_literal_run() -> None:
    assert _leading_literal_prefix(r"\.\.;[^/\\]*") == "..;"


def test_leading_literal_prefix_empty_when_pattern_opens_with_metachar() -> None:
    assert _leading_literal_prefix(r"[^<>]*x") == ""


def test_fill_to_length_pads_and_truncates() -> None:
    assert _fill_to_length("ab", "x", "!", 4) == "abx!"
    assert _fill_to_length("abcdef", "x", "!", 3) == "abc"


def test_fill_to_length_appends_the_stray_as_the_last_character() -> None:
    assert _fill_to_length("ab", "x", "!", 6) == "abxxx!"


def test_fill_to_length_does_not_force_a_stray_when_body_room_is_one_or_fewer() -> None:
    assert _fill_to_length("ab", "x", "!", 3) == "abx"
    assert _fill_to_length("ab", "x", "!", 2) == "ab"


def test_reach_probe_candidate_builders_combines_all_strategies() -> None:
    builders = _reach_probe_candidate_builders(
        _EVENT_HANDLER_PATTERN, re.IGNORECASE | re.MULTILINE
    )
    assert len(builders) >= 1
    for builder in builders:
        probe = builder(4000)
        assert len(probe) == 4000


def test_stride_sampling_bounds_timed_probe_sets_and_keeps_every_stride_step() -> None:
    probe_sets: list[tuple[str, ...]] = [
        (f"p{index}", f"p{index}!") for index in range(1200)
    ]
    assert _stride_sampled_probe_sets(probe_sets, 512) == probe_sets[::3]
    assert _stride_sampled_probe_sets(probe_sets[:512], 512) == probe_sets[:512]
    assert _stride_sampled_probe_sets(probe_sets[:513], 512) == probe_sets[:513][::2]


def test_median_of_five_presorted_samples_is_the_middle_value() -> None:
    assert _median([0.1, 0.2, 0.3, 0.4, 0.5]) == 0.3
    assert _median([0.01, 0.01, 0.3, 9.0, 9.0]) == 0.3


def test_reach_probe_verdict_measures_at_a_small_cap_without_extrapolating() -> None:
    linear_samples = [[0.001] * 5, [0.002] * 5, [0.004] * 5, [0.008] * 5]
    over, cost, ratio, min_at_cap, median_at_cap = _reach_probe_verdict_from_samples(
        linear_samples, 512
    )
    assert over is False
    assert ratio == 2.0
    assert cost == 0.008
    assert min_at_cap == 0.008
    assert median_at_cap == 0.008


def test_reach_probe_verdict_rejects_when_extrapolated_cost_exceeds_budget() -> None:
    quadratic_samples = [[0.001] * 5, [0.004] * 5, [0.016] * 5, [0.064] * 5]
    over, extrapolated, ratio, _min_32, _median_32 = _reach_probe_verdict_from_samples(
        quadratic_samples, _PATTERN_SAFETY_DEFAULT_CAP
    )
    assert over is True
    assert ratio == 4.0
    assert extrapolated > 0.05


def test_reach_probe_verdict_clamps_a_noisy_non_monotonic_ratio_to_one() -> None:
    non_monotonic_samples = [[0.001] * 5, [0.002] * 5, [0.010] * 5, [0.006] * 5]
    over, extrapolated, ratio, min_32, median_32 = _reach_probe_verdict_from_samples(
        non_monotonic_samples, 512
    )
    assert ratio == 1.0
    assert over is False
    assert extrapolated == min_32
    assert min_32 == 0.006
    assert median_32 == 0.006


def test_reach_probe_verdict_treats_tiny_times_as_inconclusive_ratio() -> None:
    noisy_samples = [[0.0] * 5, [0.0] * 5, [0.0] * 5, [0.0002] * 5]
    over, _extrapolated, ratio, _min_32, _median_32 = _reach_probe_verdict_from_samples(
        noisy_samples, _PATTERN_SAFETY_DEFAULT_CAP
    )
    assert ratio == 1.0
    assert over is False


def test_time_reach_probes_subprocess_returns_none_on_crash() -> None:
    def _raise(*args: object, **kwargs: object) -> None:
        raise OSError("no forkable subprocess slot")

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.Popen", _raise
    ):
        result = _time_reach_probes_subprocess("test", ["a"], _ample_budget())
    assert result is None


def test_time_reach_probes_subprocess_returns_none_on_nonzero_returncode() -> None:
    fake_popen = _fake_popen(1, "")

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.Popen",
        new=fake_popen,
    ):
        result = _time_reach_probes_subprocess("test", ["a"], _ample_budget())
    assert result is None


def test_time_reach_probes_subprocess_returns_none_on_malformed_output() -> None:
    fake_popen = _fake_popen(0, "not json")

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.Popen",
        new=fake_popen,
    ):
        result = _time_reach_probes_subprocess("test", ["a"], _ample_budget())
    assert result is None


def test_time_reach_probes_subprocess_returns_none_on_compile_error() -> None:
    result = _time_reach_probes_subprocess("[invalid", ["a"], _ample_budget())
    assert result is None


def test_time_reach_probes_subprocess_returns_none_when_budget_is_exhausted() -> None:
    def _fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("subprocess.Popen must not run without remaining budget")

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.Popen",
        _fail_if_called,
    ):
        result = _time_reach_probes_subprocess("test", ["a"], ReachProbeCpuBudget(0.0))
    assert result is None


def _repeat_builder(unit: str) -> Callable[[int], str]:
    return lambda size: unit * size


def test_time_reach_probes_subprocess_clips_cpu_limit_to_remaining_budget() -> None:
    captured: dict[str, float] = {}

    def _fake_popen(*args: object, **kwargs: Any) -> MagicMock:
        process = MagicMock()

        def _communicate(payload: str, timeout: float) -> None:
            captured["cpu_limit"] = json.loads(payload)[3]
            raise OSError("stop before actually spawning")

        process.communicate = _communicate
        return process

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.Popen",
        _fake_popen,
    ):
        result = _time_reach_probes_subprocess("test", ["a"], ReachProbeCpuBudget(3.0))
    assert result is None
    assert captured["cpu_limit"] == 3.0


def test_time_reach_probes_subprocess_returns_sorted_samples_per_probe() -> None:
    result = _time_reach_probes_subprocess("abc", ["abc", "abcabc"], _ample_budget())
    assert result is not None
    assert len(result.samples_by_size) == 2
    for samples in result.samples_by_size:
        assert 1 <= len(samples) <= _REACH_PROBE_SAMPLE_COUNT
        assert samples == sorted(samples)
    assert _LOAD_FACTOR_FLOOR <= result.load_factor <= _LOAD_FACTOR_CEILING


def test_reach_probe_cost_verdict_accepts_when_no_candidate_units_exist() -> None:
    is_safe, reason = _reach_probe_cost_verdict(r"[a-z]", None)
    assert is_safe is True
    assert reason == "Pattern appears safe"


@pytest.mark.redos_timing
def test_event_handler_rejects_under_intersection_fill_at_body_cap() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(
        _EVENT_HANDLER_PATTERN, max_content_length=_PATTERN_SAFETY_DEFAULT_CAP
    )
    assert is_safe is False, (
        "event_handler must reject at the body cap under an intersection fill; "
        f"got safe={is_safe} ({reason})"
    )


def _assert_event_handler_intersection_fill_is_super_linear() -> None:
    units = _class_intersection_probe_units(_EVENT_HANDLER_PATTERN, re.IGNORECASE)
    fill_char, stray = units[0]
    prefix = _leading_literal_prefix(_EVENT_HANDLER_PATTERN)
    probes = [
        _fill_to_length(prefix, fill_char, stray, size) for size in _REACH_PROBE_SIZES
    ]
    compiled = re.compile(_EVENT_HANDLER_PATTERN, re.IGNORECASE)
    times = []
    for probe in probes:
        start = time.process_time()
        compiled.search(probe)
        times.append(time.process_time() - start)
    assert times[2] > 0.0005, "measurement floor too close to noise to trust the ratio"
    ratio = times[3] / times[2]
    assert ratio >= 3.0, (
        f"expected super-linear growth from the {fill_char!r} intersection fill, "
        f"measured ratio={ratio:.2f}x, times={times}"
    )


@pytest.mark.redos_timing
def test_event_handler_intersection_fill_measures_super_linear_directly() -> None:
    try:
        _assert_event_handler_intersection_fill_is_super_linear()
    except AssertionError:
        _assert_event_handler_intersection_fill_is_super_linear()


def test_reach_probe_unreachable_reason_echoes_structural_violation() -> None:
    assert (
        _reach_probe_unreachable_reason("some structural reason")
        == "some structural reason"
    )


def test_probe_cost_verdict_logs_disagreement_without_candidate_builders(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    pattern = r"(\b|\W+)*"
    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_cost_arbiter._reach_probe_candidate_builders",
        lambda _pattern, _flags, _deadline: [],
    )
    with caplog.at_level(
        logging.WARNING,
        logger="guard_core.sync.detection_engine.compiler",
    ):
        is_safe, reason = _reach_probe_cost_verdict(pattern, None)
    assert is_safe is True
    assert reason == "Pattern appears safe"
    assert "structural rule flagged" in caplog.text
    assert "no repeatable adversarial trigger" in caplog.text


def test_first_over_budget_reason_returns_structural_violation_when_over_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quadratic_samples = [[0.001] * 5, [0.004] * 5, [0.016] * 5, [0.064] * 5]

    def _fake_timing(
        pattern: str, probes: list[str], budget: ReachProbeCpuBudget, flags: int
    ) -> ReachProbeTiming:
        return _timing(quadratic_samples)

    builder_calls = [0]

    def _builder(size: int) -> str:
        builder_calls[0] += 1
        return "a" * size

    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_cost_arbiter._time_reach_probes_ascending",
        _fake_timing,
    )
    reason = _first_over_budget_reason(
        r"(\w+\s?)*$",
        [_builder],
        _PATTERN_SAFETY_DEFAULT_CAP,
        "ambiguous optional tail",
        _ample_budget(),
    )
    assert reason is not None
    assert reason == "ambiguous optional tail"
    assert builder_calls[0] == len(_REACH_PROBE_SIZES)


def test_first_over_budget_reason_rejects_when_timing_probe_times_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        lambda _pattern, _probes, _deadline, _flags: None,
    )

    def _builder(size: int) -> str:
        return "a" * size

    reason = _first_over_budget_reason(
        r"(\w+)*$",
        [_builder],
        _PATTERN_SAFETY_DEFAULT_CAP,
        None,
        _ample_budget(),
    )
    assert reason is not None
    assert "killable-subprocess timeout" in reason


def test_first_over_budget_reason_recovers_when_over_budget_does_not_repeat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    over_samples = _timing([[0.016] * 5, [0.064] * 5])
    under_samples = _timing([[0.0004] * 5, [0.0008] * 5])
    calls = iter([over_samples, under_samples])
    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        lambda _pattern, _probes, _deadline, _flags: next(calls),
    )

    def _builder(size: int) -> str:
        return "a" * size

    reason = _first_over_budget_reason(
        r"(\w+)*$",
        [_builder],
        _PATTERN_SAFETY_DEFAULT_CAP,
        None,
        _ample_budget(),
    )
    assert reason is None


def test_first_over_budget_reason_rejects_when_over_budget_confirmation_times_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    over_samples = _timing([[0.016] * 5, [0.064] * 5])
    calls = iter([over_samples, None])
    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        lambda _pattern, _probes, _deadline, _flags: next(calls),
    )

    def _builder(size: int) -> str:
        return "a" * size

    reason = _first_over_budget_reason(
        r"(\w+)*$",
        [_builder],
        _PATTERN_SAFETY_DEFAULT_CAP,
        None,
        _ample_budget(),
    )
    assert reason is not None
    assert "extrapolated CPU cost" in reason


def test_first_over_budget_reason_returns_none_when_under_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    under_samples = _timing([[0.0004] * 5, [0.0008] * 5])
    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        lambda _pattern, _probes, _deadline, _flags: under_samples,
    )

    def _builder(size: int) -> str:
        return "a" * size

    reason = _first_over_budget_reason(
        r"(\w+)*$",
        [_builder],
        _PATTERN_SAFETY_DEFAULT_CAP,
        None,
        _ample_budget(),
    )
    assert reason is None


def test_first_over_budget_reason_retries_at_most_once_per_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    over_samples = _timing([[0.016] * 5, [0.064] * 5])
    under_samples = _timing([[0.0004] * 5, [0.0008] * 5])
    calls: list[str] = []

    def _fake_timing(
        _pattern: str, _probes: list[str], _budget: ReachProbeCpuBudget, _flags: int
    ) -> ReachProbeTiming:
        calls.append(_pattern)
        return over_samples if len(calls) % 2 else under_samples

    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        _fake_timing,
    )

    builders = [_repeat_builder(ch) for ch in ("a", "b", "c")]
    reason = _first_over_budget_reason(
        r"(\w+)*$", builders, _PATTERN_SAFETY_DEFAULT_CAP, None, _ample_budget()
    )
    assert reason is None
    assert len(calls) == 2 * len(builders)


def test_first_over_budget_reason_skips_retry_when_budget_is_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    over_samples = _timing([[0.016] * 5, [0.064] * 5])
    timing_calls: list[int] = []

    def _fake_timing(
        _pattern: str, _probes: list[str], budget: ReachProbeCpuBudget, _flags: int
    ) -> ReachProbeTiming:
        timing_calls.append(1)
        budget.charge(0.05)
        return over_samples

    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_cost_arbiter._time_reach_probes_subprocess",
        _fake_timing,
    )

    def _builder(size: int) -> str:
        return "a" * size

    reason = _first_over_budget_reason(
        r"(\w+)*$",
        [_builder],
        _PATTERN_SAFETY_DEFAULT_CAP,
        None,
        ReachProbeCpuBudget(0.02),
    )
    assert reason is not None
    assert "extrapolated CPU cost" in reason
    assert len(timing_calls) == 1


def test_remaining_budget_is_deadline_minus_now() -> None:
    deadline = time.thread_time() + 5.0
    remaining = _remaining_budget(deadline)
    assert 0.0 < remaining <= 5.0


def test_clipped_timeout_returns_default_when_budget_is_ample() -> None:
    assert _clipped_timeout(2.0, 100.0) == 2.0


def test_clipped_timeout_returns_remaining_when_budget_is_tight() -> None:
    assert _clipped_timeout(100.0, 1.0) == 1.0


def test_reach_probe_cost_verdict_bounds_the_whole_phase_to_one_shared_cpu_budget() -> (
    None
):
    seen_budgets: list[ReachProbeCpuBudget] = []

    def _fake_over_budget_reason(
        pattern: str,
        builders: list[object],
        cap: int,
        structural_violation: str | None,
        budget: ReachProbeCpuBudget,
        flags: int,
        bounded_repeat_risk: bool,
    ) -> str | None:
        assert bounded_repeat_risk is False
        seen_budgets.append(budget)
        return None

    with (
        patch(
            "guard_core.sync.detection_engine._redos_cost_arbiter._first_over_budget_reason",
            _fake_over_budget_reason,
        ),
        patch(
            "guard_core.sync.detection_engine._redos_cost_arbiter._measure_host_load_factor",
            lambda: 1.0,
        ),
    ):
        is_safe, reason = _reach_probe_cost_verdict(r"[a-z]+[a-z]+$", None)

    assert is_safe is True
    assert reason == "Pattern appears safe"
    assert len(seen_budgets) == 1
    assert seen_budgets[0].remaining_seconds == _REACH_PROBE_COMBINED_TIMEOUT_SECONDS


def test_scaled_probe_deadline_scales_with_load_and_respects_the_ceiling() -> None:
    assert (
        _scaled_probe_deadline_seconds(_LOAD_FACTOR_FLOOR)
        == _REACH_PROBE_COMBINED_TIMEOUT_SECONDS
    )
    assert _scaled_probe_deadline_seconds(1.0) == _REACH_PROBE_COMBINED_TIMEOUT_SECONDS
    assert (
        _scaled_probe_deadline_seconds(2.0) == 2 * _REACH_PROBE_COMBINED_TIMEOUT_SECONDS
    )
    assert (
        _scaled_probe_deadline_seconds(_LOAD_FACTOR_CEILING)
        == _REACH_PROBE_DEADLINE_SCALE_CEILING_SECONDS
    )


def test_measure_host_load_factor_fails_open_to_an_unscaled_deadline() -> None:
    class _Completed:
        returncode = 0
        stdout = '{"reference": 0.00458}'
        stderr = ""

    def _raise_spawn_error(*args: object, **kwargs: object) -> object:
        raise OSError("stop before actually spawning")

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run",
        lambda *args, **kwargs: _Completed(),
    ):
        assert _measure_host_load_factor() == 2.0

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run",
        _raise_spawn_error,
    ):
        assert _measure_host_load_factor() == 1.0

    broken = _Completed()
    broken.stdout = "not json"
    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.run",
        lambda *args, **kwargs: broken,
    ):
        assert _measure_host_load_factor() == 1.0


@pytest.mark.redos_timing
def test_retry_confirmation_adds_bounded_child_cpu_time_for_a_safe_pattern() -> None:
    safe_pattern = r"benign-literal-run"
    probes = [_repeat_probe_to_length("a", size) for size in _REACH_PROBE_SIZES]

    totals = []
    for _ in range(5):
        baseline = _time_reach_probes_subprocess(safe_pattern, probes, _ample_budget())
        retry = _time_reach_probes_subprocess(safe_pattern, probes, _ample_budget())
        assert baseline is not None
        assert retry is not None
        child_cpu_seconds = sum(
            t for row in baseline.samples_by_size for t in row
        ) + sum(t for row in retry.samples_by_size for t in row)
        totals.append(child_cpu_seconds)

    min_child_cpu_seconds = min(totals)
    assert min_child_cpu_seconds < 1.0, (
        "one baseline plus one retry reach-probe measurement of a safe pattern "
        f"cost {min_child_cpu_seconds:.4f}s of child CPU time across "
        f"{2 * len(_REACH_PROBE_SIZES) * 5} regex searches, expected "
        "comfortably under the 1.0s bound"
    )


def test_reach_probe_timing_strategy_selects_ascending_for_a_structural_violation() -> (
    None
):
    assert _reach_probe_timing_strategy("ambiguous optional tail") is (
        _time_reach_probes_ascending
    )


def test_reach_probe_timing_strategy_selects_combined_when_not_flagged() -> None:
    assert _reach_probe_timing_strategy(None) is _time_reach_probes_subprocess


def test_time_single_reach_probe_subprocess_returns_none_on_crash() -> None:
    def _raise(*args: object, **kwargs: object) -> None:
        raise OSError("no forkable subprocess slot")

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.Popen", _raise
    ):
        result = _time_single_reach_probe_subprocess("test", "a", _ample_budget())
    assert result is None


def test_time_single_reach_probe_subprocess_returns_none_on_nonzero_returncode() -> (
    None
):
    fake_popen = _fake_popen(1, "")

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.Popen",
        new=fake_popen,
    ):
        result = _time_single_reach_probe_subprocess("test", "a", _ample_budget())
    assert result is None


def test_time_single_reach_probe_subprocess_returns_none_on_malformed_output() -> None:
    fake_popen = _fake_popen(0, "not json")

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.Popen",
        new=fake_popen,
    ):
        result = _time_single_reach_probe_subprocess("test", "a", _ample_budget())
    assert result is None


def test_time_single_reach_probe_subprocess_returns_none_on_compile_error() -> None:
    result = _time_single_reach_probe_subprocess("[invalid", "a", _ample_budget())
    assert result is None


def test_time_single_reach_probe_subprocess_returns_none_when_budget_is_exhausted() -> (
    None
):
    def _fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("subprocess.Popen must not run without remaining budget")

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter.subprocess.Popen",
        _fail_if_called,
    ):
        result = _time_single_reach_probe_subprocess(
            "test", "a", ReachProbeCpuBudget(0.0)
        )
    assert result is None


def test_time_single_reach_probe_subprocess_returns_sorted_samples() -> None:
    result = _time_single_reach_probe_subprocess("abc", "abcabc", _ample_budget())
    assert result is not None
    (samples,) = result.samples_by_size
    assert 1 <= len(samples) <= _REACH_PROBE_SAMPLE_COUNT
    assert samples == sorted(samples)


def test_time_reach_probes_ascending_returns_sorted_samples_per_probe() -> None:
    result = _time_reach_probes_ascending("abc", ["abc", "abcabc"], _ample_budget())
    assert result is not None
    assert len(result.samples_by_size) == 2
    for samples in result.samples_by_size:
        assert 1 <= len(samples) <= _REACH_PROBE_SAMPLE_COUNT
        assert samples == sorted(samples)


def test_time_reach_probes_ascending_stops_at_the_first_failing_size() -> None:
    calls: list[str] = []

    def _fake_single(
        pattern: str, probe: str, budget: ReachProbeCpuBudget, flags: int
    ) -> ReachProbeTiming | None:
        calls.append(probe)
        return None if probe == "second" else _timing([[0.0] * 5])

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter."
        "_time_single_reach_probe_subprocess",
        _fake_single,
    ):
        result = _time_reach_probes_ascending(
            "test", ["first", "second", "third"], _ample_budget()
        )

    assert result is None
    assert calls == ["first", "second"]


def test_time_reach_probes_ascending_keeps_the_smallest_load_factor() -> None:
    factors = iter([3.0, 2.0, 2.5])

    def _fake_single(
        pattern: str, probe: str, budget: ReachProbeCpuBudget, flags: int
    ) -> ReachProbeTiming:
        return _timing([[0.0] * 5], next(factors))

    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter."
        "_time_single_reach_probe_subprocess",
        _fake_single,
    ):
        result = _time_reach_probes_ascending("test", ["a", "b", "c"], _ample_budget())

    assert result is not None
    assert result.load_factor == 2.0
    assert len(result.samples_by_size) == 3


def test_load_factor_is_one_on_the_reference_host() -> None:
    assert _load_factor(_REFERENCE_SCAN_SECONDS) == 1.0


def test_load_factor_is_clamped_to_its_floor_and_ceiling() -> None:
    assert _load_factor(0.0) == _LOAD_FACTOR_FLOOR
    assert _load_factor(_REFERENCE_SCAN_SECONDS * 1000) == _LOAD_FACTOR_CEILING


def test_parse_reach_probe_child_output_requires_the_reference_scan() -> None:
    assert _parse_reach_probe_child_output('{"results": [[0.1]]}') is None
    assert _parse_reach_probe_child_output('{"error": "x", "reference": 0.002}') is None
    assert _parse_reach_probe_child_output("not json") is None


def test_parse_reach_probe_child_output_normalizes_by_the_reference_scan() -> None:
    timing = _parse_reach_probe_child_output(
        f'{{"results": [[0.3, 0.1, 0.2]], "reference": {_REFERENCE_SCAN_SECONDS * 2}, '
        '"cpu": 0.75}'
    )
    assert timing is not None
    assert timing.samples_by_size == [[0.1, 0.2, 0.3]]
    assert timing.load_factor == pytest.approx(2.0)
    assert timing.cpu_seconds == 0.75


@pytest.mark.parametrize("cpu", ["", ', "cpu": -1', ', "cpu": "x"', ', "cpu": null'])
def test_parse_reach_probe_child_output_needs_the_childs_reported_cpu(
    cpu: str,
) -> None:
    assert (
        _parse_reach_probe_child_output(
            f'{{"results": [[0.1]], "reference": 0.1{cpu}}}'
        )
        is None
    )


def test_verdict_divides_measurements_by_the_load_factor() -> None:
    samples = [[0.008] * 5, [0.016] * 5]

    over_on_reference_host, extrapolated, _ratio, min_32, _median = (
        _reach_probe_verdict_from_samples(samples, _PATTERN_SAFETY_DEFAULT_CAP)
    )
    over_on_loaded_host, extrapolated_loaded, _ratio, min_32_loaded, _median = (
        _reach_probe_verdict_from_samples(samples, _PATTERN_SAFETY_DEFAULT_CAP, 4.0)
    )

    assert over_on_reference_host is True
    assert over_on_loaded_host is False
    assert min_32_loaded == pytest.approx(min_32 / 4.0)
    assert extrapolated_loaded == pytest.approx(extrapolated / 4.0)


def test_cost_reason_reports_the_load_factor() -> None:
    reason = _reach_probe_cost_reason(None, 0.2, 2.0, 262144, 0.025, 0.026, 2.5)
    assert "normalized by host load factor 2.50" in reason


def test_cost_reason_echoes_a_structural_violation_over_the_measurement() -> None:
    reason = _reach_probe_cost_reason("nested quantifier", 0.2, 2.0, 262144, 0.02, 0.02)
    assert reason == "nested quantifier"


_NO_WORK_COUNTER_SOURCE = "def build_work_counter():\n    return None\n"


@pytest.fixture
def measured_time_child(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_cost_arbiter."
        "_REACH_PROBE_TIMING_CHILD_SCRIPT",
        _reach_probe_timing_child_script(_NO_WORK_COUNTER_SOURCE),
    )


def test_probe_child_counts_one_deterministic_sample_per_probe() -> None:
    probes = [_repeat_probe_to_length("foo", size) for size in _REACH_PROBE_SIZES[-2:]]
    first = _time_reach_probes_subprocess(r"(?:foo|bar)+$", probes, _ample_budget())
    second = _time_reach_probes_subprocess(r"(?:foo|bar)+$", probes, _ample_budget())
    assert first is not None and second is not None
    assert first.samples_by_size == second.samples_by_size
    assert [len(row) for row in first.samples_by_size] == [1, 1]
    assert first.load_factor == 1.0


@pytest.mark.usefixtures("measured_time_child")
def test_probe_child_without_a_work_counter_measures_cpu_time() -> None:
    timing = _time_reach_probes_subprocess("abc", ["abcabc"], _ample_budget())
    assert timing is not None
    assert timing.load_factor != 1.0


@pytest.mark.usefixtures("measured_time_child")
def test_probe_child_takes_a_single_sample_below_the_full_sample_trigger() -> None:
    timing = _time_reach_probes_subprocess("abc", ["abcabc"], _ample_budget())
    assert timing is not None
    assert [len(row) for row in timing.samples_by_size] == [1]


@pytest.mark.usefixtures("measured_time_child")
def test_probe_child_takes_five_samples_when_every_probe_meets_the_trigger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_cost_arbiter."
        "_REACH_PROBE_FULL_SAMPLE_TRIGGER_SECONDS",
        0.0,
    )
    timing = _time_reach_probes_subprocess("abc", ["abcabc"], _ample_budget())
    assert timing is not None
    assert [len(row) for row in timing.samples_by_size] == [_REACH_PROBE_SAMPLE_COUNT]


@pytest.mark.redos_timing
@pytest.mark.usefixtures("measured_time_child")
def test_probe_child_stops_sampling_once_a_sample_is_large() -> None:
    probes = [_repeat_probe_to_length("foo", size) for size in _REACH_PROBE_SIZES[-2:]]
    timing = _time_reach_probes_subprocess(r"(?:foo|bar)+$", probes, _ample_budget())
    assert timing is not None
    largest = timing.samples_by_size[-1]
    assert largest[0] > _REACH_PROBE_LARGE_SAMPLE_SECONDS
    assert len(largest) < _REACH_PROBE_SAMPLE_COUNT


@pytest.mark.redos_timing
@pytest.mark.usefixtures("measured_time_child")
def test_reference_scan_costs_the_same_as_a_near_budget_builtin_probe() -> None:
    timing = _time_reach_probes_subprocess(
        _NEAR_BUDGET_SQLI_BUILTIN_PATTERN,
        [_NEAR_BUDGET_SQLI_BUILTIN_PROBE],
        _ample_budget(),
    )
    assert timing is not None
    (samples,) = timing.samples_by_size
    min_32 = samples[0]
    reference_seconds = timing.load_factor * _REFERENCE_SCAN_SECONDS
    ratio = min_32 / reference_seconds
    assert 0.5 <= ratio <= 2.0, (
        "near-budget sqli builtin probe at 32000 chars measured min "
        f"{min_32:.4f}s against a child reference of {reference_seconds:.4f}s "
        f"(load factor {timing.load_factor:.2f}), ratio={ratio:.2f}x, "
        "expected the reference scan to track the probe within [0.5, 2.0]"
    )


@pytest.mark.redos_timing
def test_sqli_comment_terminator_pairing_rejects_old_and_accepts_new() -> None:
    compiler = PatternCompiler()
    is_safe_old, reason_old = compiler.validate_pattern_safety(r"'\s*[\);]*\s*--")
    assert is_safe_old is False, (
        "expected the pre-fix sqli comment terminator alternative to be rejected "
        "once cross-atom class-intersection pairing reaches it, got safe="
        f"{is_safe_old} ({reason_old})"
    )
    is_safe_new, reason_new = compiler.validate_pattern_safety(
        _SQLI_COMMENT_TERMINATOR_RE
    )
    assert is_safe_new is True, (
        f"expected the linear rewrite to pass pattern safety validation, "
        f"got safe={is_safe_new} ({reason_new})"
    )


def test_sqli_comment_terminator_rewrite_matches_the_previous_pattern() -> None:
    _PREVIOUS_QUADRATIC_SQLI_COMMENT_TERMINATOR = r"'\s*[\);]*\s*--|'[\);]*#(?:\n|\Z)"
    candidates = [
        "'--",
        "' --",
        "');--",
        "') ; --",
        "';  --",
        "'  )  --",
        "' ) ) --",
        "'x--",
        "'-- ",
        "' ; ; --",
        "''--",
        "' -",
        "')-",
    ]
    for candidate in candidates:
        old_no_match = (
            re.search(_PREVIOUS_QUADRATIC_SQLI_COMMENT_TERMINATOR, candidate) is None
        )
        new_no_match = re.search(_SQLI_COMMENT_TERMINATOR_RE, candidate) is None
        assert old_no_match == new_no_match, (
            f"terminator rewrite diverged for {candidate!r}: "
            f"old no-match={old_no_match}, new no-match={new_no_match}"
        )


@pytest.mark.redos_timing
def test_sqli_comment_terminator_rewrite_is_linear_on_a_quote_then_spaces() -> None:
    probe = "'" + " " * 31999
    compiled = re.compile(_SQLI_COMMENT_TERMINATOR_RE)
    times = []
    for _ in range(5):
        start = time.process_time()
        compiled.search(probe)
        times.append(time.process_time() - start)
    min_time = min(times)
    assert min_time < 0.01, (
        "expected the linear rewrite to search a 32000-char quote-then-spaces probe "
        f"in under 0.01s of min-of-5 CPU time, measured {min_time:.4f}s"
    )
