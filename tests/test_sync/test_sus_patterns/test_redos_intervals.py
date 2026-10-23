import importlib
import random
import re
from typing import cast

import pytest

from guard_core.sync.detection_engine._redos_ignorecase_fold import (
    _EXPAND_IGNORECASE_MEMBER_SCAN_CEILING,
    _expand_ignorecase_by_group_scan,
    _expand_ignorecase_by_member_scan,
    _fold_group_by_code_point,
    _fold_partners,
    expand_ignorecase,
)
from guard_core.sync.detection_engine._redos_intervals import (
    MAX_CODE_POINT,
    MIN_CODE_POINT,
    _IntervalSet,
    cached_category_intervals,
)
from guard_core.sync.detection_engine._redos_parse_slots import (
    _cached_class_node_predicate,
    _category_intervals,
    _class_node_predicate,
    _node_intervals,
    _regex_parser,
)


def test_empty_set_has_no_members() -> None:
    empty = _IntervalSet.empty()
    assert empty.is_empty() is True
    assert empty.first_member() is None
    assert empty.contains(0) is False


def test_full_set_contains_the_entire_range() -> None:
    full = _IntervalSet.full()
    assert full.is_empty() is False
    assert full.contains(MIN_CODE_POINT) is True
    assert full.contains(MAX_CODE_POINT) is True
    assert full.first_member() == MIN_CODE_POINT


def test_single_builds_a_one_code_point_set() -> None:
    single = _IntervalSet.single(65)
    assert single.contains(65) is True
    assert single.contains(64) is False
    assert single.contains(66) is False
    assert single.first_member() == 65


def test_from_range_builds_an_inclusive_range() -> None:
    interval = _IntervalSet.from_range(10, 20)
    assert interval.contains(10) is True
    assert interval.contains(20) is True
    assert interval.contains(9) is False
    assert interval.contains(21) is False


def test_from_range_returns_empty_when_low_exceeds_high() -> None:
    assert _IntervalSet.from_range(20, 10).is_empty() is True


def test_from_range_clips_to_the_valid_code_point_span() -> None:
    interval = _IntervalSet.from_range(-5, MAX_CODE_POINT + 50)
    assert interval.contains(MIN_CODE_POINT) is True
    assert interval.contains(MAX_CODE_POINT) is True


def test_union_merges_adjacent_and_overlapping_intervals() -> None:
    adjacent = _IntervalSet.from_range(0, 10).union(_IntervalSet.from_range(11, 20))
    assert adjacent.contains(10) is True
    assert adjacent.contains(11) is True
    assert adjacent.first_member() == 0

    overlapping = _IntervalSet.from_range(0, 10).union(_IntervalSet.from_range(5, 15))
    assert overlapping.contains(15) is True


def test_union_keeps_disjoint_intervals_separate() -> None:
    merged = _IntervalSet.from_range(0, 5).union(_IntervalSet.from_range(10, 15))
    assert merged.contains(7) is False
    assert merged.contains(3) is True
    assert merged.contains(12) is True


def test_intersection_finds_the_overlap() -> None:
    a = _IntervalSet.from_range(0, 10)
    b = _IntervalSet.from_range(5, 15)
    overlap = a.intersection(b)
    assert overlap.contains(5) is True
    assert overlap.contains(10) is True
    assert overlap.contains(4) is False
    assert overlap.contains(11) is False


def test_intersection_of_disjoint_sets_is_empty() -> None:
    a = _IntervalSet.from_range(0, 5)
    b = _IntervalSet.from_range(10, 15)
    assert a.intersection(b).is_empty() is True


def test_complement_of_empty_is_full() -> None:
    assert _IntervalSet.empty().complement() == _IntervalSet.full()


def test_complement_of_full_is_empty() -> None:
    assert _IntervalSet.full().complement().is_empty() is True


def test_complement_finds_the_gap_around_an_interval() -> None:
    complement = _IntervalSet.from_range(10, 20).complement()
    assert complement.contains(9) is True
    assert complement.contains(21) is True
    assert complement.contains(15) is False
    assert complement.contains(MIN_CODE_POINT) is True
    assert complement.contains(MAX_CODE_POINT) is True


def test_difference_removes_the_other_sets_members() -> None:
    diff = _IntervalSet.from_range(0, 20).difference(_IntervalSet.from_range(10, 30))
    assert diff.contains(5) is True
    assert diff.contains(10) is False


def test_component_first_members_returns_the_start_of_each_interval() -> None:
    combined = _IntervalSet.from_range(0, 5).union(_IntervalSet.from_range(10, 15))
    assert combined.component_first_members() == (0, 10)


def test_equality_and_hash_depend_on_the_normalized_intervals() -> None:
    split = _IntervalSet.from_range(0, 5).union(_IntervalSet.from_range(6, 10))
    whole = _IntervalSet.from_range(0, 10)
    assert split == whole
    assert hash(split) == hash(whole)


def test_equality_returns_notimplemented_for_a_non_interval_set() -> None:
    assert _IntervalSet.single(1).__eq__(object()) is NotImplemented
    assert _IntervalSet.single(1) != object()


def test_repr_includes_the_class_name() -> None:
    assert "_IntervalSet" in repr(_IntervalSet.single(1))


def test_cached_category_intervals_builds_once_and_reuses_the_cache() -> None:
    calls: list[int] = []

    def predicate(code_point: int) -> bool:
        calls.append(code_point)
        return code_point == 42

    first = cached_category_intervals("test-cache-key-unique-9f1c", predicate)
    calls_after_first_build = len(calls)
    second = cached_category_intervals("test-cache-key-unique-9f1c", predicate)
    assert first is second
    assert len(calls) == calls_after_first_build
    assert first.contains(42) is True
    assert first.contains(41) is False


def test_expand_ignorecase_adds_the_kelvin_sign_for_k() -> None:
    expanded = expand_ignorecase(_IntervalSet.single(ord("k")), ascii_only=False)
    assert expanded.contains(ord("K")) is True
    assert expanded.contains(0x212A) is True


def test_expand_ignorecase_adds_dotless_i_for_i() -> None:
    expanded = expand_ignorecase(_IntervalSet.single(ord("i")), ascii_only=False)
    assert expanded.contains(ord("I")) is True
    assert expanded.contains(0x131) is True


def test_expand_ignorecase_ascii_only_excludes_the_kelvin_sign() -> None:
    expanded = expand_ignorecase(_IntervalSet.single(ord("k")), ascii_only=True)
    assert expanded.contains(ord("K")) is True
    assert expanded.contains(0x212A) is False


def test_expand_ignorecase_ascii_only_excludes_dotless_i() -> None:
    expanded = expand_ignorecase(_IntervalSet.single(ord("i")), ascii_only=True)
    assert expanded.contains(ord("I")) is True
    assert expanded.contains(0x131) is False


@pytest.mark.parametrize("char", ["K", "ſ", "ı", "İ", "é"])
def test_ascii_fold_of_non_ascii_literal_matches_engine(char: str) -> None:
    original = _IntervalSet.single(ord(char))
    expanded = expand_ignorecase(original, ascii_only=True)
    assert expanded == original
    assert _expand_ignorecase_by_group_scan(original, ascii_only=True) == expanded
    compiled = re.compile(re.escape(char), re.ASCII | re.IGNORECASE)
    for candidate in (*map(chr, range(128)), char):
        assert expanded.contains(ord(candidate)) is (
            compiled.fullmatch(candidate) is not None
        )


def test_class_predicate_cache_evicts_old_patterns() -> None:
    _cached_class_node_predicate.cache_clear()
    first = _class_node_predicate(_regex_parser.LITERAL, 0, 0)
    assert _class_node_predicate(_regex_parser.LITERAL, 0, 0) is first
    for code_point in range(1, 1100):
        predicate = _class_node_predicate(_regex_parser.LITERAL, code_point, 0)
        assert predicate(code_point)
        assert not predicate(code_point + 1)
    assert _cached_class_node_predicate.cache_info().currsize == 1024
    assert _class_node_predicate(_regex_parser.LITERAL, 0, 0) is not first
    assert first(0)


def test_expand_ignorecase_is_a_no_op_for_a_class_with_no_case_partners() -> None:
    digits = _IntervalSet.from_range(ord("0"), ord("9"))
    assert expand_ignorecase(digits, ascii_only=False) == digits


def test_expand_ignorecase_member_scan_skips_an_already_seen_group() -> None:
    both = _IntervalSet.single(ord("k")).union(_IntervalSet.single(ord("K")))
    expanded = _expand_ignorecase_by_member_scan(both, ascii_only=False)
    assert expanded.contains(0x212A) is True


def test_expand_ignorecase_by_group_scan_matches_the_member_scan_for_k() -> None:
    base = _IntervalSet.single(ord("k"))
    via_member_scan = _expand_ignorecase_by_member_scan(base, ascii_only=False)
    via_group_scan = _expand_ignorecase_by_group_scan(base, ascii_only=False)
    assert via_member_scan == via_group_scan


def test_expand_ignorecase_group_scan_skips_fully_non_ascii_groups() -> None:
    wide = _IntervalSet.from_range(0, _EXPAND_IGNORECASE_MEMBER_SCAN_CEILING + 1)
    expanded = _expand_ignorecase_by_group_scan(wide, ascii_only=True)
    assert expanded.contains(0x212A) is False


def test_expand_ignorecase_dispatches_to_group_scan_above_the_member_ceiling() -> None:
    wide = _IntervalSet.from_range(0, _EXPAND_IGNORECASE_MEMBER_SCAN_CEILING + 1)
    via_dispatch = expand_ignorecase(wide, ascii_only=False)
    via_group_scan = _expand_ignorecase_by_group_scan(wide, ascii_only=False)
    assert via_dispatch == via_group_scan


def test_fold_group_by_code_point_maps_k_to_its_group() -> None:
    mapping = _fold_group_by_code_point()
    assert ord("K") in mapping[ord("k")]


def test_fold_partners_restricts_to_ascii_when_requested() -> None:
    group = frozenset({ord("k"), ord("K"), 0x212A})
    assert _fold_partners(group, ascii_only=False) == group
    assert _fold_partners(group, ascii_only=True) == frozenset({ord("k"), ord("K")})


def _engine_ignorecase_fixes() -> dict[int, tuple[int, ...]]:
    # re._casefix._EXTRA_CASES from 3.11, re._compiler._ignorecase_fixes before.
    try:
        return cast(
            dict[int, tuple[int, ...]],
            importlib.import_module("re._casefix")._EXTRA_CASES,
        )
    except ImportError:
        return cast(
            dict[int, tuple[int, ...]],
            importlib.import_module("sre_compile")._ignorecase_fixes,
        )


_NAMED_MULTI_CHAR_FOLD_PAIRS = (
    (0x390, 0x1FD3),
    (0x3B0, 0x1FE3),
    (0xFB05, 0xFB06),
)


def test_fold_groups_unite_the_named_multi_char_fold_pairs() -> None:
    mapping = _fold_group_by_code_point()
    for a, b in _NAMED_MULTI_CHAR_FOLD_PAIRS:
        group = mapping.get(a)
        assert group is not None, hex(a)
        assert b in group, (hex(a), hex(b))
        assert re.fullmatch("(?i)" + chr(a), chr(b)) is not None
        assert re.fullmatch("(?i)" + chr(b), chr(a)) is not None


def test_fold_groups_still_unite_kelvin_sign_and_dotless_i() -> None:
    mapping = _fold_group_by_code_point()
    assert 0x212A in mapping[ord("k")]
    assert 0x131 in mapping[ord("i")]


def test_fold_groups_contain_every_engine_ignorecase_fixes_pair() -> None:
    mapping = _fold_group_by_code_point()
    table = _engine_ignorecase_fixes()
    assert len(table) > 0
    for code_point, partners in table.items():
        group = mapping.get(code_point)
        assert group is not None, hex(code_point)
        for partner in partners:
            assert partner in group, (hex(code_point), hex(partner))


def test_fold_groups_put_capital_i_with_dot_in_the_group_of_i() -> None:
    mapping = _fold_group_by_code_point()
    assert 0x130 in mapping[ord("i")]
    assert re.fullmatch("(?i)i", "\u0130") is not None


def test_fold_groups_are_bidirectionally_confirmed_by_the_engine() -> None:
    mapping = _fold_group_by_code_point()
    checked = 0
    for group in {frozenset(g) for g in mapping.values()}:
        members = sorted(group)
        for a in members:
            char_a = chr(a)
            for b in members:
                if a == b:
                    continue
                char_b = chr(b)
                assert re.fullmatch("(?i)" + re.escape(char_a), char_b) is not None
                assert re.fullmatch("(?i)" + re.escape(char_b), char_a) is not None
                checked += 1
    assert checked > 0


def test_word_category_contains_circled_digit_and_excludes_general_punctuation() -> (
    None
):
    intervals = _category_intervals(_regex_parser.CATEGORY_WORD, 0)
    assert intervals.contains(0x2460) is True
    assert intervals.contains(0x2000) is False


def test_ascii_word_category_excludes_a_non_ascii_letter() -> None:
    intervals = _category_intervals(_regex_parser.CATEGORY_WORD, re.ASCII)
    assert intervals.contains(ord("e")) is True
    assert intervals.contains(0x00E9) is False


def _interval_set_for(pattern: str, flags: int) -> _IntervalSet:
    parsed = _regex_parser.parse(pattern, flags)
    op, av = parsed.data[0]
    return _node_intervals(op, av, parsed.state.flags)


_RANDOM_CLASS_KINDS = ("literal", "range", "category")
_RANDOM_CLASS_CATEGORIES = (r"\d", r"\D", r"\s", r"\S", r"\w", r"\W")


def _random_class_piece(rng: random.Random) -> str:
    kind = rng.choice(_RANDOM_CLASS_KINDS)
    if kind == "literal":
        return re.escape(chr(rng.randint(0x20, 0x2FFFF)))
    if kind == "range":
        low = rng.randint(0x20, 0x2FFFF)
        high = low + rng.randint(0, 500)
        return f"{re.escape(chr(low))}-{re.escape(chr(high))}"
    return rng.choice(_RANDOM_CLASS_CATEGORIES)


def _random_class_text(rng: random.Random) -> tuple[str, int]:
    piece_count = rng.randint(1, 3)
    pieces = [_random_class_piece(rng) for _ in range(piece_count)]
    negate = "^" if rng.random() < 0.3 else ""
    flags = re.IGNORECASE if rng.random() < 0.5 else 0
    return f"[{negate}{''.join(pieces)}]", flags


_RANDOM_CLASS_SEED = 20260906


def test_interval_set_contains_matches_re_fullmatch_over_random_small_classes() -> None:
    rng = random.Random(_RANDOM_CLASS_SEED)
    checked_classes = 0
    for _ in range(300):
        pattern, flags = _random_class_text(rng)
        try:
            compiled = re.compile(pattern, flags)
        except re.error:
            continue
        interval_set = _interval_set_for(pattern, flags)
        for _sample in range(200):
            code_point = rng.randint(MIN_CODE_POINT, MAX_CODE_POINT)
            expected = compiled.fullmatch(chr(code_point)) is not None
            assert interval_set.contains(code_point) is expected, (
                pattern,
                flags,
                code_point,
            )
        checked_classes += 1
    assert checked_classes > 0
