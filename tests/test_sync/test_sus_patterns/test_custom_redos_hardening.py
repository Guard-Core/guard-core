import re
import subprocess
import sys
import time
from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.detection_engine._redos_ambiguous_tail import (
    _atom_char_set,
    _detect_ambiguous_optional_tail_in_quantified_group,
    _extract_literal_chars,
    _parse_brace_quantifier_with_variability,
    _parse_flat_quantified_atoms,
    _parse_flat_quantified_atoms_with_text,
    _representative_char_for_atom,
)
from guard_core.sync.detection_engine._redos_cost_arbiter import (
    _PATTERN_SAFETY_DEFAULT_CAP,
    _REACH_PROBE_SIZES,
    _reach_probe_verdict_from_samples,
    _time_reach_probes_subprocess,
)
from guard_core.sync.detection_engine._redos_literal_in_wildcard import (
    _detect_ambiguous_literal_boundary,
)
from guard_core.sync.detection_engine._redos_parse_slots import (
    _candidate_chars_for_atom_text,
)
from guard_core.sync.detection_engine._redos_probe_fill import (
    _reach_probe_candidate_builders,
    _repeat_probe_to_length,
)
from guard_core.sync.detection_engine._redos_structure import (
    _detect_adjacent_broad_unbounded_quantifiers,
    _detect_nested_unbounded_quantifier,
    _find_group_end,
    _iter_quantified_group_bodies,
    _normalize_group_inner,
    _split_top_level_alternations,
    _strip_escapes_and_char_classes,
    _unwrap_transparent_wrapper,
)
from guard_core.sync.detection_engine._redos_unreachable_terminator import (
    _detect_unreachable_terminator_scan,
    _quantifier_at_allows_zero,
    _skip_quantifier_at,
)
from guard_core.sync.detection_engine.compiler import PatternCompiler
from guard_core.sync.handlers.suspatterns_handler import (
    _PATTERN_SCAN_WINDOW_MATCHERS,
    _SCAN_WINDOW_PATTERNS,
    _WINDOWED_PATTERN_FINDERS,
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.sync.utils import _MAX_USER_AGENT_MATCH_LENGTH

_CONFIG = SecurityConfig(detection_compiler_timeout=2.0)
_BENIGN_MATCHING_PAYLOAD = "<script>alert(1)</script>"
_CUSTOM_MARKER = "zzq_custom_hardening_marker_zzq"
_CUSTOM_PATTERN = rf"{_CUSTOM_MARKER}\d+"

_SHIPPED_XSS_SCRIPT_TAG_PATTERN = r"<script[^>]*>[^<]*<\/script\s*>"
_SQLI_TAUTOLOGY_REQUIRED_ACCEPT_PATTERN = (
    r"(?i)\b(?:OR|AND)\s*(\d+|'[^']*'|\"[^\"]*\")\s*=\s*\1\b"
)
_SEMVER_SCAN_PATTERN = r"(?:v(?:\d+\.){1,}\d+){1,}$"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig(detection_compiler_timeout=2.0))
    sus_patterns_handler.compiled_custom_patterns = set()
    sus_patterns_handler.custom_patterns = set()


def test_overlapping_equal_literal_branches_flagged() -> None:
    assert _detect_nested_unbounded_quantifier(r"(b|b)*c") is not None
    assert _detect_nested_unbounded_quantifier(r"(q|q)*r") is not None


def test_overlapping_prefix_literal_branches_flagged() -> None:
    assert _detect_nested_unbounded_quantifier(r"(X|XY)*") is not None
    assert _detect_nested_unbounded_quantifier(r"(a|ab)*") is not None
    assert _detect_nested_unbounded_quantifier(r"(ab|abc)*") is not None


def test_disjoint_literal_branches_not_flagged() -> None:
    assert _detect_nested_unbounded_quantifier(r"(a|b)*") is None
    assert _detect_nested_unbounded_quantifier(r"(http|https)") is None
    assert _detect_nested_unbounded_quantifier(r"(?:[/\\][\w.\-~%]*)*") is None
    assert _detect_nested_unbounded_quantifier(r"(?:[\w.\-~%]+[/\\])*") is None
    assert _detect_nested_unbounded_quantifier(r"(a{2,4})*") is None


def test_char_class_overlap_branches_not_flagged() -> None:
    assert _detect_nested_unbounded_quantifier(r"(\w|\w)*x") is None
    assert _detect_nested_unbounded_quantifier(r"([^`\\n]|\\.)*") is None
    assert _detect_nested_unbounded_quantifier(r"([\w]|x)*") is None
    assert _detect_nested_unbounded_quantifier(r"([ab]|x)*") is None


def test_escape_inside_group_not_flagged() -> None:
    assert _detect_nested_unbounded_quantifier(r"(\.)+") is None
    assert _detect_nested_unbounded_quantifier(r"(\()") is None


def test_find_group_end_handles_unterminated_char_class() -> None:
    assert _find_group_end("(a[)*", 0) is None
    assert _detect_nested_unbounded_quantifier(r"(a[)*") is None


def test_strip_escapes_and_char_classes_handles_malformed() -> None:
    assert _strip_escapes_and_char_classes("abc[") == "abcX"
    assert _strip_escapes_and_char_classes("abc\\") == "abc\\"


@pytest.mark.redos_timing
def test_validate_pattern_safety_rejects_overlapping_alternation_with_tail() -> None:
    compiler = PatternCompiler()
    for pattern in [r"(b|b)*c", r"(q|q)*r"]:
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False, f"{pattern} was not rejected: {reason}"


@pytest.mark.redos_timing
def test_validate_pattern_safety_accepts_overlapping_alternation_with_no_tail() -> None:
    compiler = PatternCompiler()
    for pattern in [r"(X|XY)*", r"(a|ab)*"]:
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is True, (
            f"{pattern}: nothing forces failure after the trivial zero-rep "
            f"empty match, so re.search never needs to backtrack; {reason}"
        )


def test_extract_literal_chars_pulls_trigger_char() -> None:
    assert "b" in _extract_literal_chars(r"(b|b)*c")
    assert "q" in _extract_literal_chars(r"(q|q)*r")
    assert "X" in _extract_literal_chars(r"(X|XY)*")


def test_extract_literal_chars_represents_char_classes_with_escapes() -> None:
    chars = _extract_literal_chars(r"[\w]abc")
    assert chars == ["0", "a", "b", "c"]
    assert _extract_literal_chars(r"[\d\-]+") == ["0"]
    assert _extract_literal_chars(r"abc[") == ["a", "b", "c"]


def test_extract_literal_chars_represents_top_level_escape_atoms() -> None:
    assert "0" in _extract_literal_chars(r"abc\d")
    assert _extract_literal_chars(r"\w") == ["0"]
    assert _extract_literal_chars(r"a\sb") == ["a", " ", "b"]
    assert _extract_literal_chars(r"\d\w") == ["0", "0"]


def test_extract_literal_chars_skips_zero_width_escape_atoms() -> None:
    assert _extract_literal_chars(r"a\bb") == ["a", "b"]
    assert _extract_literal_chars(r"\b\d") == ["0"]


def test_split_top_level_alternations_handles_malformed() -> None:
    assert _split_top_level_alternations("a|b") == ["a", "b"]
    assert _split_top_level_alternations("a[") == ["a["]
    assert _split_top_level_alternations(r"\|") == [r"\|"]
    assert _split_top_level_alternations("(a|b)|c") == ["(a|b)", "c"]


def test_reach_probe_candidates_are_derived_from_the_patterns_own_literal_chars() -> (
    None
):
    builders = _reach_probe_candidate_builders(r"bbb", re.IGNORECASE | re.MULTILINE)
    assert builders
    probed_units = {builder(30) for builder in builders}
    assert any(unit.count("b") >= 10 for unit in probed_units), probed_units


@pytest.mark.redos_timing
def test_max_content_length_changes_the_verdict_for_the_same_quadratic_pattern() -> (
    None
):
    compiler = PatternCompiler()
    is_safe_at_ua_cap, _reason = compiler.validate_pattern_safety(
        r"(?:foo|bar)+$", max_content_length=_MAX_USER_AGENT_MATCH_LENGTH
    )
    is_safe_at_body_cap, _reason = compiler.validate_pattern_safety(
        r"(?:foo|bar)+$", max_content_length=_PATTERN_SAFETY_DEFAULT_CAP
    )
    assert is_safe_at_ua_cap is True
    assert is_safe_at_body_cap is False


def _non_windowed_builtin_patterns() -> list[str]:
    return [
        pattern
        for pattern, _ctx, _category in SusPatternsManager._pattern_definitions
        if pattern not in _WINDOWED_PATTERN_FINDERS
        and pattern not in _PATTERN_SCAN_WINDOW_MATCHERS
        and pattern not in _SCAN_WINDOW_PATTERNS
    ]


@pytest.mark.redos_timing
@pytest.mark.parametrize(
    "pattern", _non_windowed_builtin_patterns(), ids=lambda pattern: pattern[:40]
)
def test_validator_rejects_no_raw_search_builtin_pattern(
    pattern: str,
) -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(pattern)
    assert is_safe is True, f"{pattern!r} unexpectedly rejected: {reason}"


@pytest.mark.redos_timing
def test_shipped_xss_script_tag_pattern_flagged_by_hardened_validator() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(_SHIPPED_XSS_SCRIPT_TAG_PATTERN)
    assert is_safe is False
    assert "adjacent broad unbounded quantifiers" in reason.lower()


def test_detect_adjacent_broad_unbounded_quantifiers_flags_reduced_xss_shape() -> None:
    assert _detect_adjacent_broad_unbounded_quantifiers(r"[^>]*>[^<]*") is not None
    assert _detect_adjacent_broad_unbounded_quantifiers(r".*x.*") is not None
    assert _detect_adjacent_broad_unbounded_quantifiers(r"[\s\S]*x[^%]+") is not None


def test_detect_adjacent_broad_unbounded_quantifiers_ignores_single_quantifier() -> (
    None
):
    assert _detect_adjacent_broad_unbounded_quantifiers(r"[^>]*x") is None
    assert _detect_adjacent_broad_unbounded_quantifiers(r"foo.*bar") is None


def test_detect_adjacent_broad_unbounded_quantifiers_ignores_narrow_classes() -> None:
    assert _detect_adjacent_broad_unbounded_quantifiers(r"[a-z]*x[0-9]*") is None
    assert _detect_adjacent_broad_unbounded_quantifiers(r"\d+x\w+") is None
    assert _detect_adjacent_broad_unbounded_quantifiers(r"[^\S\r\n]*x[^\S\r\n]*") is (
        None
    )


def test_detect_adjacent_broad_unbounded_quantifiers_ignores_bounded_repetition() -> (
    None
):
    assert _detect_adjacent_broad_unbounded_quantifiers(r"[^>]{0,5}x[^<]{0,5}") is None


def test_detect_adjacent_broad_unbounded_quantifiers_ignores_alternation_siblings() -> (
    None
):
    assert (
        _detect_adjacent_broad_unbounded_quantifiers(
            _SQLI_TAUTOLOGY_REQUIRED_ACCEPT_PATTERN
        )
        is None
    )
    assert _detect_adjacent_broad_unbounded_quantifiers(r"(?:'[^']*'|\"[^\"]*\")") is (
        None
    )
    assert (
        _detect_adjacent_broad_unbounded_quantifiers(r"(?:'[^']*'|\"[^\"]*\")\s*=\s*\1")
        is None
    )


def test_detect_adjacent_broad_unbounded_quantifiers_flags_pair_inside_one_branch() -> (
    None
):
    assert (
        _detect_adjacent_broad_unbounded_quantifiers(r"(?:a|[^>]*b[^<]*c)") is not None
    )
    assert (
        _detect_adjacent_broad_unbounded_quantifiers(r"(?:x|(?:y|[^>]*b[^<]*c))")
        is not None
    )
    assert (
        _detect_adjacent_broad_unbounded_quantifiers(r"[^<>]*(?:foo|bar)[^\"']*")
        is not None
    )


def test_detect_adjacent_broad_unbounded_quantifiers_ignores_unterminated_group() -> (
    None
):
    assert _detect_adjacent_broad_unbounded_quantifiers(r"[^>]*x(unclosed") is None


def test_detect_adjacent_broad_unbounded_quantifiers_skips_backreference_group() -> (
    None
):
    assert (
        _detect_adjacent_broad_unbounded_quantifiers(r"(?P=n)[^>]*x[^<]*") is not None
    )


_DEEPLY_NESTED_ALTERNATION_PATTERN = ("(?:x|" * 25) + "z" + (")" * 25)


def test_detect_adjacent_broad_unbounded_quantifiers_fails_closed_past_depth_cap() -> (
    None
):
    reason = _detect_adjacent_broad_unbounded_quantifiers(
        _DEEPLY_NESTED_ALTERNATION_PATTERN
    )
    assert reason is not None
    assert "maximum group nesting depth" in reason


def test_detect_unreachable_terminator_scan_flags_prefix_with_disjoint_terminator() -> (
    None
):
    assert _detect_unreachable_terminator_scan(r"<script[^>]*>") is not None
    assert _detect_unreachable_terminator_scan(r"\$\([^)]+\)") is not None
    assert _detect_unreachable_terminator_scan(r"\$\{[^}]+\}") is not None


def test_detect_unreachable_terminator_scan_ignores_self_delimited_prefix() -> None:
    assert _detect_unreachable_terminator_scan(r"'[^']*'") is None
    assert _detect_unreachable_terminator_scan(r"\"[^\"]*\"") is None


def test_detect_unreachable_terminator_scan_ignores_missing_prefix() -> None:
    assert _detect_unreachable_terminator_scan(r"[^>]*x") is None


def test_detect_unreachable_terminator_scan_ignores_missing_terminator() -> None:
    assert _detect_unreachable_terminator_scan(r"javascript:\s*[^\s]+") is None


def test_detect_unreachable_terminator_scan_ignores_bounded_repetition() -> None:
    assert _detect_unreachable_terminator_scan(r"<script[^>]{0,5}>") is None


def test_detect_unreachable_terminator_scan_flags_dot_scan_with_lazy_quantifier() -> (
    None
):
    assert _detect_unreachable_terminator_scan(r"<!\[CDATA\[.*?\]\]>") is not None
    assert _detect_unreachable_terminator_scan(r"foo.*bar") is not None


def test_detect_unreachable_terminator_ignores_dot_scan_with_no_mandatory_tail() -> (
    None
):
    assert _detect_unreachable_terminator_scan(r"foo.*") is None


def test_detect_unreachable_terminator_ignores_terminator_reachable_from_prefix() -> (
    None
):
    assert _detect_unreachable_terminator_scan(r"foo.*foo") is None


def test_detect_unreachable_terminator_scan_ignores_negated_class_terminator() -> None:
    assert _detect_unreachable_terminator_scan(r"foo[^x]*[^y]") is None


def test_detect_unreachable_terminator_flags_zero_min_quantified_escape_prefix() -> (
    None
):
    assert _detect_unreachable_terminator_scan(r"\(\s*[^)]+=") is not None
    assert (
        _detect_unreachable_terminator_scan(r"\(\s*[|&]\s*\(\s*[^)]+=[*]") is not None
    )


def test_quantifier_at_allows_zero_true_for_star_and_optional() -> None:
    assert _quantifier_at_allows_zero(r"\s*x", 2) is True
    assert _quantifier_at_allows_zero(r"\s?x", 2) is True
    assert _quantifier_at_allows_zero(r"\s{0,5}x", 2) is True
    assert _quantifier_at_allows_zero(r"\s{,5}x", 2) is True


def test_quantifier_at_allows_zero_false_for_mandatory_quantifiers() -> None:
    assert _quantifier_at_allows_zero(r"\sx", 2) is False
    assert _quantifier_at_allows_zero(r"\s+x", 2) is False
    assert _quantifier_at_allows_zero(r"\s{1,5}x", 2) is False


def test_detect_ambiguous_literal_boundary_flags_class_that_absorbs_literal() -> None:
    assert _detect_ambiguous_literal_boundary(r"[\w-]*config[\w-]*\.env") is not None


def test_detect_ambiguous_literal_boundary_ignores_class_matching_nothing() -> None:
    assert _detect_ambiguous_literal_boundary(r"[^\x00-\xff]*config") is None


def test_detect_ambiguous_literal_boundary_ignores_disjoint_class() -> None:
    assert _detect_ambiguous_literal_boundary(r"[0-9]*config") is None


def test_detect_ambiguous_literal_boundary_ignores_single_char_literal() -> None:
    assert _detect_ambiguous_literal_boundary(r"[a-z]*x") is None


def test_detect_ambiguous_literal_boundary_ignores_unquantified_class() -> None:
    assert _detect_ambiguous_literal_boundary(r"[a-z]config") is None


def test_detect_ambiguous_literal_boundary_ignores_tautology_and_semver() -> None:
    assert (
        _detect_ambiguous_literal_boundary(_SQLI_TAUTOLOGY_REQUIRED_ACCEPT_PATTERN)
        is None
    )
    assert _detect_ambiguous_literal_boundary(_SEMVER_SCAN_PATTERN) is None


def test_skip_quantifier_at_rejects_unterminated_brace() -> None:
    assert _skip_quantifier_at("a{2,", 1) == 0


def test_skip_quantifier_at_rejects_malformed_brace_content() -> None:
    assert _skip_quantifier_at("a{2,x}", 1) == 0
    assert _skip_quantifier_at("a{,}", 1) == 0


def test_skip_quantifier_at_advances_past_lazy_brace_modifier() -> None:
    assert _skip_quantifier_at("a{2,3}?", 1) == 6


def test_detect_unreachable_terminator_scan_sees_through_transparent_group() -> None:
    assert _detect_unreachable_terminator_scan(r"://(?:[^/@\s]*@)") is None


def test_detect_unreachable_terminator_scan_ignores_tautology_and_semver() -> None:
    assert (
        _detect_unreachable_terminator_scan(_SQLI_TAUTOLOGY_REQUIRED_ACCEPT_PATTERN)
        is None
    )
    assert _detect_unreachable_terminator_scan(_SEMVER_SCAN_PATTERN) is None


@pytest.mark.redos_timing
def test_validate_pattern_safety_rejects_prefixed_broad_scan_with_own_terminator() -> (
    None
):
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(r"<script[^>]*>")
    assert is_safe is False
    assert "terminator" in reason.lower()


@pytest.mark.redos_timing
def test_validate_pattern_safety_rejects_single_broad_quantifier_with_no_prefix() -> (
    None
):
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(r"[^>]*x")
    assert is_safe is False, (
        "unanchored, this gives re.search a start position at every offset "
        f"in the input, each paying its own O(remaining) backtrack search "
        f"for the missing terminator; measures genuinely quadratic, got {reason}"
    )


@pytest.mark.redos_timing
def test_validate_pattern_safety_accepts_single_broad_quantifier_when_anchored() -> (
    None
):
    compiler = PatternCompiler()
    is_safe, _reason = compiler.validate_pattern_safety(r"^[^>]*x")
    assert is_safe is True


def test_detect_ambiguous_optional_tail_flags_unbounded_then_optional() -> None:
    assert _detect_ambiguous_optional_tail_in_quantified_group(r"(\w+\s?)*$")
    assert _detect_ambiguous_optional_tail_in_quantified_group(r"(\w+\s?)*")


def test_detect_ambiguous_optional_tail_agrees_with_and_without_leading_anchor() -> (
    None
):
    for body in (r"(\w+\s?)*$", r"(\s*\w+)*$", r"(a+b?)*"):
        unanchored = _detect_ambiguous_optional_tail_in_quantified_group(body)
        anchored = _detect_ambiguous_optional_tail_in_quantified_group("^" + body)
        assert unanchored is not None
        assert anchored is not None


def test_detect_ambiguous_optional_tail_flags_optional_then_unbounded() -> None:
    assert _detect_ambiguous_optional_tail_in_quantified_group(r"(\s*\w+)*$")


def test_detect_ambiguous_optional_tail_flags_mandatory_separator_sandwich() -> None:
    pattern = r"(?:[\w.\-~%]+[/\\][\w.\-~%]*)*"
    assert _detect_ambiguous_optional_tail_in_quantified_group(pattern) is not None


def test_detect_ambiguous_optional_tail_ignores_mandatory_pair() -> None:
    assert _detect_ambiguous_optional_tail_in_quantified_group(r"(a+b+)*") is None
    assert _detect_ambiguous_optional_tail_in_quantified_group(r"(ab)*") is None


def test_detect_ambiguous_optional_tail_ignores_disjoint_separator_groups() -> None:
    assert (
        _detect_ambiguous_optional_tail_in_quantified_group(r"(?:[/\\][\w.\-~%]*)*")
        is None
    )
    assert (
        _detect_ambiguous_optional_tail_in_quantified_group(r"(?:[\w.\-~%]+[/\\])*")
        is None
    )


def test_detect_ambiguous_optional_tail_ignores_single_unbounded_atom_group() -> None:
    assert _detect_ambiguous_optional_tail_in_quantified_group(r"(a+)*") is None


def test_detect_ambiguous_optional_tail_ignores_single_fixed_count_atom_group() -> None:
    assert _detect_ambiguous_optional_tail_in_quantified_group(r"(a{3})+") is None
    assert _detect_ambiguous_optional_tail_in_quantified_group(r"(\d{2})+") is None


def test_detect_ambiguous_optional_tail_flags_single_bounded_variable_atom_group() -> (
    None
):
    for pattern in (
        r"(a{2,4})*",
        r"(x{1,2})+",
        r"(\d{1,3})+",
        r"([a-f]{2,4})+",
    ):
        assert _detect_ambiguous_optional_tail_in_quantified_group(pattern) is not None


def test_detect_ambiguous_optional_tail_flags_bounded_mandatory_optional_pair() -> None:
    for body in (
        r"(\d\d?)+$",
        r"([0-9A-F][0-9A-F]?)+$",
        r"(aa?)+$",
        r"(\w\w?)+$",
    ):
        assert _detect_ambiguous_optional_tail_in_quantified_group(body) is not None, (
            body
        )


def test_detect_ambiguous_optional_tail_ignores_forced_delimiter_before_overlap() -> (
    None
):
    pattern = r"(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    assert _detect_ambiguous_optional_tail_in_quantified_group(pattern) is None


def test_parse_flat_quantified_atoms_with_text_rejects_malformed_brace() -> None:
    assert _parse_flat_quantified_atoms_with_text("a{,5}b+") is None


def test_parse_brace_quantifier_with_variability_rejects_unterminated_brace() -> None:
    assert _parse_brace_quantifier_with_variability("a{2,4", 1) is None


def test_parse_flat_quantified_atoms_with_text_skips_lazy_variable_brace() -> None:
    atoms = _parse_flat_quantified_atoms_with_text("a{1,2}?b")
    assert atoms == [("a", False, False, True), ("b", False, False, False)]


def test_atom_char_set_returns_empty_for_uncompilable_atom_text() -> None:
    assert _atom_char_set(r"\p") == frozenset()


def test_detect_ambiguous_optional_tail_ignores_uncompilable_atom() -> None:
    assert _detect_ambiguous_optional_tail_in_quantified_group(r"(\pa?)+") is None


def test_detect_ambiguous_optional_tail_ignores_unquantified_group() -> None:
    assert _detect_ambiguous_optional_tail_in_quantified_group(r"(ab)") is None


def test_detect_ambiguous_optional_tail_ignores_plain_text() -> None:
    assert _detect_ambiguous_optional_tail_in_quantified_group(r"abc") is None


def test_detect_ambiguous_optional_tail_handles_unclosed_group() -> None:
    assert _detect_ambiguous_optional_tail_in_quantified_group(r"(unclosed") is None


def test_detect_ambiguous_optional_tail_recurses_into_named_group() -> None:
    assert (
        _detect_ambiguous_optional_tail_in_quantified_group(r"(?P<n>a+\s?)*")
        is not None
    )


def test_detect_ambiguous_optional_tail_skips_nested_group_body() -> None:
    assert _detect_ambiguous_optional_tail_in_quantified_group(r"(a+(b)+c?)*") is None


def test_unwrap_transparent_wrapper_peels_repeated_plain_and_named_layers() -> None:
    assert _unwrap_transparent_wrapper(r"(\d{1,3}\d{1,3})") == r"\d{1,3}\d{1,3}"
    assert _unwrap_transparent_wrapper(r"?P<b>\d\d?") == r"?P<b>\d\d?"
    assert _unwrap_transparent_wrapper(r"(?P<b>\d\d?)") == r"\d\d?"
    assert _unwrap_transparent_wrapper(r"a+(b)+c?") == r"a+(b)+c?"
    assert _unwrap_transparent_wrapper(r"(a)b") == r"(a)b"


def test_unwrap_transparent_wrapper_stops_on_backreference() -> None:
    assert _unwrap_transparent_wrapper(r"(?P=n)") == r"(?P=n)"


def test_normalize_group_inner_rejects_unterminated_named_group() -> None:
    assert _normalize_group_inner("?P<unterminated") is None


_DEPTH_EXCEEDING_PATTERN = ("(?:" * 25) + "x" + (")+" * 25)


def test_detect_nested_unbounded_quantifier_fails_closed_past_depth_cap() -> None:
    reason = _detect_nested_unbounded_quantifier(_DEPTH_EXCEEDING_PATTERN)
    assert reason is not None
    assert "maximum group nesting depth" in reason


def test_detect_ambiguous_optional_tail_fails_closed_past_depth_cap() -> None:
    reason = _detect_ambiguous_optional_tail_in_quantified_group(
        _DEPTH_EXCEEDING_PATTERN
    )
    assert reason is not None
    assert "maximum group nesting depth" in reason


def test_iter_quantified_group_bodies_skips_unnormalizable_group() -> None:
    assert list(_iter_quantified_group_bodies(r"(?P=n)+$")) == []


def test_detect_ambiguous_optional_tail_skips_alternation_body() -> None:
    assert _detect_ambiguous_optional_tail_in_quantified_group(r"(a+|b?)*") is None


def test_parse_flat_quantified_atoms_rejects_group_or_alternation() -> None:
    assert _parse_flat_quantified_atoms("X(Y)") is None
    assert _parse_flat_quantified_atoms("X|Y") is None


def test_parse_flat_quantified_atoms_plain_atoms_are_mandatory() -> None:
    assert _parse_flat_quantified_atoms("XX") == [(False, False), (False, False)]
    assert _parse_flat_quantified_atoms("X") == [(False, False)]


def test_parse_flat_quantified_atoms_reads_symbol_quantifiers() -> None:
    assert _parse_flat_quantified_atoms("X+Y?") == [(False, True), (True, False)]
    assert _parse_flat_quantified_atoms("X*Y") == [(True, True), (False, False)]


def test_parse_flat_quantified_atoms_skips_lazy_symbol_quantifier() -> None:
    assert _parse_flat_quantified_atoms("X+?Y") == [(False, True), (False, False)]


def test_parse_flat_quantified_atoms_reads_brace_quantifiers() -> None:
    assert _parse_flat_quantified_atoms("X{2,}Y?") == [(False, True), (True, False)]
    assert _parse_flat_quantified_atoms("X{0,5}Y") == [(True, False), (False, False)]


def test_parse_flat_quantified_atoms_skips_lazy_brace_quantifier() -> None:
    assert _parse_flat_quantified_atoms("X{2,}?Y") == [(False, True), (False, False)]


def test_parse_flat_quantified_atoms_rejects_malformed_brace() -> None:
    assert _parse_flat_quantified_atoms("X{,5}Y+") is None
    assert _parse_flat_quantified_atoms("X{2Y+") is None


@pytest.mark.redos_timing
def test_validate_pattern_safety_rejects_ambiguous_optional_tail() -> None:
    compiler = PatternCompiler()
    for pattern in (r"(\w+\s?)*$", r"^(\w+\s?)*$", r"(\s*\w+)*$"):
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False, f"{pattern} was not rejected"
        assert "ambiguous optional tail" in reason.lower()


@pytest.mark.redos_timing
def test_validate_pattern_safety_rejects_bounded_mandatory_optional_pair() -> None:
    compiler = PatternCompiler()
    for pattern in (
        r"(\d\d?)+$",
        r"([0-9A-F][0-9A-F]?)+$",
        r"(aa?)+$",
        r"(\w\w?)+$",
    ):
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False, f"{pattern} was not rejected"
        assert "ambiguous optional tail" in reason.lower(), (pattern, reason)


@pytest.mark.redos_timing
def test_validate_pattern_safety_accepts_disjoint_and_fixed_length_corpus() -> None:
    compiler = PatternCompiler()
    safe_patterns = [
        r"(?:[/\\][\w.\-~%]*)*",
        r"(?:[\w.\-~%]+[/\\])*",
        r"BadBot|EvilCrawler",
        r"\A(?:\d{3}-)*\d{4}",
    ]
    for pattern in safe_patterns:
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is True, f"{pattern} was rejected: {reason}"


@pytest.mark.redos_timing
def test_validate_pattern_safety_rejects_quantifier_before_disjoint_literal() -> None:
    compiler = PatternCompiler()
    for pattern in (r"\d+abc", r"(ab{2})+$"):
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False, f"{pattern} was accepted: {reason}"


@pytest.mark.redos_timing
def test_validate_pattern_safety_accepts_required_accept_canaries() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(r"\A" + _SEMVER_SCAN_PATTERN)
    assert is_safe is True, reason
    is_safe, reason = compiler.validate_pattern_safety(
        _SQLI_TAUTOLOGY_REQUIRED_ACCEPT_PATTERN
    )
    assert is_safe is True, reason


@pytest.mark.redos_timing
@pytest.mark.parametrize("pattern", (r"(?:\d{3}-)*\d{4}", _SEMVER_SCAN_PATTERN))
def test_validate_pattern_safety_rejects_unanchored_repeated_scan(pattern: str) -> None:
    is_safe, reason = PatternCompiler().validate_pattern_safety(pattern)
    assert is_safe is False
    assert "CPU cost" in reason or "timeout" in reason


@pytest.mark.redos_timing
def test_semver_dot_separated_sample_stays_under_budget() -> None:
    unit = "v1."
    probes = [_repeat_probe_to_length(unit, size) for size in _REACH_PROBE_SIZES]
    timing = _time_reach_probes_subprocess(
        _SEMVER_SCAN_PATTERN, probes, time.monotonic() + 30.0
    )
    assert timing is not None
    over, extrapolated, ratio, min_32, median_32 = _reach_probe_verdict_from_samples(
        timing.samples_by_size, _PATTERN_SAFETY_DEFAULT_CAP, timing.load_factor
    )
    measurement = (
        f"{_SEMVER_SCAN_PATTERN} unit={unit!r}: growth ratio "
        f"{ratio:.2f}x per doubling, CPU time at 32000 chars min={min_32:.4f}s "
        f"median={median_32:.4f}s, extrapolated to body cap "
        f"({_PATTERN_SAFETY_DEFAULT_CAP} chars) = {extrapolated:.3f}s"
    )
    assert over is False, (
        f"{measurement}; the mandatory '.' separator between version segments "
        "was expected to keep this linear even under a non-aligned fill"
    )


@pytest.mark.redos_timing
def test_validate_pattern_safety_rejects_single_bounded_variable_atom() -> None:
    compiler = PatternCompiler()
    for pattern in (
        r"(x{1,2})+$",
        r"(\d{1,3})+$",
        r"([a-f]{2,4})+$",
        r"(a{2,4})*$",
    ):
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False, f"{pattern} was not rejected"
        assert "ambiguous optional tail" in reason.lower(), (pattern, reason)


@pytest.mark.redos_timing
def test_validate_pattern_safety_rejects_nested_and_named_group_wrapping() -> None:
    compiler = PatternCompiler()
    for pattern in (
        r"(?P<x>\d{1,3}\d{1,3})+$",
        r"((\d{1,3}\d{1,3}))+$",
        r"(?:(?:a|aa))+$",
        r"(?P<a>(?P<b>\d\d?))+$",
    ):
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False, f"{pattern} was not rejected"


@pytest.mark.redos_timing
def test_validate_pattern_safety_accepts_non_repeating_and_single_scan_shapes() -> None:
    compiler = PatternCompiler()
    for pattern in (r"(?:foo|bar)", r"foo+$"):
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is True, f"{pattern} was rejected: {reason}"


_CAP_AWARE_CANARIES: tuple[tuple[str, str], ...] = (
    (r"(?:foo|bar)+$", "foo"),
    (r"(?:foo)+$", "foo"),
    (r"(\d{2})+$", "00"),
    (r"(ab)+$", "ab"),
)


@pytest.mark.redos_timing
def test_validate_pattern_safety_cap_aware_quadratic_canaries() -> None:
    compiler = PatternCompiler()
    for pattern, unit in _CAP_AWARE_CANARIES:
        probes = [_repeat_probe_to_length(unit, size) for size in _REACH_PROBE_SIZES]
        timing = _time_reach_probes_subprocess(pattern, probes, time.monotonic() + 30.0)
        if timing is None:
            over_at_body_cap = True
            measurement = (
                f"{pattern} unit={unit!r}: probe subprocess did not complete "
                "within its own budget, treated as over-budget (fail closed)"
            )
        else:
            over_at_body_cap, extrapolated, ratio, min_32, median_32 = (
                _reach_probe_verdict_from_samples(
                    timing.samples_by_size,
                    _PATTERN_SAFETY_DEFAULT_CAP,
                    timing.load_factor,
                )
            )
            measurement = (
                f"{pattern} unit={unit!r}: growth ratio {ratio:.2f}x per doubling, "
                f"CPU time at 32000 chars min={min_32:.4f}s median={median_32:.4f}s, "
                f"extrapolated to body cap ({_PATTERN_SAFETY_DEFAULT_CAP} chars) = "
                f"{extrapolated:.3f}s"
            )

        is_safe_body, reason_body = compiler.validate_pattern_safety(
            pattern, max_content_length=_PATTERN_SAFETY_DEFAULT_CAP
        )
        assert is_safe_body is (not over_at_body_cap), (
            f"{measurement}; validator said safe={is_safe_body} ({reason_body})"
        )

        if timing is None:
            continue

        is_safe_ua, reason_ua = compiler.validate_pattern_safety(
            pattern, max_content_length=_MAX_USER_AGENT_MATCH_LENGTH
        )
        assert is_safe_ua is True, (
            f"{measurement}; at UA cap ({_MAX_USER_AGENT_MATCH_LENGTH} chars) a "
            f"quadratic pattern is microseconds and must accept, got "
            f"safe={is_safe_ua} ({reason_ua})"
        )


@pytest.mark.redos_timing
def test_validate_pattern_safety_never_hangs_on_a_structurally_evasive_pattern() -> (
    None
):
    script = (
        "from guard_core.sync.detection_engine.compiler import PatternCompiler\n"
        "compiler = PatternCompiler()\n"
        "safe, reason = compiler.validate_pattern_safety(r'(?P<x>a+)*$')\n"
        "print(safe, reason)\n"
    )

    try:
        completed = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=90.0,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(
            "validate_pattern_safety hung past a 90s bound (generous over the "
            "arbiter's own 40s per-candidate-unit killable-subprocess ceiling) "
            "on (?P<x>a+)*$. The runtime probe must never execute a candidate "
            "pattern on a thread the caller can't kill."
        )

    assert completed.returncode == 0, completed.stderr
    assert "False" in completed.stdout


def test_windowed_patterns_are_exactly_the_scan_window_converted_six() -> None:
    assert len(_WINDOWED_PATTERN_FINDERS) == 6
    windowed_pattern_sources = set(_WINDOWED_PATTERN_FINDERS)
    builtin_pattern_sources = {
        pattern for pattern, _ctx, _category in SusPatternsManager._pattern_definitions
    }
    assert windowed_pattern_sources <= builtin_pattern_sources


@pytest.mark.redos_timing
def test_validator_keeps_benign_custom_corpus_safe() -> None:
    compiler = PatternCompiler()
    benign_custom = [
        r"attackterm\d+",
        r"<custom>\w+</custom>",
        r"https?://example\.com",
        r"\bword\b",
        r"(a|b)",
    ]
    rejected = []
    for pattern in benign_custom:
        is_safe, _reason = compiler.validate_pattern_safety(pattern)
        if not is_safe:
            rejected.append(pattern)
    assert rejected == [], f"benign custom patterns falsely rejected: {rejected}"


@pytest.mark.redos_timing
def test_overlapping_alternation_pattern_rejected_at_registration() -> None:
    ok = SusPatternsManager.add_pattern(r"(b|b)*c", custom=True)
    assert ok is False
    assert r"(b|b)*c" not in sus_patterns_handler.custom_patterns


@pytest.mark.redos_timing
def test_full_byte_range_pattern_rejected_at_registration() -> None:
    pattern = r"^[\x00-\xff]*[\x00-\xfe]+$"
    ok = SusPatternsManager.add_pattern(pattern, custom=True)
    assert ok is False
    assert pattern not in sus_patterns_handler.custom_patterns


def test_custom_pattern_routed_through_pool_path() -> None:
    SusPatternsManager.add_pattern(_CUSTOM_PATTERN, custom=True)

    captured: list[bool] = []
    original = PatternCompiler.create_async_safe_finditer_matcher

    def _spy(
        self: PatternCompiler,
        pattern: str | re.Pattern,
        timeout: float | None = None,
        inline_safe: bool = False,
        worker_wrapper: Any = None,
    ) -> Callable[[str], list[re.Match]]:
        captured.append(inline_safe)
        return original(
            self,
            pattern,
            timeout=timeout,
            inline_safe=inline_safe,
            worker_wrapper=worker_wrapper,
        )

    with patch.object(PatternCompiler, "create_async_safe_finditer_matcher", _spy):
        result = sus_patterns_handler.detect(
            f"{_CUSTOM_MARKER}12345", "1.2.3.4", "request_body"
        )

    assert result["is_threat"] is True
    assert captured.count(False) >= 1


def test_built_in_pattern_routed_through_inline_safe_path() -> None:
    captured: list[bool] = []
    original = PatternCompiler.create_async_safe_finditer_matcher

    def _spy(
        self: PatternCompiler,
        pattern: str | re.Pattern,
        timeout: float | None = None,
        inline_safe: bool = False,
        worker_wrapper: Any = None,
    ) -> Callable[[str], list[re.Match]]:
        captured.append(inline_safe)
        return original(
            self,
            pattern,
            timeout=timeout,
            inline_safe=inline_safe,
            worker_wrapper=worker_wrapper,
        )

    with patch.object(PatternCompiler, "create_async_safe_finditer_matcher", _spy):
        result = sus_patterns_handler.detect(
            _BENIGN_MATCHING_PAYLOAD, "1.2.3.4", "request_body"
        )

    assert result["is_threat"] is True
    assert captured.count(True) >= 1


def test_built_in_detect_is_fast_and_non_blocking() -> None:
    samples: list[float] = []
    for _ in range(5):
        start = time.process_time()
        result = sus_patterns_handler.detect(
            _BENIGN_MATCHING_PAYLOAD, "1.2.3.4", "request_body"
        )
        samples.append(time.process_time() - start)
        assert result["is_threat"] is True

    assert min(samples) < 2.0


def test_candidate_chars_for_atom_text_returns_empty_for_unparseable_text() -> None:
    assert _candidate_chars_for_atom_text("[unterminated", 0) == frozenset()


def test_candidate_chars_for_atom_text_returns_empty_for_a_multi_atom_text() -> None:
    assert _candidate_chars_for_atom_text("ab", 0) == frozenset()


def test_candidate_chars_for_atom_text_includes_the_range_start() -> None:
    chars = _candidate_chars_for_atom_text(r"[Ѐ-ӿ]", 0)
    assert "Ѐ" in chars


def test_representative_char_for_atom_falls_back_to_class_candidates_beyond_printable() -> (  # noqa: E501
    None
):
    assert _representative_char_for_atom(r"[Ѐ-ӿ]") == "Ѐ"
    assert _representative_char_for_atom(r"[一-鿿]") == "一"
    assert _representative_char_for_atom(r"[\U0001F600-\U0001F64F]") == "\U0001f600"


def test_representative_char_for_atom_finds_the_boundary_just_past_a_negated_range() -> (  # noqa: E501
    None
):
    assert _representative_char_for_atom(r"[^\x00-\x7f]") == "\x80"


def test_representative_char_for_atom_stays_none_when_the_class_matches_nothing() -> (
    None
):
    assert _representative_char_for_atom(r"[^\x00-\U0010FFFF]") is None


_CONFIRMED_FALSE_SAFE_WORD_BOUNDARY_PATTERN = r"^[↞-▞]+\w+$"
_CONFIRMED_FALSE_SAFE_GROUP_VARIANTS = (
    r"^(?:[↞-▞])+\w+$",
    r"^(?:[↞-▞]+)\w+$",
    r"^(?:[↞-▞]+\w+)$",
)
_PUNCTUATION_OVERLAP_CLASS_INTERSECTION_PATTERN = "^\\W*[ -⁳]+$"

_CLASS_INTERSECTION_REGRESSION_REJECT_PATTERNS: tuple[str, ...] = (
    _CONFIRMED_FALSE_SAFE_WORD_BOUNDARY_PATTERN,
    *_CONFIRMED_FALSE_SAFE_GROUP_VARIANTS,
    _PUNCTUATION_OVERLAP_CLASS_INTERSECTION_PATTERN,
    r"^[\U0001F900-\U0001FAA0a]*([\U0001F900-\U0001FAA0b])+$",
    r"^\d*[\U00010000-\U0010FFFEz]+$",
    r"[Ѐ-ӿ]*[а-я]+$",
    r"[\x00-\U0001F600]*[\x00-\U0001F5FF]+$",
    r"^[\x00-\xff]*[\x00-\xfe]+$",
    r"^[c-w]*(?:[g-z][g-z]|[g-z][g-z][g-z])*$",
    r"^[a-z]*[A-Z]+X$",
    r"^[a\x80-\xff]*[b\x80-\xff]+$",
    r"^[a-c]+(?:[b-c])[b-d]+$",
    r"(?i)[k]*[K]+$",
)

_CLASS_INTERSECTION_REGRESSION_ACCEPT_PATTERNS: tuple[str, ...] = (
    r"^(?:[a-z]+@[a-z]+\.[a-z]{2,})$",
    r"^[\s\S]*[\s\S]+$",
    r"^[Ѐ-ӿ]+$",
    r"^[一-鿿]+$",
    r"^[^\x00-\x7f]+$",
)


@pytest.mark.redos_timing
@pytest.mark.parametrize("pattern", _CLASS_INTERSECTION_REGRESSION_REJECT_PATTERNS)
def test_validate_pattern_safety_rejects_the_class_intersection_regression_corpus(
    pattern: str,
) -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(pattern)
    assert is_safe is False, f"{pattern!r} was accepted: {reason}"


@pytest.mark.redos_timing
@pytest.mark.parametrize("pattern", _CLASS_INTERSECTION_REGRESSION_ACCEPT_PATTERNS)
def test_validate_pattern_safety_accepts_the_class_intersection_regression_corpus(
    pattern: str,
) -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(pattern)
    assert is_safe is True, f"{pattern!r} was rejected: {reason}"
