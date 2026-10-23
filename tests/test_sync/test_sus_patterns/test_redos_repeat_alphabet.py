import re
import time
from unittest.mock import patch

import pytest

from guard_core.sync.detection_engine._redos_cost_arbiter import (
    _reach_probe_cost_verdict,
)
from guard_core.sync.detection_engine._redos_repeat_alphabet import (
    _has_large_bounded_repeat,
    _repeat_alphabet_fills,
)
from guard_core.sync.detection_engine._redos_repeat_prefix import (
    _repeat_reaching_prefixes,
)
from guard_core.sync.detection_engine._redos_stray_chooser import (
    _build_stray_context,
    choose_repeat_unit_stray,
)
from guard_core.sync.detection_engine.compiler import PatternCompiler


@pytest.mark.parametrize(
    "pattern,fill",
    [
        (r"[\s\S]+[^\u2603]", "☃"),
        (r"\s*[\s\S]+([^\u2603])", "☃"),
        (r"(?:[\s\S])+[^\u2603]", "☃"),
        (r"(?s:.+)(?ai:[^k])", "K"),
        (r"(?s:.+)(?ai:[^K])", "K"),
        (r"[\s\S]+[^\u2602\u2603][^\u2603\u2604]", "☃"),
    ],
)
def test_repeat_alphabet_has_a_representative_for_restrictive_tail(
    pattern: str, fill: str
) -> None:
    fills = _repeat_alphabet_fills(pattern, re.IGNORECASE | re.MULTILINE)
    assert fill in fills
    assert re.search(pattern, fill * 16, re.IGNORECASE | re.MULTILINE) is None


@pytest.mark.parametrize("pattern", ["abc", "[unterminated", r"[^\s\S]+"])
def test_repeat_alphabet_without_a_repeatable_atom(pattern: str) -> None:
    assert _repeat_alphabet_fills(pattern, 0) == []


def test_repeat_alphabet_respects_construction_deadline() -> None:
    with pytest.raises(TimeoutError, match="deadline"):
        _repeat_alphabet_fills(r"[\s\S]+[^\u2603]", 0, time.thread_time() - 1)


def test_repeat_alphabet_treats_large_variable_bounded_atoms_as_repeatable() -> None:
    assert _repeat_alphabet_fills(r"a{0,4096}a{0,4096}X", 0) == ["a"]
    assert _has_large_bounded_repeat(r"a{0,4096}a{0,4096}X", 0)


@pytest.mark.parametrize(
    "pattern,prefix",
    [
        (r"(?:foo|bar)[\s\S]+[\s\S]+[^\u2603]", "foo"),
        (r"(?:safe|X)[\s\S]+[\s\S]+[^\u2603]", "X"),
        (r"\A[XY][\s\S]+[\s\S]+[^\u2603]", "X"),
        (r"(?i:foo)[\s\S]+[\s\S]+[^\u2603]", "foo"),
        (r"foo[XY](?:bar)[\s\S]+[\s\S]+[^\u2603]", "fooXbar"),
        (r"\A[0-2]a{3}[XY][\s\S]+[\s\S]+[^\u2603]", "0aaaX"),
        (r"\A(?=foo)foo[\s\S]+[\s\S]+[^\u2603]", "foo"),
    ],
)
def test_repeat_prefixes_reach_repeats_after_engine_tokens(
    pattern: str, prefix: str
) -> None:
    prefixes = _repeat_reaching_prefixes(pattern, re.IGNORECASE | re.MULTILINE)
    assert any(candidate.casefold() == prefix.casefold() for candidate in prefixes)


@pytest.mark.redos_timing
@pytest.mark.parametrize(
    "pattern",
    [
        r"(?:foo|bar)[\s\S]+[\s\S]+[^\u2603]",
        r"\A(?:foo|bar)[\s\S]+[\s\S]+[^\u2603]",
        r"\A[XY][\s\S]+[\s\S]+[^\u2603]",
        r"(?:safe|X[\s\S]+[\s\S]+[^\u2603])",
        r"\A(?=foo)[\s\S]+[\s\S]+[^\u2603]",
        r"\A(?=foo)f..[\s\S]+[\s\S]+[^\u2603]",
        r"\A(?!X)[XY][\s\S]+[\s\S]+[^\u2603]",
        r"(?<=foo)[\s\S]+[\s\S]+[^\u2603]",
        r"\A([XY])\1a+a+$",
        r"\A[XY]a+a+.$",
        r"\A[XY]a{0,4095}a{0,4095}X",
        r"\A[XY](?<!X)a+a+$",
        r"\A(?=([XY]))\1a+a+$",
        r"\A(?=f?oo)fooa+a+$",
        r"\A(?=f{0,1}oo)fooa+a+$",
        r"\Axf?(?<=f)a+a+$",
        r"\Axf?(?<!x)a+a+$",
        r"\A(?=(?=foo))fooa+a+$",
        r"\A(?=(?=f.o))fooa+a+$",
        r"\A(?=f.o)fooa+a+$",
        r"\A(?=f[o-p]o)fpoa+a+$",
        r"\A(?:safea+|(?=f.o)fooa+a+)$",
        r"\A[XY]XX(?<!XXX)a+a+$",
        r"(?:[a-m][n-z])*(?:[a-m][n-z])*X",
        r"(?:[a-m][n-z])+(?:[a-m][n-z])+X",
        r"(?:[a-m][n-z]){0,100000}(?:[a-m][n-z]){0,100000}X",
    ],
)
def test_repeat_prefixes_reject_hidden_restarts(pattern: str) -> None:
    safe, reason = PatternCompiler().validate_pattern_safety(pattern)
    assert not safe, reason


@pytest.mark.parametrize("quantifier", ["{0,2}", "{2}", "{0,32}", "{0,4095}", "{4095}"])
def test_repeat_alphabet_covers_small_and_fixed_bounds(quantifier: str) -> None:
    assert "☃" in _repeat_alphabet_fills(r"[\s\S]" + quantifier + r"[^\u2603]", 0)


@pytest.mark.redos_timing
@pytest.mark.parametrize("quantifier", ["{0,256}", "{0,4095}", "{4095}"])
def test_bounded_repeat_below_large_repeat_cutoff_is_not_a_safety_bypass(
    quantifier: str,
) -> None:
    safe, reason = PatternCompiler().validate_pattern_safety(
        r"[\s\S]" + quantifier + r"[^\u2603]"
    )
    assert not safe, reason


@pytest.mark.parametrize(
    "pattern",
    [r"\Aa{0,32}X", r"\Aa{4096}X", r"\A(?:a{0,32}|b{0,32})X"],
)
def test_large_bounded_repeat_risk_ignores_fixed_and_small_bounds(pattern: str) -> None:
    assert not _has_large_bounded_repeat(pattern, 0)


def test_large_bounded_repeat_risk_descends_into_groups() -> None:
    assert _has_large_bounded_repeat(r"\A(?:x|a{0,4096})X", 0)
    assert not _has_large_bounded_repeat("[unterminated", 0)


def test_validation_rejects_when_construction_consumes_remaining_budget() -> None:
    with (
        patch(
            "guard_core.sync.detection_engine._redos_cost_arbiter."
            "_reach_probe_candidate_builders",
            return_value=[],
        ),
        patch(
            "guard_core.sync.detection_engine._redos_cost_arbiter._remaining_budget",
            return_value=0.0,
        ),
    ):
        safe, reason = _reach_probe_cost_verdict("a+", None)
    assert not safe
    assert "construction exceeded its deadline" in reason


@pytest.mark.redos_timing
def test_large_bounded_repeat_is_rejected_within_the_short_child_timeout() -> None:
    safe, reason = PatternCompiler().validate_pattern_safety(r"a{0,100000}a{0,100000}X")
    assert not safe
    assert "killable-subprocess timeout" in reason


@pytest.mark.redos_timing
@pytest.mark.parametrize("pattern", [r"\Aa{0,32}X", r"\Aa{4096}X"])
def test_short_and_fixed_bounded_repeats_remain_accepted(pattern: str) -> None:
    safe, reason = PatternCompiler().validate_pattern_safety(pattern)
    assert safe, reason


def test_stray_verification_respects_shared_construction_deadline() -> None:
    ctx = _build_stray_context("a+", 0, time.thread_time() - 1)
    with pytest.raises(TimeoutError, match="deadline"):
        choose_repeat_unit_stray(ctx, "a")


def test_validation_fails_closed_when_probe_construction_expires() -> None:
    with patch(
        "guard_core.sync.detection_engine._redos_cost_arbiter."
        "_reach_probe_candidate_builders",
        side_effect=TimeoutError("construction deadline"),
    ):
        safe, reason = _reach_probe_cost_verdict("a+", None)
    assert not safe
    assert "deadline" in reason


@pytest.mark.redos_timing
@pytest.mark.parametrize(
    "pattern",
    [
        r"[\s\S]+[^\u2603]",
        r"\s*[\s\S]+([^\u2603])",
        r"(?:[\s\S])+[^\u2603]",
        r"(?s:.+)(?ai:[^K])",
        r"[\s\S]+[^\u2602\u2603][^\u2603\u2604]",
    ],
)
def test_restrictive_tail_restart_is_rejected(pattern: str) -> None:
    safe, reason = PatternCompiler().validate_pattern_safety(pattern)
    assert not safe, reason


@pytest.mark.redos_timing
@pytest.mark.parametrize(
    "pattern", [r"\A[\s\S]+[^\u2603]", r"\A(?s:.+)(?ai:[^K])", r"[\s\S]+"]
)
def test_linear_repeat_with_same_alphabet_remains_accepted(pattern: str) -> None:
    safe, reason = PatternCompiler().validate_pattern_safety(pattern)
    assert safe, reason
