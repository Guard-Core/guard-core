import re

import pytest

from guard_core.handlers import _suspatterns_linear_path_source as source_module
from guard_core.handlers._suspatterns_lazy_rows import COMPILED_BUILTIN_PATTERNS
from guard_core.handlers._suspatterns_linear_path import (
    _LinearPathRow,
    linear_path_finder,
)
from guard_core.handlers._suspatterns_linear_path_source import (
    row_pieces,
    split_on_chains,
    without_unbalanced_parentheses,
)

_ALTERNATION = r"\A[/\\]?(?:[\w.\-~%]+[/\\])*a|b"


def _found(pattern: re.Pattern, text: str) -> list[str]:
    """What the scan finds for ``pattern``: the linear finder when the row has one."""
    finder = linear_path_finder(pattern)
    matches = pattern.finditer(text) if finder is None else finder(text)
    return [match.group() for match in matches]


def _row_pieces_before_the_alternation_refusal(
    source: str,
) -> tuple[list[str], list[str | None]] | None:
    pieces, guards = split_on_chains(source)
    if not guards:
        return None
    if (
        without_unbalanced_parentheses(pieces[0])
        not in source_module._LEADING_SEPARATORS
    ):
        return None
    for interior in pieces[1:-1]:
        if not source_module._is_separator_terminated_literal(interior):
            return None
    return pieces, guards


def test_a_top_level_alternation_is_found_like_the_regex_finds_it() -> None:
    pattern = re.compile(_ALTERNATION)

    assert _found(pattern, "x/b") == ["b"]
    assert _found(pattern, "x/b") == [m.group() for m in pattern.finditer("x/b")]


@pytest.mark.parametrize(
    "source",
    [
        _ALTERNATION,
        r"a|\A[/\\]?(?:[\w.\-~%]+[/\\])*b",
        r"(?i)x|y(?:[\w.\-~%]+[/\\])*z",
    ],
)
def test_a_source_with_a_top_level_alternation_is_not_a_linear_row(
    source: str,
) -> None:
    assert row_pieces(source) is None


def test_an_alternation_inside_a_group_or_a_class_does_not_refuse_a_row() -> None:
    assert row_pieces(r"\A[/\\]?(?:[\w.\-~%]+[/\\])*(?:a|b)") is not None
    assert row_pieces(r"\A[/\\]?(?:[\w.\-~%]+[/\\])*[a|b]c") is not None


def test_every_builtin_row_splits_as_it_did_before_the_alternation_refusal() -> None:
    for source in COMPILED_BUILTIN_PATTERNS:
        assert row_pieces(source) == _row_pieces_before_the_alternation_refusal(
            source
        ), source


def test_a_row_whose_built_pattern_misses_yields_what_the_regex_yields() -> None:
    pieces, guards = ["\\A[/\\\\]?", "a|b"], [None]
    row = _LinearPathRow(0, pieces, guards, _ALTERNATION)

    for text in ("x/b", "b", "/x/a", "x/y/b b"):
        expected = [m.group() for m in re.compile(_ALTERNATION).finditer(text)]
        assert [m.group() for m in row.find(text)] == expected
