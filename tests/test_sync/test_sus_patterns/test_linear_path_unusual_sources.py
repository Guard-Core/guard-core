import re

from guard_core.sync.handlers._suspatterns_linear_path import linear_path_finder
from guard_core.sync.handlers._suspatterns_linear_path_source import (
    mandatory_characters,
    row_pieces,
)

# A verbose-mode comment may hold unmatched parentheses, so a paren count never sees
# the guard group of this chain close.
_GUARD_WITH_PARENS_IN_A_COMMENT = "(?:(?!a # ((\n)[\\w.\\-~%]+[/\\\\])*"


def test_a_guard_whose_group_never_closes_is_not_read_as_a_linear_row() -> None:
    assert row_pieces(_GUARD_WITH_PARENS_IN_A_COMMENT) is None
    pattern = re.compile(_GUARD_WITH_PARENS_IN_A_COMMENT, re.VERBOSE)

    assert linear_path_finder(pattern) is None


def test_a_lookahead_over_a_character_range_is_a_mandatory_set() -> None:
    assert mandatory_characters("x(?=[a-c])", 0) == (
        frozenset({"x", "X"}),
        frozenset({"a", "b", "c", "A", "B", "C"}),
    )


def test_a_lookahead_over_literals_and_a_range_is_a_mandatory_set() -> None:
    assert mandatory_characters("(?=[a-bz])", 0) == (
        frozenset({"a", "b", "z", "A", "B", "Z"}),
    )


def test_a_lookahead_over_a_character_class_is_not_a_mandatory_set() -> None:
    assert mandatory_characters(r"(?=[\d])", 0) == ()
