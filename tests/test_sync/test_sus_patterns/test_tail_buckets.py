import importlib
import random
import re
from typing import Any

import pytest

from guard_core.sync.handlers._suspatterns_inline_matches import _BUILTIN_ROW_FLAGS
from guard_core.sync.handlers._suspatterns_linear_path import _row_for
from guard_core.sync.handlers._suspatterns_linear_path_source import (
    without_unbalanced_parentheses,
)
from guard_core.sync.handlers._suspatterns_pattern_table import _PATTERN_DEFINITIONS
from guard_core.sync.handlers._suspatterns_tail_buckets import (
    BucketedTail,
    _branch_key,
    _text_key,
    split_alternation,
)

_PARSER = importlib.import_module("re._parser")
_LONG_TAIL = 2000


def _long_tail_rows() -> list[tuple[str, str]]:
    rows = []
    for source, _contexts, _category in _PATTERN_DEFINITIONS:
        row = _row_for(source, _BUILTIN_ROW_FLAGS)
        if row is not None:
            tail = without_unbalanced_parentheses(row._raw_pieces[-1])
            if len(tail) > _LONG_TAIL:
                rows.append((source, tail))
    return rows


def _names(nodes: Any) -> list[str]:
    """Every string a literal-only alternation can match, from the parsed pattern."""
    results = [""]
    for operation, argument in nodes:
        kind = str(operation)
        if kind == "LITERAL":
            results = [text + chr(argument) for text in results]
        elif kind == "SUBPATTERN":
            options = _names(argument[3])
            results = [text + option for text in results for option in options]
        elif kind == "BRANCH":
            options = [name for branch in argument[1] for name in _names(branch)]
            results = [text + option for text in results for option in options]
        else:
            return results
    return results


def _texts(parts: tuple[str, ...]) -> list[str]:
    parsed = _PARSER.parse("(?:" + "|".join(parts) + ")", _BUILTIN_ROW_FLAGS)
    texts = []
    for name in _names(parsed):
        for suffix in ("", "/x", "?q=1", " ", "\n", ".php/"):
            texts += [name + suffix, name.upper() + suffix, "a/" + name]
    generator = random.Random(1)
    alphabet = "abcmqzx0.php/_ 小专Kſ"
    for _ in range(3000):
        length = generator.randint(0, 12)
        texts.append("".join(generator.choice(alphabet) for _ in range(length)))
    return texts


def test_there_are_two_long_tail_rows() -> None:
    assert len(_long_tail_rows()) == 2


@pytest.mark.parametrize(("source", "tail"), _long_tail_rows())
def test_a_bucketed_tail_answers_as_the_whole_pattern_does(
    source: str, tail: str
) -> None:
    parts = split_alternation(tail)
    assert parts is not None
    bucketed = BucketedTail(parts, _BUILTIN_ROW_FLAGS)
    whole = re.compile(tail, _BUILTIN_ROW_FLAGS)
    hits = 0
    for text in _texts(parts.branches):
        for position in {0, len(text) // 2, len(text)}:
            expected = whole.match(text, position)
            found = bucketed.match(text, position)
            assert (expected is None) == (found is None), (text, position)
            if expected is not None and found is not None:
                assert expected.end() == found.end(), (text, position)
                hits += 1
    assert hits > 300


@pytest.mark.parametrize(("source", "tail"), _long_tail_rows())
def test_a_long_tail_row_flags_every_name_it_names_and_only_those(
    source: str, tail: str
) -> None:
    row = _row_for(source, _BUILTIN_ROW_FLAGS)
    assert row is not None
    parts = split_alternation(tail)
    assert parts is not None
    compiled = re.compile(source, re.IGNORECASE)
    for text in _texts(parts.branches):
        for candidate in (text, "/" + text, "a/b/" + text):
            assert bool(list(row.find(candidate))) == (
                compiled.search(candidate) is not None
            ), candidate


def test_a_tail_that_is_not_one_alternation_behind_a_lookahead_is_not_split() -> None:
    assert split_alternation("(?:a|b)x") is None
    assert split_alternation("(?=[a])ab") is None
    assert split_alternation("(?=[a])(?:a|b") is None


def test_a_nested_group_around_the_alternation_is_unwrapped() -> None:
    parts = split_alternation(r"(?=[ab])(?:(?:a(?:x|y)|b))\Z")
    assert parts is not None
    assert parts.branches == ("a(?:x|y)", "b")
    assert parts.suffix == r"\Z"


def test_a_class_with_a_bar_or_paren_does_not_split_a_branch() -> None:
    parts = split_alternation(r"(?=[a])(?:a[|)]b|a\|c)")
    assert parts is not None
    assert parts.branches == ("a[|)]b", r"a\|c")


@pytest.mark.parametrize(
    ("branch", "key"),
    [
        ("abc", "a"),
        ("Abc", "a"),
        (r"\.php", "."),
        (r"\ x", " "),
        ("a?bc", None),
        (r"\.?bc", None),
        ("a*", None),
        ("(?:ab)", None),
        ("[ab]c", None),
        (r"\dx", None),
        ("", None),
        ("小组", "小"),
        ("Éa", None),
    ],
)
def test_the_first_character_a_branch_must_match(branch: str, key: str | None) -> None:
    assert _branch_key(branch) == key


@pytest.mark.parametrize(
    ("char", "key"),
    [
        ("A", "a"),
        ("7", "7"),
        ("小", "小"),
        ("ſ", "s"),
        ("K", "k"),
        ("İ", "i"),
        ("É", "*"),
    ],
)
def test_the_key_of_the_character_at_the_match_position(char: str, key: str) -> None:
    assert _text_key(char) == key


def test_a_bucketed_tail_with_no_branch_for_a_character_has_no_match() -> None:
    parts = split_alternation("(?=[ab])(?:ax|by)")
    assert parts is not None
    bucketed = BucketedTail(parts, re.IGNORECASE)
    assert bucketed.match("zx") is None
    assert bucketed.match("") is None
    assert bucketed.match("ax") is not None
    assert bucketed.match("AX") is not None
    assert bucketed.match("by", 0) is not None


def test_a_branch_that_may_start_with_anything_joins_every_bucket() -> None:
    parts = split_alternation("(?=[abc])(?:ax|(?:b|c)y|a?z)")
    assert parts is not None
    bucketed = BucketedTail(parts, re.IGNORECASE)
    assert bucketed.match("cy") is not None
    assert bucketed.match("z") is None
    assert bucketed.match("az") is not None
    assert bucketed.match("Éy") is None
