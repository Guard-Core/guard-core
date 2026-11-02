import re
from typing import Any
from unittest.mock import patch

import pytest

from guard_core.handlers import _suspatterns_regex
from guard_core.handlers._suspatterns_literals import (
    fold_for_literals,
    required_literals,
    rows_with_required_literal,
)
from guard_core.handlers._suspatterns_pattern_table import _PATTERN_DEFINITIONS
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest
from tests.test_sus_patterns.test_detection_benchmark import (
    BENIGN_CORPUS,
    MALICIOUS_CORPUS,
)

_SPECIAL = {"i": ["ı", "İ"], "s": ["ſ"], "k": ["K"]}


def _variants(text: str) -> list[str]:
    variants = [text, text.upper(), text.swapcase()]
    for letter, replacements in _SPECIAL.items():
        for replacement in replacements:
            variants.append(re.sub(letter, replacement, text, flags=re.IGNORECASE))
            variants.append(text.replace(letter, replacement, 1))
    return variants


CORPUS_TEXTS = sorted(
    {case.payload for case in MALICIOUS_CORPUS}
    | {case.payload for case in BENIGN_CORPUS}
)
ROWS = [
    (re.compile(source, re.IGNORECASE), source)
    for source, _c, _k in _PATTERN_DEFINITIONS
]


def test_a_matching_row_always_has_its_required_literal_in_the_folded_text() -> None:
    violations: list[str] = []
    for text in CORPUS_TEXTS:
        for variant in _variants(text):
            folded = fold_for_literals(variant)
            for pattern, source in ROWS:
                literals = required_literals(source)
                if (
                    literals
                    and pattern.search(variant)
                    and not any(literal in folded for literal in literals)
                ):
                    violations.append(f"{source[:60]!r} on {variant[:40]!r}")
    assert violations == []


def test_the_rows_with_a_requirement_are_most_of_the_table() -> None:
    covered = sum(1 for _p, source in ROWS if required_literals(source))
    assert covered >= 120


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (r"\bwget\s+--post-file", ("--post-file",)),
        (r"(?:foo|barbaz)\s", ("foo", "barbaz")),
        (r"abcd?", ("abc",)),
        (r"ab(?:cdef)?gh", ()),
        (r"(?:ab|cde)", ()),
        (r"(?i)UNION\s+SELECT", ("select",)),
        (r"x{2,}longword", ("longword",)),
        (r"(?:longword)+tail", ("longword",)),
        (r"(?=lookahead)real", ("lookahead",)),
        (r"[a-z]+", ()),
        (r"héllowörld", ()),
        (r"(unclosed", ()),
    ],
)
def test_the_extracted_requirement(source: str, expected: tuple[str, ...]) -> None:
    assert required_literals(source) == expected


@pytest.mark.parametrize(
    ("text", "folded"),
    [
        ("İ", "i"),
        ("ı", "i"),
        ("ſ", "s"),
        ("K", "k"),
        ("UNION", "union"),
    ],
)
def test_the_fold_maps_the_four_characters_ignorecase_matches(
    text: str, folded: str
) -> None:
    assert fold_for_literals(text) == folded
    assert re.fullmatch(folded, text, re.IGNORECASE)


@pytest.mark.parametrize(
    "value",
    [
        "1 unıon ſelect password from users",
        "1 UNİON SELECT password FROM users",
        "<ſcrıpt>alert(1)</ſcrıpt>",
        "<scrİpt>alert(1)</scrİpt>",
        "1 union ſelect password from users",
        "; wget --Key x",
    ],
)
async def test_folded_look_alikes_are_still_flagged(value: str) -> None:
    request = MockGuardRequest(path="/s", query_params={"q": value})

    result = await detect_penetration_attempt(
        request, SecurityConfig(enable_redis=False)
    )

    ascii_twin = MockGuardRequest(
        path="/s", query_params={"q": value.translate(str.maketrans("ıİſK", "iisk"))}
    )
    twin = await detect_penetration_attempt(
        ascii_twin, SecurityConfig(enable_redis=False)
    )
    assert result.is_threat is twin.is_threat


async def test_a_bare_look_alike_opener_has_the_verdict_of_the_ascii_one() -> None:
    config = SecurityConfig(enable_redis=False)
    plain = await detect_penetration_attempt(
        MockGuardRequest(path="/s", query_params={"q": "<script>"}), config
    )
    folded = await detect_penetration_attempt(
        MockGuardRequest(path="/s", query_params={"q": "<ſcrıpt>"}), config
    )

    assert folded.is_threat is plain.is_threat


def test_rows_without_the_literal_are_left_out_and_excluded_sources_stay() -> None:
    rows: list[Any] = [
        (re.compile(r"needle", re.IGNORECASE), frozenset(), "c"),
        (re.compile(r"hay[a-z]+", re.IGNORECASE), frozenset(), "c"),
    ]

    kept = list(rows_with_required_literal(rows, "stack hay", frozenset()))
    assert [row[0].pattern for row in kept] == ["hay[a-z]+"]

    kept = list(rows_with_required_literal(rows, "stack hay", frozenset({"needle"})))
    assert [row[0].pattern for row in kept] == ["needle", "hay[a-z]+"]


async def _rows_reached(prefilter: bool) -> int:
    calls: list[str] = []
    original = _suspatterns_regex._SusPatternsRegexMixin._check_regex_pattern

    async def counting(self: Any, pattern: Any, *args: Any, **kwargs: Any) -> Any:
        calls.append(pattern.pattern)
        return await original(self, pattern, *args, **kwargs)

    def keep_all(rows: Any, _folded: str, _excluded: Any) -> Any:
        return iter(rows)

    with patch.object(
        _suspatterns_regex._SusPatternsRegexMixin, "_check_regex_pattern", counting
    ):
        if prefilter:
            await _scan_benign()
        else:
            with patch.object(
                _suspatterns_regex, "rows_with_required_literal", keep_all
            ):
                await _scan_benign()
    return len(calls)


async def _scan_benign() -> None:
    await detect_penetration_attempt(
        MockGuardRequest(path="/s", query_params={"q": "red shoes size 9"}),
        SecurityConfig(enable_redis=False),
    )


async def test_a_benign_value_reaches_far_fewer_rows() -> None:
    with_prefilter = await _rows_reached(True)
    without = await _rows_reached(False)

    assert 0 < with_prefilter < without * 0.6


@pytest.mark.parametrize(
    "content",
    [
        pytest.param("hello", id="by-substring"),
        pytest.param("hello" * 1000, id="by-presence"),
    ],
)
def test_a_custom_row_is_never_skipped_by_a_required_literal(content: str) -> None:
    custom = (re.compile("[xyz]7", re.IGNORECASE), frozenset({"all"}), "custom")
    builtin = (re.compile("[xyz]7", re.IGNORECASE), frozenset({"all"}), "xss")
    assert required_literals("[xyz]7") == ("x", "y", "z")
    kept = list(
        rows_with_required_literal(
            [custom, builtin], fold_for_literals(content), frozenset()
        )
    )
    assert kept == [custom]
