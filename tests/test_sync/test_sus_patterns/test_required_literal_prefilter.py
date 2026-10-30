import re
from typing import Any
from unittest.mock import patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers import _suspatterns_regex
from guard_core.sync.handlers._suspatterns_literals import (
    fold_for_literals,
    required_literals,
    rows_with_required_literal,
)
from guard_core.sync.handlers._suspatterns_pattern_table import _PATTERN_DEFINITIONS
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sus_patterns.test_detection_benchmark import (
    BENIGN_CORPUS,
    MALICIOUS_CORPUS,
)
from tests.test_sync.conftest import SyncMockGuardRequest

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
def test_folded_look_alikes_are_still_flagged(value: str) -> None:
    request = SyncMockGuardRequest(path="/s", query_params={"q": value})

    result = detect_penetration_attempt(request, SyncSecurityConfig(enable_redis=False))

    ascii_twin = SyncMockGuardRequest(
        path="/s", query_params={"q": value.translate(str.maketrans("ıİſK", "iisk"))}
    )
    twin = detect_penetration_attempt(
        ascii_twin, SyncSecurityConfig(enable_redis=False)
    )
    assert result.is_threat is twin.is_threat


def test_a_bare_look_alike_opener_has_the_verdict_of_the_ascii_one() -> None:
    config = SyncSecurityConfig(enable_redis=False)
    plain = detect_penetration_attempt(
        SyncMockGuardRequest(path="/s", query_params={"q": "<script>"}), config
    )
    folded = detect_penetration_attempt(
        SyncMockGuardRequest(path="/s", query_params={"q": "<ſcrıpt>"}), config
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


def _rows_reached(prefilter: bool) -> int:
    calls: list[str] = []
    original = _suspatterns_regex._SusPatternsRegexMixin._check_regex_pattern

    def counting(self: Any, pattern: Any, *args: Any, **kwargs: Any) -> Any:
        calls.append(pattern.pattern)
        return original(self, pattern, *args, **kwargs)

    def keep_all(rows: Any, _folded: str, _excluded: Any) -> Any:
        return iter(rows)

    with patch.object(
        _suspatterns_regex._SusPatternsRegexMixin, "_check_regex_pattern", counting
    ):
        if prefilter:
            _scan_benign()
        else:
            with patch.object(
                _suspatterns_regex, "rows_with_required_literal", keep_all
            ):
                _scan_benign()
    return len(calls)


def _scan_benign() -> None:
    detect_penetration_attempt(
        SyncMockGuardRequest(path="/s", query_params={"q": "red shoes size 9"}),
        SyncSecurityConfig(enable_redis=False),
    )


def test_a_benign_value_reaches_far_fewer_rows() -> None:
    with_prefilter = _rows_reached(True)
    without = _rows_reached(False)

    assert 0 < with_prefilter < without * 0.6
