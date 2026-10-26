import random
import re

import pytest

from guard_core._utils.pair_redaction import _PAIR_HEAD_RE
from guard_core._utils.pair_value_scan import (
    _EXTENDED_NAME_RUN_RE,
    _PAIR_START_RE,
    _SOFT_GAP_THEN_PAIR_RE,
)

_OLD_NAME_RUN = r"(?:[A-Za-z0-9_.\-]|%[0-9A-Fa-f]{2}|\+)+"
_OLD_ASSIGN = r"[^\S\r\n]*[=:][^\S\r\n]*"
_OLD_PAIR_START = _OLD_NAME_RUN + _OLD_ASSIGN
_OLD_PAIRS = [
    (_EXTENDED_NAME_RUN_RE, re.compile(_OLD_NAME_RUN)),
    (_PAIR_START_RE, re.compile(_OLD_PAIR_START)),
    (
        _SOFT_GAP_THEN_PAIR_RE,
        re.compile(r"([^\S\r\n]*)(" + _OLD_PAIR_START + ")?"),
    ),
    (
        _PAIR_HEAD_RE,
        re.compile(
            rf"(?P<name>\"{_OLD_NAME_RUN}\"|'{_OLD_NAME_RUN}'|{_OLD_NAME_RUN})"
            r"(?P<assign>(?:[^\S\r\n]*[=:])+[^\S\r\n]*)?"
        ),
    ),
]
_ALPHABET = list("aZ09_.-%+ \t\r\n:='\"/é") + ["%41", "%zz", "%4", "::", "  "]
_STRINGS = 6000


def _spans(match: re.Match | None) -> tuple | None:
    if match is None:
        return None
    return (
        match.span(),
        tuple(match.span(index) for index in range(1, (match.re.groups or 0) + 1)),
    )


@pytest.mark.parametrize(
    ("new", "old"), _OLD_PAIRS, ids=["name", "pair_start", "soft_gap", "pair_head"]
)
def test_the_flat_form_gives_the_frame_heavy_forms_matches(
    new: re.Pattern, old: re.Pattern
) -> None:
    generator = random.Random(20261026)
    matched = 0
    for _ in range(_STRINGS):
        value = "".join(
            generator.choice(_ALPHABET) for _ in range(generator.randint(0, 24))
        )
        pos = generator.randint(0, len(value))
        assert _spans(new.match(value, pos)) == _spans(old.match(value, pos)), value
        assert [_spans(m) for m in new.finditer(value, pos)] == [
            _spans(m) for m in old.finditer(value, pos)
        ], value
        matched += old.match(value, pos) is not None
    assert matched > _STRINGS // 20
