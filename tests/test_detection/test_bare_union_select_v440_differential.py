import json
from pathlib import Path

import pytest

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

# 6336 seeded union-select shapes (leading and trailing comments, comment runs,
# parentheses, backslash, quotes, Unicode spaces, zero-width characters, %0a forms,
# case mixes, ALL, terminators) on the three surfaces. "v440" holds the indexes
# v4.4.0 (66f3072e) flagged on a default config, computed once by
# ledger_gaps/verify/wp128/run_shapes.py and stored, never computed at test time (D-74,
# zero loss against v4.4.0). "bare_row_only" holds a tenth of the indexes only the
# bare UNION SELECT row flags.
_TESTS_DIR = next(parent for parent in Path(__file__).parents if parent.name == "tests")
_DATA = json.loads(
    (_TESTS_DIR / "test_detection" / "data" / "bare_union_select_v440.json").read_text()
)
_SHAPES: list[str] = _DATA["shapes"]
_SURFACES = ["q", "header", "path"]


def _request(surface: str, value: str) -> MockGuardRequest:
    if surface == "q":
        return MockGuardRequest(path="/s", query_params={"q": value})
    if surface == "header":
        return MockGuardRequest(path="/s", headers={"x-foo": value})
    return MockGuardRequest(path="/" + value.replace(" ", "%20"))


@pytest.mark.parametrize("surface", _SURFACES)
async def test_every_shape_v440_flags_is_flagged_on_the_default_config(
    surface: str,
) -> None:
    config = SecurityConfig(enable_redis=False)
    missed = [
        _SHAPES[index]
        for index in _DATA["v440"][surface]
        if not (
            await detect_penetration_attempt(_request(surface, _SHAPES[index]), config)
        ).is_threat
    ]
    assert missed == []


@pytest.mark.parametrize("surface", _SURFACES)
async def test_the_switch_turns_off_every_shape_only_the_bare_row_flags(
    surface: str,
) -> None:
    config = SecurityConfig(enable_redis=False, flag_bare_union_select=False)
    flagged = [
        _SHAPES[index]
        for index in _DATA["bare_row_only"][surface]
        if (
            await detect_penetration_attempt(_request(surface, _SHAPES[index]), config)
        ).is_threat
    ]
    assert flagged == []
