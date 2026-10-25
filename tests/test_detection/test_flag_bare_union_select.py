import pytest

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

BARE_FRAGMENTS = [
    " UNION ALL SELECT",
    " union select",
    " UNION SELECT",
    "union select",
]

PROSE_CLEAN_UNDER_BOTH = [
    "how to union select two tables",
    "union select two tables",
    "a union select list",
]


async def _flagged(value: str, *, flag: bool) -> bool:
    request = MockGuardRequest(path="/search", query_params={"q": value})
    config = SecurityConfig(flag_bare_union_select=flag)
    return (await detect_penetration_attempt(request, config)).is_threat


@pytest.mark.parametrize("value", BARE_FRAGMENTS)
async def test_bare_union_select_is_clean_by_default(value: str) -> None:
    assert await _flagged(value, flag=False) is False


@pytest.mark.parametrize("value", BARE_FRAGMENTS)
async def test_bare_union_select_is_flagged_when_the_variant_is_on(
    value: str,
) -> None:
    assert await _flagged(value, flag=True) is True


@pytest.mark.parametrize("flag", [False, True])
@pytest.mark.parametrize("value", PROSE_CLEAN_UNDER_BOTH)
async def test_prose_with_union_select_is_clean_under_both(
    value: str, flag: bool
) -> None:
    assert await _flagged(value, flag=flag) is False


async def test_turning_the_variant_off_again_restores_the_default() -> None:
    assert await _flagged("union select", flag=True) is True
    assert await _flagged("union select", flag=False) is False
