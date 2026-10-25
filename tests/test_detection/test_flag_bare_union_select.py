import pytest

from guard_core.handlers.suspatterns_handler import SusPatternsManager
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


async def _flagged(value: str, config: SecurityConfig) -> bool:
    request = MockGuardRequest(path="/search", query_params={"q": value})
    return (await detect_penetration_attempt(request, config)).is_threat


@pytest.mark.parametrize("value", BARE_FRAGMENTS)
async def test_bare_union_select_is_flagged_by_default(value: str) -> None:
    assert await _flagged(value, SecurityConfig()) is True


@pytest.mark.parametrize("value", BARE_FRAGMENTS)
async def test_bare_union_select_is_clean_when_the_row_is_turned_off(
    value: str,
) -> None:
    assert await _flagged(value, SecurityConfig(flag_bare_union_select=False)) is False


@pytest.mark.parametrize("flag", [True, False])
@pytest.mark.parametrize("value", PROSE_CLEAN_UNDER_BOTH)
async def test_prose_with_union_select_is_clean_under_both(
    value: str, flag: bool
) -> None:
    assert await _flagged(value, SecurityConfig(flag_bare_union_select=flag)) is False


async def test_turning_the_row_back_on_restores_the_default() -> None:
    assert (
        await _flagged("union select", SecurityConfig(flag_bare_union_select=False))
        is False
    )
    assert await _flagged("union select", SecurityConfig()) is True


async def test_the_per_parameter_opt_out_clears_only_that_parameter() -> None:
    config = SecurityConfig(excluded_detection_params={"q": ["sqli"]})
    assert await _flagged("union select", config) is False
    other = MockGuardRequest(path="/search", query_params={"s": "union select"})
    assert (await detect_penetration_attempt(other, config)).is_threat is True


async def test_the_row_is_a_default_row_not_a_custom_pattern() -> None:
    config = SecurityConfig()
    await _flagged("union select", config)
    manager = SusPatternsManager()
    assert await manager.get_custom_compiled_patterns() == []
    assert any(
        row[0].pattern.startswith(r"(?i)\A\s*UNION")
        for row in await manager.get_default_compiled_patterns()
    )
