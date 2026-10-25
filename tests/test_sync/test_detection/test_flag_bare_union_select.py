import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers._suspatterns_pattern_table import BARE_UNION_SELECT_ROW
from guard_core.sync.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_manager_for,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

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


def _flagged(value: str, config: SyncSecurityConfig) -> bool:
    request = SyncMockGuardRequest(path="/search", query_params={"q": value})
    return (detect_penetration_attempt(request, config)).is_threat


@pytest.mark.parametrize("value", BARE_FRAGMENTS)
def test_bare_union_select_is_flagged_by_default(value: str) -> None:
    assert _flagged(value, SyncSecurityConfig()) is True


@pytest.mark.parametrize("value", BARE_FRAGMENTS)
def test_bare_union_select_is_clean_when_the_row_is_turned_off(
    value: str,
) -> None:
    assert _flagged(value, SyncSecurityConfig(flag_bare_union_select=False)) is False


@pytest.mark.parametrize("flag", [True, False])
@pytest.mark.parametrize("value", PROSE_CLEAN_UNDER_BOTH)
def test_prose_with_union_select_is_clean_under_both(value: str, flag: bool) -> None:
    assert _flagged(value, SyncSecurityConfig(flag_bare_union_select=flag)) is False


def test_turning_the_row_back_on_restores_the_default() -> None:
    assert (
        _flagged("union select", SyncSecurityConfig(flag_bare_union_select=False))
        is False
    )
    assert _flagged("union select", SyncSecurityConfig()) is True


def test_the_per_parameter_opt_out_clears_only_that_parameter() -> None:
    config = SyncSecurityConfig(excluded_detection_params={"q": ["sqli"]})
    assert _flagged("union select", config) is False
    other = SyncMockGuardRequest(path="/search", query_params={"s": "union select"})
    assert (detect_penetration_attempt(other, config)).is_threat is True


def test_the_row_is_a_default_row_not_a_custom_pattern() -> None:
    config = SyncSecurityConfig()
    _flagged("union select", config)
    manager = SusPatternsManager()
    assert manager.get_custom_compiled_patterns() == []
    assert any(
        row[0].pattern == BARE_UNION_SELECT_ROW
        for row in manager.get_default_compiled_patterns()
    )


def _two_apps_on_one_redis_prefix() -> tuple[SyncSecurityConfig, SyncSecurityConfig]:
    on = SyncSecurityConfig(
        flag_bare_union_select=True, enable_redis=True, redis_prefix="wp114:"
    )
    off = SyncSecurityConfig(
        flag_bare_union_select=False, enable_redis=True, redis_prefix="wp114:"
    )
    sus_patterns_manager_for(on, bind=True)
    sus_patterns_manager_for(off, bind=True)
    return on, off
