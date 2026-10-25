import pytest

from guard_core.models import SyncSecurityConfig
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


def _flagged(value: str, *, flag: bool) -> bool:
    request = SyncMockGuardRequest(path="/search", query_params={"q": value})
    config = SyncSecurityConfig(flag_bare_union_select=flag)
    return (detect_penetration_attempt(request, config)).is_threat


@pytest.mark.parametrize("value", BARE_FRAGMENTS)
def test_bare_union_select_is_clean_by_default(value: str) -> None:
    assert _flagged(value, flag=False) is False


@pytest.mark.parametrize("value", BARE_FRAGMENTS)
def test_bare_union_select_is_flagged_when_the_variant_is_on(
    value: str,
) -> None:
    assert _flagged(value, flag=True) is True


@pytest.mark.parametrize("flag", [False, True])
@pytest.mark.parametrize("value", PROSE_CLEAN_UNDER_BOTH)
def test_prose_with_union_select_is_clean_under_both(value: str, flag: bool) -> None:
    assert _flagged(value, flag=flag) is False


def test_turning_the_variant_off_again_restores_the_default() -> None:
    assert _flagged("union select", flag=True) is True
    assert _flagged("union select", flag=False) is False
