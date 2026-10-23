import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_JUNK = {f"k{i}": "v" for i in range(25)}


def _flagged(value: str, spent_budget: bool) -> bool:
    config = SyncSecurityConfig(
        enable_redis=False,
        rate_limit=1000000,
        detection_max_scan_values=20 if spent_budget else 100000,
        detection_max_scan_chars=1024 if spent_budget else 262144,
    )
    params = {**_JUNK, "q": value} if spent_budget else {"q": value}
    result = detect_penetration_attempt(
        SyncMockGuardRequest(path="/x", query_params=params), config
    )
    return result.is_threat


@pytest.mark.parametrize("spent_budget", [False, True])
@pytest.mark.parametrize(
    "value", ["ftp://ftp.example.com/pub/file.txt", "http://evil.com/shell.php"]
)
def test_a_plain_url_value_is_not_flagged_by_the_remainder_either(
    value: str, spent_budget: bool
) -> None:
    assert not _flagged(value, spent_budget)


@pytest.mark.parametrize("spent_budget", [False, True])
def test_a_value_that_starts_with_equals_and_a_url_stays_flagged(
    spent_budget: bool,
) -> None:
    assert _flagged("=http://evil.com/shell.php", spent_budget)
