from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.initialization._ban_threshold_report import (
    _BanThresholdContext,
    unreachable_ban_threshold_problems,
)


def _context() -> _BanThresholdContext:
    return _BanThresholdContext(lambda: [], lambda: False)


def _config(*, ban_on_hostile_signals: bool) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        blacklist=["203.0.113.9"],
        rate_limit=10,
        rate_limit_window=60,
        auto_ban_threshold=100000,
        ban_on_hostile_signals=ban_on_hostile_signals,
        fail_on_misconfiguration=False,
        enable_redis=False,
    )


def test_a_blacklist_hit_feeds_the_auto_ban_early_only_when_hostile_signals_ban() -> (
    None
):
    fed = unreachable_ban_threshold_problems(
        _config(ban_on_hostile_signals=True), _context()
    )
    assert not any(problem.startswith("auto_ban_threshold") for problem in fed)


def test_with_hostile_signals_off_auto_ban_threshold_meets_the_bound() -> None:
    problems = unreachable_ban_threshold_problems(
        _config(ban_on_hostile_signals=False), _context()
    )
    assert any(
        problem.startswith("auto_ban_threshold is 100000") for problem in problems
    )
