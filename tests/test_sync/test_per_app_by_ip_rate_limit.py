from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ratelimit_handler import (
    _by_ip_autoban_counts,
    _by_ip_request_timestamps,
    check_rate_limit_by_ip,
    clear_by_ip_request_windows,
    clear_by_ip_strikes,
    forget_by_ip_strikes,
    forget_by_ip_strikes_inside,
)

IP = "203.0.113.9"


def _config(*, auto_ban: bool = False) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_rate_limiting=True,
        rate_limit=2,
        rate_limit_window=60,
        enable_ip_banning=auto_ban,
        enable_rate_limit_auto_ban=auto_ban,
        auto_ban_threshold=50,
    )


def test_one_apps_budget_does_not_limit_another_app() -> None:
    app_a, app_b = _config(), _config()

    first_app = [check_rate_limit_by_ip(IP, app_a) for _ in range(3)]

    assert first_app == [True, True, False]
    assert check_rate_limit_by_ip(IP, app_b) is True
    assert check_rate_limit_by_ip(IP, app_b) is True
    assert check_rate_limit_by_ip(IP, app_b) is False


def test_one_apps_violations_do_not_become_another_apps_strikes() -> None:
    app_a, app_b = _config(auto_ban=True), _config(auto_ban=True)

    for _ in range(4):
        check_rate_limit_by_ip(IP, app_a)
    check_rate_limit_by_ip(IP, app_b)
    check_rate_limit_by_ip(IP, app_b)
    check_rate_limit_by_ip(IP, app_b)

    assert _by_ip_autoban_counts.for_app(app_a)[IP] == {"rate_limit": 2}
    assert _by_ip_autoban_counts.for_app(app_b)[IP] == {"rate_limit": 1}


def test_forgetting_strikes_reaches_every_app() -> None:
    app_a, app_b = _config(auto_ban=True), _config(auto_ban=True)
    for app in (app_a, app_b):
        for _ in range(3):
            check_rate_limit_by_ip(IP, app)

    forget_by_ip_strikes(IP)

    assert IP not in _by_ip_autoban_counts.for_app(app_a)
    assert IP not in _by_ip_autoban_counts.for_app(app_b)


def test_forgetting_a_range_and_clearing_reach_every_app() -> None:
    app_a, app_b = _config(auto_ban=True), _config(auto_ban=True)
    for app in (app_a, app_b):
        for _ in range(3):
            check_rate_limit_by_ip(IP, app)

    forget_by_ip_strikes_inside(lambda identity: identity == IP)
    assert not _by_ip_autoban_counts.for_app(app_a)
    assert not _by_ip_autoban_counts.for_app(app_b)

    for app in (app_a, app_b):
        check_rate_limit_by_ip(IP, app)
    clear_by_ip_strikes()
    clear_by_ip_request_windows()
    assert not _by_ip_autoban_counts.for_app(app_a)
    assert not _by_ip_request_timestamps.for_app(app_a)
    assert not _by_ip_request_timestamps.for_app(app_b)


def test_a_copy_of_the_config_is_another_app_with_a_budget_of_its_own() -> None:
    app = _config()
    check_rate_limit_by_ip(IP, app)
    copy = app.model_copy()

    check_rate_limit_by_ip(IP, app)

    assert check_rate_limit_by_ip(IP, app) is False
    assert check_rate_limit_by_ip(IP, copy) is True
    assert check_rate_limit_by_ip(IP, copy) is True
    assert check_rate_limit_by_ip(IP, copy) is False
