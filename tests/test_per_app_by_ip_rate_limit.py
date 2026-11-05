from guard_core.handlers.ratelimit_handler import (
    _by_ip_autoban_counts,
    _by_ip_request_timestamps,
    check_rate_limit_by_ip,
    clear_by_ip_request_windows,
    clear_by_ip_strikes,
    forget_by_ip_strikes,
    forget_by_ip_strikes_inside,
)
from guard_core.models import SecurityConfig

IP = "203.0.113.9"


def _config(*, auto_ban: bool = False) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_rate_limiting=True,
        rate_limit=2,
        rate_limit_window=60,
        enable_ip_banning=auto_ban,
        enable_rate_limit_auto_ban=auto_ban,
        auto_ban_threshold=50,
    )


async def test_one_apps_budget_does_not_limit_another_app() -> None:
    app_a, app_b = _config(), _config()

    first_app = [await check_rate_limit_by_ip(IP, app_a) for _ in range(3)]

    assert first_app == [True, True, False]
    assert await check_rate_limit_by_ip(IP, app_b) is True
    assert await check_rate_limit_by_ip(IP, app_b) is True
    assert await check_rate_limit_by_ip(IP, app_b) is False


async def test_one_apps_violations_do_not_become_another_apps_strikes() -> None:
    app_a, app_b = _config(auto_ban=True), _config(auto_ban=True)

    for _ in range(4):
        await check_rate_limit_by_ip(IP, app_a)
    await check_rate_limit_by_ip(IP, app_b)
    await check_rate_limit_by_ip(IP, app_b)
    await check_rate_limit_by_ip(IP, app_b)

    assert _by_ip_autoban_counts.for_app(app_a)[IP] == {"rate_limit": 2}
    assert _by_ip_autoban_counts.for_app(app_b)[IP] == {"rate_limit": 1}


async def test_forgetting_strikes_reaches_every_app() -> None:
    app_a, app_b = _config(auto_ban=True), _config(auto_ban=True)
    for app in (app_a, app_b):
        for _ in range(3):
            await check_rate_limit_by_ip(IP, app)

    forget_by_ip_strikes(IP)

    assert IP not in _by_ip_autoban_counts.for_app(app_a)
    assert IP not in _by_ip_autoban_counts.for_app(app_b)


async def test_forgetting_a_range_and_clearing_reach_every_app() -> None:
    app_a, app_b = _config(auto_ban=True), _config(auto_ban=True)
    for app in (app_a, app_b):
        for _ in range(3):
            await check_rate_limit_by_ip(IP, app)

    forget_by_ip_strikes_inside(lambda identity: identity == IP)
    assert not _by_ip_autoban_counts.for_app(app_a)
    assert not _by_ip_autoban_counts.for_app(app_b)

    for app in (app_a, app_b):
        await check_rate_limit_by_ip(IP, app)
    clear_by_ip_strikes()
    clear_by_ip_request_windows()
    assert not _by_ip_autoban_counts.for_app(app_a)
    assert not _by_ip_request_timestamps.for_app(app_a)
    assert not _by_ip_request_timestamps.for_app(app_b)


async def test_a_copy_of_the_config_is_another_app_with_a_budget_of_its_own() -> None:
    app = _config()
    await check_rate_limit_by_ip(IP, app)
    copy = app.model_copy()

    await check_rate_limit_by_ip(IP, app)

    assert await check_rate_limit_by_ip(IP, app) is False
    assert await check_rate_limit_by_ip(IP, copy) is True
    assert await check_rate_limit_by_ip(IP, copy) is True
    assert await check_rate_limit_by_ip(IP, copy) is False
