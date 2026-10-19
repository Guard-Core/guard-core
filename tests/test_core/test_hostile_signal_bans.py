from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest

from guard_core._utils import access_control
from guard_core.core.checks import helpers
from guard_core.decorators import SecurityDecorator
from guard_core.handlers import ipban_handler
from guard_core.models import SecurityConfig, ThreatBanConfig
from tests.test_core.conftest import (
    build_middleware,
    build_route_pipeline,
    fixed_country_geo_ip,
    send_request,
)

DecoratorFactory = Callable[[SecurityDecorator], Any]

BOT_IP = "203.0.113.7"
CLOUD_IP = "198.51.100.77"


def _config(**overrides: Any) -> SecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "ban_on_hostile_signals": True,
        "auto_ban_threshold": 2,
        "auto_ban_duration": 600,
        "geo_ip_handler": fixed_country_geo_ip("CN"),
    }
    settings.update(overrides)
    return SecurityConfig(**settings)


HOSTILE_FAILURES = [
    pytest.param(
        lambda d: d.api_key_auth(verifier=lambda r, k: False),
        {"headers": {"X-API-Key": "wrong"}},
        "auth_failure",
        id="auth-verifier-false",
    ),
    pytest.param(
        lambda d: d.require_auth(type="bearer", verifier=lambda r, k: False),
        {},
        "auth_failure",
        id="auth-missing-bearer",
    ),
    pytest.param(
        lambda d: d.require_auth(type="bearer", verifier=lambda r, k: False),
        {"headers": {"authorization": "Bearer nope"}},
        "auth_failure",
        id="auth-invalid-bearer",
    ),
    pytest.param(
        lambda d: d.require_headers({"X-Trace": "required"}),
        {},
        "required_header",
        id="required-header-missing",
    ),
    pytest.param(
        lambda d: d.require_headers({"X-Trace": "abc"}),
        {"headers": {"X-Trace": "other"}},
        "required_header",
        id="required-header-mismatch",
    ),
    pytest.param(
        lambda d: d.require_referrer(["example.com"]),
        {},
        "referrer",
        id="referrer-missing",
    ),
    pytest.param(
        lambda d: d.require_referrer(["example.com"]),
        {"headers": {"referer": "https://evil.test/page"}},
        "referrer",
        id="referrer-invalid",
    ),
    pytest.param(
        lambda d: d.require_ip(blacklist=[BOT_IP]),
        {},
        "ip_list",
        id="route-ip-blacklist",
    ),
    pytest.param(
        lambda d: d.block_countries(["CN"]),
        {},
        "country",
        id="route-country-blocked",
    ),
    pytest.param(
        lambda d: d.block_user_agents(["badbot"]),
        {"headers": {"User-Agent": "badbot/1.0"}},
        "user_agent",
        id="route-user-agent",
    ),
]


async def _hit_until_banned(
    config: SecurityConfig,
    factory: DecoratorFactory,
    request_kwargs: dict[str, Any],
    attempts: int,
) -> tuple[Any, list[Any]]:
    pipeline, middleware, route_id = build_route_pipeline(
        config, factory, geo_ip_handler=config.geo_ip_handler
    )
    responses = [
        await send_request(pipeline, route_id, ip=BOT_IP, **request_kwargs)
        for _ in range(attempts)
    ]
    return middleware, responses


@pytest.mark.parametrize(("factory", "request_kwargs", "category"), HOSTILE_FAILURES)
async def test_hostile_failure_counts_and_bans_at_threshold(
    factory: DecoratorFactory, request_kwargs: dict[str, Any], category: str
) -> None:
    config = _config()
    manager = ipban_handler.ip_ban_manager
    with patch.object(
        manager, "_ban_ip_escalating", wraps=manager._ban_ip_escalating
    ) as ban_spy:
        middleware, responses = await _hit_until_banned(
            config, factory, request_kwargs, attempts=2
        )

    assert all(r is not None and r.status_code != 200 for r in responses)
    ban_spy.assert_awaited_once_with(
        BOT_IP, 600, f"{category}_triggered:{category}", grouped=False
    )
    assert BOT_IP not in middleware.suspicious_request_counts
    assert await manager.is_ip_banned(BOT_IP)


async def test_cloud_denial_counts_and_bans_at_threshold() -> None:
    config = _config()
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.block_clouds(["AWS"])
    )
    with patch(
        "guard_core.handlers.cloud_handler.cloud_handler.is_cloud_ip",
        return_value=True,
    ):
        for _ in range(2):
            response = await send_request(pipeline, route_id, ip=CLOUD_IP)
            assert response is not None
            assert response.status_code == 403

    assert CLOUD_IP not in middleware.suspicious_request_counts
    assert await ipban_handler.ip_ban_manager.is_ip_banned(CLOUD_IP)


@pytest.mark.parametrize(("factory", "request_kwargs", "category"), HOSTILE_FAILURES)
async def test_below_threshold_is_counted_but_not_banned(
    factory: DecoratorFactory, request_kwargs: dict[str, Any], category: str
) -> None:
    config = _config(auto_ban_threshold=5)
    middleware, _ = await _hit_until_banned(config, factory, request_kwargs, 2)

    assert middleware.suspicious_request_counts[BOT_IP] == {category: 2}
    assert not await ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


@pytest.mark.parametrize(("factory", "request_kwargs", "category"), HOSTILE_FAILURES)
async def test_passive_mode_never_counts_or_bans(
    factory: DecoratorFactory, request_kwargs: dict[str, Any], category: str
) -> None:
    config = _config(passive_mode=True)
    middleware, _ = await _hit_until_banned(config, factory, request_kwargs, 3)

    assert middleware.suspicious_request_counts == {}
    assert not await ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


@pytest.mark.parametrize(("factory", "request_kwargs", "category"), HOSTILE_FAILURES)
async def test_ip_banning_disabled_never_bans(
    factory: DecoratorFactory, request_kwargs: dict[str, Any], category: str
) -> None:
    config = _config(enable_ip_banning=False)
    middleware, responses = await _hit_until_banned(config, factory, request_kwargs, 3)

    assert all(r is not None and r.status_code != 200 for r in responses)
    assert not await ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


async def test_threat_ban_config_overrides_threshold_and_duration() -> None:
    config = _config(
        auto_ban_threshold=100,
        threat_ban_config={"auth_failure": ThreatBanConfig(threshold=3, duration=77)},
    )
    manager = ipban_handler.ip_ban_manager
    with patch.object(
        manager, "_ban_ip_escalating", wraps=manager._ban_ip_escalating
    ) as ban_spy:
        await _hit_until_banned(
            config,
            lambda d: d.api_key_auth(verifier=lambda r, k: False),
            {"headers": {"X-API-Key": "wrong"}},
            attempts=3,
        )

    ban_spy.assert_awaited_once_with(
        BOT_IP, 77, "auth_failure_triggered:auth_failure", grouped=False
    )
    assert await manager.is_ip_banned(BOT_IP)


async def test_default_duration_is_auto_ban_duration() -> None:
    config = _config(auto_ban_duration=321)
    manager = ipban_handler.ip_ban_manager
    with patch.object(
        manager, "_ban_ip_escalating", wraps=manager._ban_ip_escalating
    ) as ban_spy:
        await _hit_until_banned(
            config, lambda d: d.require_referrer(["example.com"]), {}, attempts=2
        )

    ban_spy.assert_awaited_once_with(
        BOT_IP, 321, "referrer_triggered:referrer", grouped=False
    )


async def test_ban_manager_refusal_leaves_request_denied_not_crashed() -> None:
    config = _config()
    loopback = "127.0.0.1"
    pipeline, _, route_id = build_route_pipeline(
        config, lambda d: d.require_referrer(["example.com"])
    )

    for _ in range(3):
        response = await send_request(pipeline, route_id, ip=loopback)
        assert response is not None
        assert response.status_code == 403

    assert not await ipban_handler.ip_ban_manager.is_ip_banned(loopback)


async def test_route_denial_counts_without_penetration_detection() -> None:
    config = _config(enable_penetration_detection=False)
    middleware, _ = await _hit_until_banned(
        config, lambda d: d.require_ip(blacklist=[BOT_IP]), {}, attempts=1
    )

    assert middleware.suspicious_request_counts[BOT_IP] == {"ip_list": 1}


async def test_global_ip_denial_stays_conditional_on_penetration_detection() -> None:
    config = _config(blacklist=[BOT_IP], enable_penetration_detection=False)
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.max_request_size(10**6)
    )

    for _ in range(3):
        response = await send_request(pipeline, route_id, ip=BOT_IP)
        assert response is not None
        assert response.status_code == 403

    assert middleware.suspicious_request_counts == {}


@pytest.mark.parametrize(
    ("factory", "request_kwargs"),
    [
        pytest.param(
            lambda d: d.max_request_size(5),
            {
                "method": "POST",
                "headers": {"content-length": "50"},
                "body": b"x" * 50,
            },
            id="oversize",
        ),
        pytest.param(
            lambda d: d.content_type_filter(["application/json"]),
            {"method": "POST", "headers": {"content-type": "text/plain"}},
            id="content-type",
        ),
        pytest.param(
            lambda d: d.time_window("00:00", "00:00", "UTC"),
            {},
            id="time-window",
        ),
        pytest.param(
            lambda d: d.require_https(),
            {"scheme": "http"},
            id="https",
        ),
    ],
)
async def test_non_hostile_denials_never_count(
    factory: DecoratorFactory, request_kwargs: dict[str, Any]
) -> None:
    config = _config()
    pipeline, middleware, route_id = build_route_pipeline(config, factory)

    for _ in range(4):
        await send_request(pipeline, route_id, ip=BOT_IP, **request_kwargs)

    assert middleware.suspicious_request_counts == {}
    assert not await ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


GLOBAL_DENIALS = [
    pytest.param({"blacklist": [BOT_IP]}, {}, "ip_list", id="global-blacklist"),
    pytest.param(
        {"blocked_countries": ["CN"]}, {}, "country", id="global-blocked-country"
    ),
    pytest.param(
        {"blocked_user_agents": ["badbot"]},
        {"headers": {"User-Agent": "badbot/1.0"}},
        "user_agent",
        id="global-user-agent",
    ),
]


@pytest.mark.parametrize(("settings", "request_kwargs", "category"), GLOBAL_DENIALS)
async def test_global_block_list_denial_counts_and_bans(
    settings: dict[str, Any], request_kwargs: dict[str, Any], category: str
) -> None:
    config = _config(**settings)
    pipeline, middleware, route_id = build_route_pipeline(
        config,
        lambda d: d.max_request_size(10**6),
        geo_ip_handler=config.geo_ip_handler,
    )

    for _ in range(2):
        response = await send_request(pipeline, route_id, ip=BOT_IP, **request_kwargs)
        assert response is not None
        assert response.status_code == 403

    assert BOT_IP not in middleware.suspicious_request_counts
    assert await ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


async def test_global_cloud_denial_counts_and_bans() -> None:
    config = _config(block_cloud_providers={"AWS"})
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.max_request_size(10**6)
    )
    with patch(
        "guard_core.handlers.cloud_handler.cloud_handler.is_cloud_ip",
        return_value=True,
    ):
        for _ in range(2):
            response = await send_request(pipeline, route_id, ip=CLOUD_IP)
            assert response is not None
            assert response.status_code == 403
            assert response.body == b"Cloud provider IP not allowed"

    assert CLOUD_IP not in middleware.suspicious_request_counts
    assert await ipban_handler.ip_ban_manager.is_ip_banned(CLOUD_IP)


@pytest.mark.parametrize(
    "config_settings",
    [
        pytest.param(
            {"whitelist": [CLOUD_IP], "whitelist_access_only": False}, id="whitelist"
        ),
        pytest.param({"exempt_ips": [CLOUD_IP]}, id="exempt-ips"),
    ],
)
async def test_global_cloud_block_honors_whitelist_and_exempt_ips(
    config_settings: dict[str, Any],
) -> None:
    config = _config(block_cloud_providers={"AWS"}, **config_settings)
    pipeline, _, route_id = build_route_pipeline(
        config, lambda d: d.max_request_size(10**6)
    )
    with patch(
        "guard_core.handlers.cloud_handler.cloud_handler.is_cloud_ip",
        return_value=True,
    ):
        assert await send_request(pipeline, route_id, ip=CLOUD_IP) is None


async def test_global_cloud_block_honors_route_bypass() -> None:
    config = _config(block_cloud_providers={"AWS"})
    pipeline, _, route_id = build_route_pipeline(config, lambda d: d.bypass(["clouds"]))
    with patch(
        "guard_core.handlers.cloud_handler.cloud_handler.is_cloud_ip",
        return_value=True,
    ):
        assert await send_request(pipeline, route_id, ip=CLOUD_IP) is None


ALLOW_LIST_MISSES = [
    pytest.param(
        {"whitelist": ["192.0.2.1"]},
        lambda d: d.max_request_size(10**6),
        "ip_list",
        id="global-whitelist",
    ),
    pytest.param(
        {"whitelist_countries": ["IT"]},
        lambda d: d.max_request_size(10**6),
        "country",
        id="global-whitelist-countries",
    ),
    pytest.param(
        {},
        lambda d: d.require_ip(whitelist=["192.0.2.0/24"]),
        "ip_list",
        id="route-whitelist",
    ),
    pytest.param(
        {}, lambda d: d.allow_countries(["IT"]), "country", id="route-allow-countries"
    ),
]


@pytest.mark.parametrize(("settings", "factory", "category"), ALLOW_LIST_MISSES)
async def test_allow_list_miss_is_denied_but_not_counted(
    settings: dict[str, Any], factory: DecoratorFactory, category: str
) -> None:
    config = _config(**settings)
    pipeline, middleware, route_id = build_route_pipeline(
        config, factory, geo_ip_handler=config.geo_ip_handler
    )

    for _ in range(3):
        response = await send_request(pipeline, route_id, ip=BOT_IP)
        assert response is not None
        assert response.status_code == 403

    assert middleware.suspicious_request_counts == {}
    assert not await ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


@pytest.mark.parametrize(("settings", "factory", "category"), ALLOW_LIST_MISSES)
async def test_allow_list_miss_counting_switches_on_in_one_place(
    monkeypatch: pytest.MonkeyPatch,
    settings: dict[str, Any],
    factory: DecoratorFactory,
    category: str,
) -> None:
    monkeypatch.setattr(access_control, "ALLOW_LIST_MISSES_ARE_HOSTILE", True)
    config = _config(
        auto_ban_threshold=5, geo_ip_handler=fixed_country_geo_ip("CN"), **settings
    )
    pipeline, middleware, route_id = build_route_pipeline(
        config, factory, geo_ip_handler=config.geo_ip_handler
    )

    for _ in range(2):
        await send_request(pipeline, route_id, ip=BOT_IP)

    assert middleware.suspicious_request_counts[BOT_IP] == {category: 2}


async def test_counts_reset_when_a_ban_is_applied_and_expired_ban_does_not_reban() -> (
    None
):
    config = _config()
    manager = ipban_handler.ip_ban_manager
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.require_referrer(["example.com"])
    )

    for _ in range(2):
        await send_request(pipeline, route_id, ip=BOT_IP)
    assert await manager.is_ip_banned(BOT_IP)
    assert BOT_IP not in middleware.suspicious_request_counts

    await manager.unban_ip(BOT_IP)
    response = await send_request(pipeline, route_id, ip=BOT_IP)

    assert response is not None
    assert response.status_code == 403
    assert middleware.suspicious_request_counts[BOT_IP] == {"referrer": 1}
    assert not await manager.is_ip_banned(BOT_IP)


async def test_events_older_than_an_hour_do_not_count() -> None:
    config = _config(auto_ban_threshold=3)
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.require_referrer(["example.com"])
    )
    clock = {"now": 1000.0}

    with patch.object(helpers.time, "monotonic", side_effect=lambda: clock["now"]):
        await send_request(pipeline, route_id, ip=BOT_IP)
        await send_request(pipeline, route_id, ip=BOT_IP)
        clock["now"] += helpers.SUSPICIOUS_COUNT_WINDOW_SECONDS + 1
        await send_request(pipeline, route_id, ip=BOT_IP)

    assert middleware.suspicious_request_counts[BOT_IP] == {"referrer": 1}
    assert not await ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


async def test_events_inside_the_hour_accumulate_across_the_window() -> None:
    config = _config(auto_ban_threshold=3)
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.require_referrer(["example.com"])
    )
    clock = {"now": 1000.0}

    with patch.object(helpers.time, "monotonic", side_effect=lambda: clock["now"]):
        for _ in range(3):
            await send_request(pipeline, route_id, ip=BOT_IP)
            clock["now"] += 1000

    assert await ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


def test_counts_adopt_a_plain_dict_entry_and_stay_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(auto_ban_threshold=3)
    middleware = build_middleware(config, SecurityDecorator(config))
    middleware.suspicious_request_counts = {BOT_IP: {"sqli": 2}}
    monkeypatch.setattr(helpers, "_MAX_RETAINED_EVENTS_PER_CATEGORY", 3)

    for _ in range(10):
        helpers._increment_suspicious_counts(middleware, BOT_IP, "sqli")

    assert middleware.suspicious_request_counts[BOT_IP] == {"sqli": 3}
