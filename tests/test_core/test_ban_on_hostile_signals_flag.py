from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest

from guard_core.decorators import SecurityDecorator
from guard_core.handlers import ipban_handler
from guard_core.models import SecurityConfig
from tests.test_core.conftest import (
    build_route_pipeline,
    fixed_country_geo_ip,
    send_request,
)

DecoratorFactory = Callable[[SecurityDecorator], Any]

BOT_IP = "203.0.113.7"
SQLI_PATH = "/x?q=1%20UNION%20SELECT%20password%20FROM%20users--"


def _config(**overrides: object) -> SecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "auto_ban_threshold": 2,
        "geo_ip_handler": fixed_country_geo_ip("CN"),
        "ban_on_hostile_signals": False,
    }
    settings.update(overrides)
    return SecurityConfig(**settings)


FLAGGED_DENIALS = [
    pytest.param(
        {},
        lambda d: d.api_key_auth(verifier=lambda r, k: False),
        {"headers": {"X-API-Key": "wrong"}},
        id="auth-failure",
    ),
    pytest.param(
        {},
        lambda d: d.require_headers({"X-Trace": "required"}),
        {},
        id="required-header",
    ),
    pytest.param({}, lambda d: d.require_referrer(["example.com"]), {}, id="referrer"),
    pytest.param(
        {}, lambda d: d.require_ip(blacklist=[BOT_IP]), {}, id="route-ip-blacklist"
    ),
    pytest.param(
        {}, lambda d: d.block_countries(["CN"]), {}, id="route-blocked-country"
    ),
    pytest.param(
        {},
        lambda d: d.block_user_agents(["badbot"]),
        {"headers": {"User-Agent": "badbot/1.0"}},
        id="route-user-agent",
    ),
    pytest.param(
        {"blacklist": [BOT_IP]},
        lambda d: d.max_request_size(10**6),
        {},
        id="global-blacklist",
    ),
    pytest.param(
        {"blocked_user_agents": ["badbot"]},
        lambda d: d.max_request_size(10**6),
        {"headers": {"User-Agent": "badbot/1.0"}},
        id="global-user-agent",
    ),
]


@pytest.mark.parametrize(("settings", "factory", "request_kwargs"), FLAGGED_DENIALS)
async def test_flag_off_never_counts_without_a_penetration_match(
    settings: dict[str, Any], factory: DecoratorFactory, request_kwargs: dict[str, Any]
) -> None:
    config = _config(**settings)
    pipeline, middleware, route_id = build_route_pipeline(
        config, factory, geo_ip_handler=config.geo_ip_handler
    )

    for _ in range(4):
        response = await send_request(pipeline, route_id, ip=BOT_IP, **request_kwargs)
        assert response is not None
        assert response.status_code != 200

    assert middleware.suspicious_request_counts == {}
    assert not await ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


@pytest.mark.parametrize(("settings", "factory", "request_kwargs"), FLAGGED_DENIALS)
async def test_flag_on_counts_and_bans(
    settings: dict[str, Any], factory: DecoratorFactory, request_kwargs: dict[str, Any]
) -> None:
    config = _config(ban_on_hostile_signals=True, **settings)
    pipeline, _, route_id = build_route_pipeline(
        config, factory, geo_ip_handler=config.geo_ip_handler
    )

    for _ in range(2):
        await send_request(pipeline, route_id, ip=BOT_IP, **request_kwargs)

    assert await ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


async def test_flag_off_keeps_the_conditional_penetration_escalation() -> None:
    config = _config(enable_penetration_detection=True, auto_ban_threshold=5)
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.require_ip(blacklist=[BOT_IP])
    )

    await send_request(pipeline, route_id, ip=BOT_IP, path=SQLI_PATH)

    assert set(middleware.suspicious_request_counts[BOT_IP]) == {"sqli"}


async def test_flag_off_keeps_the_conditional_global_escalation() -> None:
    config = _config(
        enable_penetration_detection=True, auto_ban_threshold=5, blacklist=[BOT_IP]
    )
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.max_request_size(10**6)
    )

    await send_request(pipeline, route_id, ip=BOT_IP, path=SQLI_PATH)

    assert set(middleware.suspicious_request_counts[BOT_IP]) == {"sqli"}


async def test_flag_off_leaves_honeypot_banning_on() -> None:
    config = _config()
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.honeypot_detection(["hp"])
    )

    response = await send_request(
        pipeline,
        route_id,
        ip=BOT_IP,
        method="POST",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": "6",
        },
        body=b"hp=bot",
    )

    assert response is not None
    assert response.status_code == 403
    assert await ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


async def test_flag_off_cloud_denial_keeps_global_escalation_only() -> None:
    config = _config(
        block_cloud_providers={"AWS"},
        enable_penetration_detection=True,
        auto_ban_threshold=5,
    )
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.max_request_size(10**6)
    )
    with patch(
        "guard_core.handlers.cloud_handler.cloud_handler.is_cloud_ip",
        return_value=True,
    ):
        response = await send_request(pipeline, route_id, ip=BOT_IP, path=SQLI_PATH)

    assert response is not None
    assert response.status_code == 403
    assert set(middleware.suspicious_request_counts[BOT_IP]) == {"sqli"}
