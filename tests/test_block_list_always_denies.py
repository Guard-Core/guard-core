from typing import Any

import pytest

from guard_core.core.checks.factory import build_default_pipeline
from guard_core.decorators import SecurityDecorator
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest
from tests.test_core.conftest import (
    build_middleware,
    build_route_pipeline,
    send_request,
)

BLOCKED = "10.0.0.66"
NEIGHBOUR = "10.0.0.5"
OUTSIDER = "203.0.113.9"


def _config(**settings: Any) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        **settings,
    )


async def _global_status(config: SecurityConfig, ip: str) -> int | None:
    middleware = build_middleware(config, SecurityDecorator(config))
    pipeline = build_default_pipeline(middleware)
    response = await pipeline.execute(MockGuardRequest(path="/x", client_host=ip))
    return None if response is None else response.status_code


async def _route_status(config: SecurityConfig, factory: Any, ip: str) -> int | None:
    pipeline, _, route_id = build_route_pipeline(config, factory)
    response = await send_request(pipeline, route_id, ip=ip)
    return None if response is None else response.status_code


async def test_a_blacklist_entry_denies_under_a_global_whitelist_covering_it() -> None:
    config = _config(whitelist=["10.0.0.0/8"], blacklist=[BLOCKED])

    assert await _global_status(config, BLOCKED) == 403
    assert await _global_status(config, NEIGHBOUR) is None
    assert await _global_status(config, OUTSIDER) == 403


async def test_a_blacklist_alone_still_denies() -> None:
    assert await _global_status(_config(blacklist=[BLOCKED]), BLOCKED) == 403


async def test_a_blacklisted_cidr_inside_a_whitelisted_cidr_is_carved_out() -> None:
    config = _config(whitelist=["10.0.0.0/8"], blacklist=["10.0.0.64/26"])

    assert await _global_status(config, BLOCKED) == 403
    assert await _global_status(config, NEIGHBOUR) is None


async def test_a_route_allow_list_does_not_lift_the_global_blacklist() -> None:
    config = _config(blacklist=[BLOCKED])

    status = await _route_status(
        config, lambda d: d.require_ip(whitelist=["10.0.0.0/8"]), BLOCKED
    )

    assert status == 403


async def test_a_route_allow_list_still_admits_an_unlisted_address() -> None:
    config = _config(blacklist=[BLOCKED])

    status = await _route_status(
        config, lambda d: d.require_ip(whitelist=["10.0.0.0/8"]), NEIGHBOUR
    )

    assert status is None


async def test_a_route_allow_list_still_replaces_the_global_whitelist() -> None:
    config = _config(whitelist=["192.168.0.0/16"])

    status = await _route_status(
        config, lambda d: d.require_ip(whitelist=["10.0.0.0/8"]), NEIGHBOUR
    )

    assert status is None


async def test_the_route_bypass_is_still_the_explicit_override() -> None:
    config = _config(blacklist=[BLOCKED])

    status = await _route_status(config, lambda d: d.bypass(["ip"]), BLOCKED)

    assert status is None


@pytest.fixture(autouse=True)
def _no_bans() -> None:
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.redis_handler = None
