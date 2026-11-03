from collections.abc import Callable

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import (
    build_middleware,
    build_route_pipeline,
    send_request,
)

BLOCKED = "10.0.0.66"
NEIGHBOUR = "10.0.0.5"
OUTSIDER = "203.0.113.9"


def _config(**settings: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        **settings,
    )


def _global_status(config: SyncSecurityConfig, ip: str) -> int | None:
    middleware = build_middleware(config, SecurityDecorator(config))
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(SyncMockGuardRequest(path="/x", client_host=ip))
    return None if response is None else response.status_code


def _route_status(
    config: SyncSecurityConfig, factory: Callable[[SecurityDecorator], object], ip: str
) -> int | None:
    pipeline, _, route_id = build_route_pipeline(config, factory)
    response = send_request(pipeline, route_id, ip=ip)
    return None if response is None else response.status_code


def test_a_blacklist_entry_denies_under_a_global_whitelist_covering_it() -> None:
    config = _config(whitelist=["10.0.0.0/8"], blacklist=[BLOCKED])

    assert _global_status(config, BLOCKED) == 403
    assert _global_status(config, NEIGHBOUR) is None
    assert _global_status(config, OUTSIDER) == 403


def test_a_blacklist_alone_still_denies() -> None:
    assert _global_status(_config(blacklist=[BLOCKED]), BLOCKED) == 403


def test_a_blacklisted_cidr_inside_a_whitelisted_cidr_is_carved_out() -> None:
    config = _config(whitelist=["10.0.0.0/8"], blacklist=["10.0.0.64/26"])

    assert _global_status(config, BLOCKED) == 403
    assert _global_status(config, NEIGHBOUR) is None


def test_a_route_allow_list_does_not_lift_the_global_blacklist() -> None:
    config = _config(blacklist=[BLOCKED])

    status = _route_status(
        config, lambda d: d.require_ip(whitelist=["10.0.0.0/8"]), BLOCKED
    )

    assert status == 403


def test_a_route_allow_list_still_admits_an_unlisted_address() -> None:
    config = _config(blacklist=[BLOCKED])

    status = _route_status(
        config, lambda d: d.require_ip(whitelist=["10.0.0.0/8"]), NEIGHBOUR
    )

    assert status is None


def test_a_route_allow_list_still_replaces_the_global_whitelist() -> None:
    config = _config(whitelist=["192.168.0.0/16"])

    status = _route_status(
        config, lambda d: d.require_ip(whitelist=["10.0.0.0/8"]), NEIGHBOUR
    )

    assert status is None


def test_the_route_bypass_is_still_the_explicit_override() -> None:
    config = _config(blacklist=[BLOCKED])

    status = _route_status(config, lambda d: d.bypass(["ip"]), BLOCKED)

    assert status is None


@pytest.fixture(autouse=True)
def _no_bans() -> None:
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.redis_handler = None
