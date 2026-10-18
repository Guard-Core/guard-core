from collections.abc import Generator
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import build_middleware

SETTINGS: dict[str, Any] = {
    "enable_redis": False,
    "enable_penetration_detection": False,
    "enable_rate_limiting": True,
    "rate_limit": 1,
    "rate_limit_window": 60,
    "enable_rate_limit_auto_ban": True,
    "auto_ban_threshold": 3,
    "auto_ban_duration": 600,
}
SLASH_64 = [f"2001:db8:0:1::{index:x}" for index in range(1, 9)]


@pytest.fixture(autouse=True)
def _fresh_ban_store() -> Generator[None, None, None]:
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    ip_ban_manager.redis_handler = None
    yield
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()


def _statuses(config: SecurityConfig, addresses: list[str]) -> list[int | None]:
    middleware = build_middleware(config, SecurityDecorator(config))
    pipeline = build_default_pipeline(middleware)
    outcomes: list[int | None] = []
    for address in addresses:
        response = pipeline.execute(
            SyncMockGuardRequest(path="/x", client_host=address)
        )
        outcomes.append(None if response is None else response.status_code)
    return outcomes


def test_violations_of_one_slash_64_add_up_and_ban_the_whole_prefix() -> None:
    statuses = _statuses(SecurityConfig(**SETTINGS), SLASH_64)

    assert statuses[0] is None
    assert statuses[1:3] == [429, 429]
    assert 403 in statuses[3:]
    assert ip_ban_manager.is_ip_banned("2001:db8:0:1::ffff") is True


def test_a_neighbouring_prefix_is_not_banned_with_it() -> None:
    _statuses(SecurityConfig(**SETTINGS), SLASH_64)

    assert ip_ban_manager.is_ip_banned("2001:db8:0:2::1") is False


def test_at_prefix_length_128_every_address_counts_alone() -> None:
    statuses = _statuses(SecurityConfig(**SETTINGS, ipv6_prefix_length=128), SLASH_64)

    assert statuses == [None] * 8
    assert ip_ban_manager.is_ip_banned("2001:db8:0:1::1") is False


def test_ipv4_clients_keep_counting_per_address() -> None:
    statuses = _statuses(SecurityConfig(**SETTINGS), ["198.51.100.9"] * 6)

    assert statuses[0] is None
    assert 403 in statuses
    assert ip_ban_manager.is_ip_banned("198.51.100.9") is True
    assert ip_ban_manager.is_ip_banned("198.51.100.10") is False


def test_the_by_ip_primitive_adds_up_violations_of_one_slash_64() -> None:
    from guard_core.sync.handlers.ratelimit_handler import (
        _by_ip_request_timestamps,
        check_rate_limit_by_ip,
    )

    _by_ip_request_timestamps.clear()
    config = SecurityConfig(**SETTINGS)

    results = [check_rate_limit_by_ip(ip, config) for ip in SLASH_64]

    assert results[0] is True
    assert False in results
    assert ip_ban_manager.is_ip_banned("2001:db8:0:1::ffff") is True
    assert ip_ban_manager.is_ip_banned("2001:db8:0:2::1") is False
