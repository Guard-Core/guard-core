from collections.abc import Generator
from typing import Any

import pytest

from guard_core.handlers import ratelimit_handler
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.ratelimit_handler import check_rate_limit_by_ip
from guard_core.models import SecurityConfig

SLASH_56 = "2001:db8::/56"
FIRST = "2001:db8:0:1::1"
SECOND_NETWORK_NEIGHBOUR = "2001:db8:0:9::1"
SETTINGS: dict[str, Any] = {
    "enable_redis": False,
    "ipv6_prefix_length": 56,
    "rate_limit": 1,
    "rate_limit_window": 60,
    "enable_rate_limit_auto_ban": True,
    "auto_ban_threshold": 3,
    "auto_ban_duration": 600,
}


@pytest.fixture(autouse=True)
def fresh_state() -> Generator[None, None, None]:
    IPBanManager._instance = None
    ratelimit_handler._by_ip_request_timestamps.clear()
    ratelimit_handler._by_ip_autoban_counts.clear()
    yield
    IPBanManager._instance = None
    ratelimit_handler._by_ip_request_timestamps.clear()
    ratelimit_handler._by_ip_autoban_counts.clear()


async def test_without_an_initializer_the_primitive_finds_a_ban_at_its_prefix() -> None:
    config = SecurityConfig(**SETTINGS)
    manager = IPBanManager()
    assert manager.config is None
    await manager.ban_ip(SLASH_56, 600, "t", grouped=True)

    assert await manager._is_ip_banned_under(SECOND_NETWORK_NEIGHBOUR, config) is True
    assert await manager.is_ip_banned(SECOND_NETWORK_NEIGHBOUR) is False


async def test_a_banned_neighbour_neither_counts_nor_re_bans_in_the_primitive() -> None:
    config = SecurityConfig(**SETTINGS)
    await IPBanManager().ban_ip(SLASH_56, 600, "t", grouped=True)

    results = [
        await check_rate_limit_by_ip(SECOND_NETWORK_NEIGHBOUR, config) for _ in range(3)
    ]

    assert False in results
    assert ratelimit_handler._by_ip_autoban_counts.for_app(config) == {}


async def test_a_whitelisted_host_inside_the_prefix_finds_its_own_carved_ban() -> None:
    host = "2001:db8:0:1::5"
    config = SecurityConfig(**SETTINGS, whitelist=[host])
    manager = IPBanManager()
    await manager.ban_ip(f"{host}/128", 600, "t", grouped=True)

    assert await manager._is_ip_banned_under(host, config) is True
    assert await manager._is_ip_banned_under(FIRST, config) is False


async def test_the_primitive_leaves_the_manager_config_alone() -> None:
    config = SecurityConfig(**SETTINGS)

    await check_rate_limit_by_ip(FIRST, config)

    assert IPBanManager().config is None


async def test_the_primitive_keys_its_window_and_ban_by_the_config_identity() -> None:
    config = SecurityConfig(**SETTINGS)
    addresses = [f"2001:db8:0:{index:x}::1" for index in range(1, 9)]

    results = [await check_rate_limit_by_ip(address, config) for address in addresses]

    assert results[0] is True
    assert False in results
    assert list(ratelimit_handler._by_ip_request_timestamps.for_app(config)) == [
        SLASH_56
    ]
