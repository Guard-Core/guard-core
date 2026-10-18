from ipaddress import ip_address
from unittest.mock import MagicMock

from guard_core.core.checks.helpers import (
    check_route_ip_access,
    is_ip_in_blacklist,
    is_ip_in_whitelist,
)
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.utils import _check_whitelist, extract_client_ip, is_ip_allowed
from tests.conftest import MockGuardRequest


async def test_whitelist_does_not_override_blacklist_exact() -> None:
    config = SecurityConfig(whitelist=["1.2.3.4"], blacklist=["1.2.3.4"])
    assert await is_ip_allowed("1.2.3.4", config) is False


async def test_whitelist_does_not_override_blacklist_cidr() -> None:
    config = SecurityConfig(whitelist=["10.0.0.0/8"], blacklist=["10.0.0.0/8"])
    assert await is_ip_allowed("10.1.2.3", config) is False


async def test_restrictive_whitelist_blocks_unlisted() -> None:
    config = SecurityConfig(whitelist=["1.2.3.4"])
    assert await is_ip_allowed("5.6.7.8", config) is False


async def test_blacklist_enforced_without_whitelist() -> None:
    config = SecurityConfig(blacklist=["1.2.3.4"])
    assert await is_ip_allowed("1.2.3.4", config) is False


async def test_whitelist_ipv6_compact_matches_expanded_client() -> None:
    config = SecurityConfig(whitelist=["::1"])
    assert await is_ip_allowed("0:0:0:0:0:0:0:1", config) is True


async def test_blacklist_ipv6_expanded_matches_compact_client() -> None:
    config = SecurityConfig(blacklist=["2001:db8::1"])
    assert (
        await is_ip_allowed("2001:0db8:0000:0000:0000:0000:0000:0001", config) is False
    )


async def test_route_whitelist_overrides_blacklist() -> None:
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    route_config.ip_blacklist = ["1.2.3.4"]
    middleware = MagicMock()
    middleware.geo_ip_handler = None
    assert await check_route_ip_access("1.2.3.4", route_config, middleware) is True


async def test_route_whitelist_ipv6_parsed_equality() -> None:
    route_config = RouteConfig()
    route_config.ip_whitelist = ["::1"]
    route_config.ip_blacklist = []
    middleware = MagicMock()
    middleware.geo_ip_handler = None
    assert (
        await check_route_ip_access("0:0:0:0:0:0:0:1", route_config, middleware) is True
    )


async def test_is_ip_in_whitelist_ipv6_parsed_equality() -> None:
    assert (
        is_ip_in_whitelist("0:0:0:0:0:0:0:1", ip_address("0:0:0:0:0:0:0:1"), ["::1"])
        is True
    )


async def test_is_ip_in_blacklist_ipv6_parsed_equality() -> None:
    expanded = "2001:0db8:0000:0000:0000:0000:0000:0001"
    assert is_ip_in_blacklist(expanded, ip_address(expanded), ["2001:db8::1"]) is True


async def test_extract_client_ip_ignores_spoofed_xff_prefix() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "9.9.9.9, 1.2.3.4"},
        client_host="127.0.0.1",
    )
    assert await extract_client_ip(request, config) == "1.2.3.4"


async def test_extract_client_ip_depth2_ignores_spoofed_prefix() -> None:
    config = SecurityConfig(
        trusted_proxies=["127.0.0.1", "5.5.5.5"], trusted_proxy_depth=2
    )
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "9.9.9.9, 1.2.3.4, 5.5.5.5"},
        client_host="127.0.0.1",
    )
    assert await extract_client_ip(request, config) == "1.2.3.4"


async def test_global_and_route_agree_on_ipv6_whitelist_match() -> None:
    config = SecurityConfig(whitelist=["::1"])
    route_config = RouteConfig()
    route_config.ip_whitelist = ["::1"]
    middleware = MagicMock()
    middleware.geo_ip_handler = None

    global_allowed = await is_ip_allowed("0:0:0:0:0:0:0:1", config)
    route_allowed = await check_route_ip_access(
        "0:0:0:0:0:0:0:1", route_config, middleware
    )
    assert global_allowed is True
    assert route_allowed is True


async def test_route_whitelist_non_ip_entry_skipped() -> None:
    assert is_ip_in_whitelist("1.2.3.4", ip_address("1.2.3.4"), ["not-an-ip"]) is False


async def test_route_whitelist_non_ip_entry_string_fallback() -> None:
    assert is_ip_in_whitelist("token", ip_address("1.2.3.4"), ["token"]) is True


async def test_restrictive_route_whitelist_blocks_non_member() -> None:
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    route_config.ip_blacklist = []
    middleware = MagicMock()
    middleware.geo_ip_handler = None
    assert await check_route_ip_access("5.6.7.8", route_config, middleware) is False


async def test_check_whitelist_without_whitelist_allows() -> None:
    config = SecurityConfig()
    assert await _check_whitelist(ip_address("1.2.3.4"), "1.2.3.4", config) is True
