from collections.abc import Iterator
from ipaddress import ip_network
from typing import Any
from unittest.mock import patch

import pytest

from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.models import SecurityConfig
from guard_core.utils import (
    IpAccessResult,
    _check_cloud_providers_detail,
    check_ip_access,
    is_ip_allowed,
)

AWS_IP = "198.51.100.7"
AWS_NETWORK = "198.51.100.0/24"


@pytest.fixture(autouse=True)
def aws_ranges() -> Iterator[None]:
    with patch.dict(cloud_handler.ip_ranges, {"AWS": {ip_network(AWS_NETWORK)}}):
        yield


def _config(**overrides: Any) -> SecurityConfig:
    settings: dict[str, Any] = {"enable_redis": False, "block_cloud_providers": {"AWS"}}
    settings.update(overrides)
    return SecurityConfig(**settings)


async def test_check_ip_access_blocks_a_blocked_cloud_provider_with_its_detail() -> (
    None
):
    result = await check_ip_access(AWS_IP, _config())
    assert result == IpAccessResult(
        False,
        "IP belongs to blocked cloud provider: AWS",
        cloud_provider="AWS",
        network=AWS_NETWORK,
        denial_category="cloud",
    )
    assert await is_ip_allowed(AWS_IP, _config()) is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"whitelist": [AWS_IP]},
        {"exempt_ips": [AWS_IP]},
        {"block_cloud_providers": set()},
    ],
)
async def test_whitelisted_exempt_or_unblocked_ips_pass_the_cloud_check(
    overrides: dict[str, Any],
) -> None:
    assert await is_ip_allowed(AWS_IP, _config(**overrides)) is True


async def test_skip_clouds_leaves_cloud_blocking_to_the_caller() -> None:
    assert await is_ip_allowed(AWS_IP, _config(), skip_clouds=True) is True
    result = await check_ip_access(AWS_IP, _config(), skip_clouds=True)
    assert result.allowed is True


async def test_cloud_detail_helper_returns_none_for_an_ip_outside_blocked_ranges() -> (
    None
):
    assert await _check_cloud_providers_detail("192.0.2.1", _config()) is None
    assert await _check_cloud_providers_detail(AWS_IP, _config()) == IpAccessResult(
        False,
        "IP belongs to blocked cloud provider: AWS",
        "AWS",
        AWS_NETWORK,
        "cloud",
    )


async def test_cloud_detail_without_a_resolved_network_keeps_the_generic_reason() -> (
    None
):
    with patch.object(cloud_handler, "get_cloud_provider_details", return_value=None):
        result = await _check_cloud_providers_detail(AWS_IP, _config())
    assert result == IpAccessResult(
        False,
        f"IP {AWS_IP} not in global allowlist/blocklist",
        denial_category="cloud",
    )
