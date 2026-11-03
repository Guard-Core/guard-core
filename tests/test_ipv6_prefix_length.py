import pytest
from pydantic import ValidationError

from guard_core.handlers.ratelimit_handler import (
    RateLimitManager,
    _by_ip_request_timestamps,
    check_rate_limit_by_ip,
)
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest, MockGuardResponse


async def _error_response(status_code: int, message: str) -> MockGuardResponse:
    return MockGuardResponse(message, status_code)


def _config(**settings: object) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_rate_limiting=True,
        rate_limit=2,
        rate_limit_window=60,
        **settings,
    )


async def _statuses(config: SecurityConfig, addresses: list[str]) -> list[int | None]:
    manager = RateLimitManager(config)
    outcomes: list[int | None] = []
    for address in addresses:
        request = MockGuardRequest(path="/x", client_host=address)
        response = await manager.check_rate_limit(request, address, _error_response)
        outcomes.append(response.status_code if response else None)
    return outcomes


def _one_slash_64(count: int) -> list[str]:
    return [f"2001:db8:0:1::{index + 1:x}" for index in range(count)]


def test_ipv6_prefix_length_defaults_to_64() -> None:
    assert SecurityConfig(enable_redis=False).ipv6_prefix_length == 64


@pytest.mark.parametrize("length", [48, 56, 64, 128])
def test_ipv6_prefix_length_accepts_48_to_128(length: int) -> None:
    config = SecurityConfig(enable_redis=False, ipv6_prefix_length=length)

    assert config.ipv6_prefix_length == length


@pytest.mark.parametrize("length", [0, 47, 129])
def test_ipv6_prefix_length_outside_48_to_128_is_rejected(length: int) -> None:
    with pytest.raises(ValidationError):
        SecurityConfig(enable_redis=False, ipv6_prefix_length=length)


async def test_addresses_of_one_slash_64_share_one_rate_limit_window() -> None:
    outcomes = await _statuses(_config(), _one_slash_64(8))

    assert outcomes == [None, None, 429, 429, 429, 429, 429, 429]


async def test_another_slash_64_has_its_own_window() -> None:
    addresses = [*_one_slash_64(3), "2001:db8:0:2::1"]

    outcomes = await _statuses(_config(), addresses)

    assert outcomes == [None, None, 429, None]


async def test_prefix_length_128_keeps_one_window_per_address() -> None:
    outcomes = await _statuses(_config(ipv6_prefix_length=128), _one_slash_64(8))

    assert outcomes == [None] * 8


async def test_a_wider_prefix_groups_neighbouring_slash_64s() -> None:
    addresses = ["2001:db8:0:1::1", "2001:db8:0:2::1", "2001:db8:0:3::1"]

    outcomes = await _statuses(_config(ipv6_prefix_length=48), addresses)

    assert outcomes == [None, None, 429]


async def test_ipv4_windows_are_unchanged() -> None:
    outcomes = await _statuses(_config(), ["198.51.100.1"] * 3)

    assert outcomes == [None, None, 429]


async def test_the_by_ip_primitive_groups_a_slash_64() -> None:
    _by_ip_request_timestamps.clear()
    config = _config()

    results = [await check_rate_limit_by_ip(ip, config) for ip in _one_slash_64(4)]

    assert results == [True, True, False, False]
