from unittest.mock import AsyncMock, MagicMock

from guard_core._utils.access_control import check_ip_access
from guard_core._utils.ip_extraction import MALFORMED_FORWARDED_FOR_PREFIX
from guard_core.core.checks.implementations.ip_security import (
    _is_private_peer_without_forwarded_for,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.geo_ip_protocol import GeoIPHandler
from guard_core.utils import extract_client_ip
from tests.conftest import MockGuardRequest


async def test_a_peer_that_is_not_an_address_is_never_a_private_peer() -> None:
    request = MockGuardRequest(client_host="not-an-address")

    assert _is_private_peer_without_forwarded_for(request, "not-an-address") is False


async def test_skipping_the_ip_lists_still_applies_the_country_rules() -> None:
    geo = MagicMock(spec=GeoIPHandler)
    geo.is_initialized = True
    geo.initialize = AsyncMock()
    geo.get_country.return_value = "CN"
    config = SecurityConfig(
        enable_redis=False, blocked_countries=["CN"], geo_ip_handler=geo
    )

    result = await check_ip_access("203.0.113.5", config, geo, skip_ip_lists=True)

    assert result.allowed is False


async def test_a_unix_peer_with_a_malformed_chain_gets_the_malformed_identity() -> None:
    config = SecurityConfig(
        enable_redis=False, trusted_proxies=["unix"], fail_secure=False
    )
    request = MockGuardRequest(
        client_host=None, headers={"X-Forwarded-For": "8.8.8.8,"}
    )

    identity = await extract_client_ip(request, config)

    assert identity.startswith(MALFORMED_FORWARDED_FOR_PREFIX)
