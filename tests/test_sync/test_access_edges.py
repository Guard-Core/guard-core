from unittest.mock import MagicMock

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.access_control import check_ip_access
from guard_core.sync._utils.ip_extraction import MALFORMED_FORWARDED_FOR_PREFIX
from guard_core.sync.core.checks.implementations.ip_security import (
    _is_private_peer_without_forwarded_for,
)
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
from guard_core.sync.utils import extract_client_ip
from tests.test_sync.conftest import SyncMockGuardRequest


def test_a_peer_that_is_not_an_address_is_never_a_private_peer() -> None:
    request = SyncMockGuardRequest(client_host="not-an-address")

    assert _is_private_peer_without_forwarded_for(request, "not-an-address") is False


def test_skipping_the_ip_lists_still_applies_the_country_rules() -> None:
    geo = MagicMock(spec=SyncGeoIPHandler)
    geo.is_initialized = True
    geo.initialize = MagicMock()
    geo.get_country.return_value = "CN"
    config = SyncSecurityConfig(
        enable_redis=False, blocked_countries=["CN"], geo_ip_handler=geo
    )

    result = check_ip_access("203.0.113.5", config, geo, skip_ip_lists=True)

    assert result.allowed is False


def test_a_unix_peer_with_a_malformed_chain_gets_the_malformed_identity() -> None:
    config = SyncSecurityConfig(
        enable_redis=False, trusted_proxies=["unix"], fail_secure=False
    )
    request = SyncMockGuardRequest(
        client_host=None, headers={"X-Forwarded-For": "8.8.8.8,"}
    )

    identity = extract_client_ip(request, config)

    assert identity.startswith(MALFORMED_FORWARDED_FOR_PREFIX)
