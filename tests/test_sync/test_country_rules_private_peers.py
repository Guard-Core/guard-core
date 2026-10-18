from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import build_middleware


def _unresolving_geo() -> MagicMock:
    geo = MagicMock(spec=SyncGeoIPHandler)
    geo.is_initialized = True
    geo.initialize = MagicMock()
    geo.get_country.return_value = None
    return geo


def _status(
    client_host: str, headers: dict[str, str] | None = None, **settings: Any
) -> int | None:
    geo = _unresolving_geo()
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        geo_ip_handler=geo,
        whitelist_countries=["US"],
        **settings,
    )
    middleware = build_middleware(config, SecurityDecorator(config), geo)
    request = SyncMockGuardRequest(
        path="/x", client_host=client_host, headers=headers or {}
    )
    response = build_default_pipeline(middleware).execute(request)
    return None if response is None else response.status_code


def test_the_flag_defaults_to_off() -> None:
    assert (
        SecurityConfig(enable_redis=False).country_rules_exempt_private_peers is False
    )


def test_the_flag_rejects_a_non_boolean() -> None:
    with pytest.raises(ValidationError):
        SecurityConfig(enable_redis=False, country_rules_exempt_private_peers="maybe")


@pytest.mark.parametrize(
    "peer", ["10.0.0.9", "192.168.1.5", "169.254.1.1", "100.64.0.1"]
)
def test_a_private_peer_is_denied_by_a_country_allow_list_by_default(
    peer: str,
) -> None:
    assert _status(peer) == 403


@pytest.mark.parametrize(
    "peer", ["10.0.0.9", "192.168.1.5", "169.254.1.1", "100.64.0.1"]
)
def test_the_opt_in_exempts_a_private_peer_that_sends_no_forwarded_for(
    peer: str,
) -> None:
    assert _status(peer, country_rules_exempt_private_peers=True) is None


def test_the_opt_in_never_exempts_a_peer_that_sends_forwarded_for() -> None:
    status = _status(
        "10.0.0.9",
        {"X-Forwarded-For": "203.0.113.9"},
        country_rules_exempt_private_peers=True,
    )

    assert status == 403


def test_the_opt_in_does_not_exempt_a_public_peer() -> None:
    assert _status("8.8.8.8", country_rules_exempt_private_peers=True) == 403
