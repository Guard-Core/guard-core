from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import build_middleware


def _raising_geo() -> MagicMock:
    geo = MagicMock(spec=SyncGeoIPHandler)
    geo.is_initialized = True
    geo.initialize = MagicMock()
    geo.get_country.side_effect = RuntimeError("lookup exploded")
    return geo


def _status(**settings: Any) -> int | None:
    geo = _raising_geo()
    config = SecurityConfig(
        geo_ip_handler=geo,
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        **settings,
    )
    middleware = build_middleware(config, SecurityDecorator(config), geo)
    request = SyncMockGuardRequest(path="/x", client_host="203.0.113.5")
    response = build_default_pipeline(middleware).execute(request)
    return None if response is None else response.status_code


@pytest.mark.parametrize(
    "rules", [{"blocked_countries": ["CN"]}, {"whitelist_countries": ["US"]}]
)
def test_a_raising_geo_handler_denies_under_fail_secure(
    rules: dict[str, Any],
) -> None:
    assert _status(**rules) == 403


@pytest.mark.parametrize(
    "rules", [{"blocked_countries": ["CN"]}, {"whitelist_countries": ["US"]}]
)
def test_a_raising_geo_handler_lets_the_request_through_without_fail_secure(
    rules: dict[str, Any],
) -> None:
    assert _status(fail_secure=False, **rules) is None
