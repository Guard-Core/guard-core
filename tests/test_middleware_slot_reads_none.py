from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.implementations.cors_preflight import CorsPreflightCheck
from guard_core.core.checks.implementations.custom_request import CustomRequestCheck
from guard_core.core.checks.implementations.https_enforcement import (
    HttpsEnforcementCheck,
)
from guard_core.core.checks.implementations.ip_security import (
    _classify_route_ip_denial,
)
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig


def _middleware(config: SecurityConfig) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.response_factory = None
    middleware.event_bus.send_middleware_event = AsyncMock()
    return middleware


async def test_https_redirect_without_a_response_factory_raises_attribute_error() -> (
    None
):
    check = HttpsEnforcementCheck(_middleware(SecurityConfig(enforce_https=True)))
    with pytest.raises(
        AttributeError,
        match="'NoneType' object has no attribute 'create_https_redirect'",
    ):
        await check._create_https_redirect(MagicMock())


async def test_cors_preflight_without_a_response_factory_raises_attribute_error() -> (
    None
):
    check = CorsPreflightCheck(_middleware(SecurityConfig(enable_redis=False)))
    request = MagicMock()
    request.method = "OPTIONS"
    request.state = MagicMock(spec=[])
    with pytest.raises(
        AttributeError,
        match="'NoneType' object has no attribute 'security_headers_manager'",
    ):
        await check.check(request)


async def test_custom_request_block_without_a_response_factory_raises() -> None:
    config = SecurityConfig(
        enable_redis=False, custom_request_check=AsyncMock(return_value=MagicMock())
    )
    check = CustomRequestCheck(_middleware(config))
    with pytest.raises(
        AttributeError,
        match="'NoneType' object has no attribute 'apply_modifier'",
    ):
        await check.check(MagicMock())


def test_route_ip_denial_by_country_without_a_geo_handler_is_allow_countries() -> None:
    route_config = RouteConfig()
    route_config.blocked_countries = ["CN"]
    assert _classify_route_ip_denial(route_config, None, "203.0.113.9", False) == (
        "allow_countries",
        "country_restriction",
    )
