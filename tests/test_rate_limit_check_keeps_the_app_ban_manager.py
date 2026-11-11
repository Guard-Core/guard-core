from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from guard_core._utils.app_managers import release_app
from guard_core.core.checks import build_default_pipeline
from guard_core.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.ratelimit_handler import RateLimitBlock
from guard_core.models import SecurityConfig
from tests.protocol_only_redis import REDIS_URL

_IP = "203.0.113.6"


@pytest.fixture(autouse=True)
def _ban_default_unserved() -> Iterator[None]:
    ipban_module._APP_BAN_MANAGERS.forget_default()
    yield
    ipban_module._APP_BAN_MANAGERS.forget_default()
    ipban_module.ip_ban_manager.banned_ips.clear()


def _app_config(prefix: str) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=2,
    )


def rate_limit_middleware(config: SecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=429))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.geo_ip_handler = None
    middleware.suspicious_request_counts = {}
    middleware.rate_limit_handler = Mock(redis_handler=None)
    middleware.rate_limit_handler.report_rate_limit_block = AsyncMock()
    middleware.rate_limit_handler.check_rate_limit_tiers = AsyncMock(
        return_value=RateLimitBlock(0, 2, Mock(status_code=429))
    )
    return middleware


def rate_limit_request(client_ip: str) -> MagicMock:
    request = MagicMock()
    request.state.client_ip = client_ip
    request.state.route_config = None
    request.state.is_whitelisted = False
    request.url_path = "/api/test"
    request.url_full = "https://test/api/test"
    return request


def _ip_check_middleware(config: SecurityConfig) -> Mock:
    middleware = rate_limit_middleware(config)
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=403))
    return middleware


async def test_a_rate_limit_ban_lands_on_the_manager_of_the_app_that_crossed_it() -> (
    None
):
    first = _app_config("wp616:rl-a:")
    second = _app_config("wp616:rl-b:")
    initializer_a = HandlerInitializer(first)
    initializer_b = HandlerInitializer(second)
    default = ip_ban_manager_for(first)
    own = ip_ban_manager_for(second)
    assert default is ipban_module.ip_ban_manager
    assert own is not default
    assert initializer_a.config is first and initializer_b.config is second
    check = RateLimitCheck(rate_limit_middleware(second))
    request = rate_limit_request(_IP)
    await check.check(request)
    await check.check(request)
    assert check.ip_ban_manager is own
    assert await own.is_ip_banned(_IP)
    assert not await default.is_ip_banned(_IP)
    refused = await IpSecurityCheck(_ip_check_middleware(second)).check(
        rate_limit_request(_IP)
    )
    assert refused is not None and refused.status_code == 403
    allowed = await IpSecurityCheck(_ip_check_middleware(first)).check(
        rate_limit_request(_IP)
    )
    assert allowed is None


async def test_a_pipeline_built_after_the_initializer_holds_the_own_manager() -> None:
    first, second = _app_config("wp616:pl-a:"), _app_config("wp616:pl-b:")
    HandlerInitializer(first)
    HandlerInitializer(second)
    own = ip_ban_manager_for(second)
    assert own is not ipban_module.ip_ban_manager
    middleware = rate_limit_middleware(second)
    middleware.guard_decorator = None
    middleware.handler_initializer = None
    pipeline = build_default_pipeline(middleware)
    held = [c.ip_ban_manager for c in pipeline.checks if hasattr(c, "ip_ban_manager")]
    assert held
    assert all(manager is own for manager in held)


async def test_a_late_rate_limit_ban_after_release_lands_on_the_apps_own_manager() -> (
    None
):
    first = _app_config("wp616:late-a:")
    second = _app_config("wp616:late-b:")
    default = ip_ban_manager_for(first, bind=True)
    own = ip_ban_manager_for(second, bind=True)
    check = RateLimitCheck(rate_limit_middleware(second))
    release_app(second)
    request = rate_limit_request(_IP)
    await check.check(request)
    await check.check(request)
    assert check.ip_ban_manager is own
    assert await own.is_ip_banned(_IP)
    assert not await default.is_ip_banned(_IP)
