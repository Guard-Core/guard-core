import asyncio
from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from guard_core._utils.app_managers import release_app
from guard_core.core.checks import build_default_pipeline
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers import suspatterns_handler as patterns_module
from guard_core.handlers.ratelimit_handler import RateLimitBlock
from guard_core.models import SecurityConfig
from tests.protocol_only_redis import REDIS_URL

_IP = "203.0.113.90"


@pytest.fixture(autouse=True)
def _defaults_unserved() -> Iterator[None]:
    ipban_module._APP_BAN_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()
    yield
    ipban_module._APP_BAN_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()
    ipban_module.ip_ban_manager.banned_ips.clear()


def _config(prefix: str, **settings: object) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_ip_banning=True,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        auto_ban_threshold=2,
        **settings,
    )


def _middleware(config: SecurityConfig, initializer: HandlerInitializer) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.handler_initializer = initializer
    middleware.guard_decorator = None
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=403))
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


def _request(client_ip: str, path: str = "/api/test") -> MagicMock:
    request = MagicMock()
    request.state.client_ip = client_ip
    request.state.route_config = None
    request.state.is_whitelisted = False
    request.url_path = path
    request.url_full = f"https://test{path}"
    return request


class _CountingInitializer(HandlerInitializer):
    reinitializations = 0

    async def reinitialize_after_release(self) -> None:
        type(self).reinitializations += 1
        await asyncio.sleep(0.01)
        await super().reinitialize_after_release()


async def test_two_concurrent_first_requests_after_a_release_initialize_once() -> None:
    config = _config("wp616:r4-once:")
    initializer = _CountingInitializer(config)
    pipeline = build_default_pipeline(_middleware(config, initializer))
    _CountingInitializer.reinitializations = 0
    release_app(config)
    first, second = await asyncio.gather(
        pipeline._rebuild_response(_request(_IP)),
        pipeline._rebuild_response(_request(_IP)),
    )
    assert first is None and second is None
    assert _CountingInitializer.reinitializations == 1
    await pipeline._rebuild_response(_request(_IP))
    assert _CountingInitializer.reinitializations == 1
    release_app(config)
    await pipeline._rebuild_response(_request(_IP))
    assert _CountingInitializer.reinitializations == 2
