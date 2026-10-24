import logging
import uuid
from collections.abc import Generator
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
from redis import Redis

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks._shared_strikes import record_shared_detection_strikes
from guard_core.sync.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers import ipban_handler
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.protocol_only_redis import REDIS_URL

IP_A = "198.51.100.10"
IP_B = "198.51.100.20"


class _ErrorResponse:
    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        self.headers: dict[str, str] = {}


@dataclass
class _App:
    config: SyncSecurityConfig
    redis: RedisManager
    middleware: Mock

    def ip_check(self) -> IpSecurityCheck:
        return IpSecurityCheck(self.middleware)

    def rate_check(self) -> RateLimitCheck:
        return RateLimitCheck(self.middleware)


def _request(ip: str) -> SyncMockGuardRequest:
    request = SyncMockGuardRequest(path="/x", client_host=ip)
    request.state.client_ip = ip
    request.state.route_config = None
    request.state.is_whitelisted = False
    return request


def _start_app(prefix: str) -> _App:
    config = SyncSecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_ip_banning=True,
        passive_mode=False,
        trusted_proxies=[],
    )
    redis = RedisManager(config)
    middleware = Mock()
    middleware.config = config
    middleware.resolve_route = None
    middleware.logger = logging.getLogger("two_apps")
    middleware.rate_limit_handler = RateLimitManager(config)
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: _ErrorResponse(
            status_code, default_message
        )
    )
    initializer = HandlerInitializer(
        config,
        redis_handler=redis,
        rate_limit_handler=middleware.rate_limit_handler,
    )
    initializer.initialize_redis_handlers()
    middleware.initializer = initializer
    return _App(config, redis, middleware)


@pytest.fixture
def apps() -> Generator[tuple[_App, _App], None]:
    tag = uuid.uuid4().hex[:8]
    app_a = _start_app(f"a{tag}:")
    app_b = _start_app(f"b{tag}:")
    try:
        yield app_a, app_b
    finally:
        for app in (app_a, app_b):
            app.redis.delete_pattern("*")
            app.redis.close()


def _keys(prefix: str) -> set[str]:
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        return {key for key in client.scan_iter(match=f"{prefix}*", count=500)}
    finally:
        client.close()


def test_each_app_resolves_a_ban_manager_of_its_own_prefix(
    apps: tuple[_App, _App],
) -> None:
    app_a, app_b = apps
    manager_a = ipban_handler.ip_ban_manager_for(app_a.config)
    manager_b = ipban_handler.ip_ban_manager_for(app_b.config)
    assert manager_a is not manager_b
    assert manager_a.redis_handler is app_a.redis
    assert manager_b.redis_handler is app_b.redis
    assert app_a.ip_check().ip_ban_manager is manager_a
    assert app_b.ip_check().ip_ban_manager is manager_b
    assert IPBanManager._instance is manager_b


def test_a_ban_through_app_a_lands_under_a_and_app_b_does_not_see_it(
    apps: tuple[_App, _App],
) -> None:
    app_a, app_b = apps
    assert app_a.ip_check().ip_ban_manager.ban_ip(IP_A, 60, "test")
    keys_a, keys_b = (
        _keys(app_a.config.redis_prefix),
        _keys(app_b.config.redis_prefix),
    )
    assert any("banned_ips" in key and IP_A in key for key in keys_a)
    assert not any(IP_A in key for key in keys_b)
    assert app_a.ip_check().ip_ban_manager.is_ip_banned(IP_A)
    assert not app_b.ip_check().ip_ban_manager.is_ip_banned(IP_A)
    blocked = app_a.ip_check().check(_request(IP_A))
    assert blocked is not None
    assert blocked.status_code == 403
    assert app_b.ip_check().check(_request(IP_A)) is None


def test_a_ban_through_app_b_lands_under_b_and_app_a_does_not_see_it(
    apps: tuple[_App, _App],
) -> None:
    app_a, app_b = apps
    assert app_b.ip_check().ip_ban_manager.ban_ip(IP_B, 60, "test")
    keys_a, keys_b = (
        _keys(app_a.config.redis_prefix),
        _keys(app_b.config.redis_prefix),
    )
    assert any("banned_ips" in key and IP_B in key for key in keys_b)
    assert not any(IP_B in key for key in keys_a)
    assert not app_a.ip_check().ip_ban_manager.is_ip_banned(IP_B)
    assert app_a.ip_check().check(_request(IP_B)) is None
    blocked = app_b.ip_check().check(_request(IP_B))
    assert blocked is not None
    assert blocked.status_code == 403


def test_rate_limit_hits_through_each_app_land_only_under_its_prefix(
    apps: tuple[_App, _App],
) -> None:
    app_a, app_b = apps
    assert app_a.rate_check().check(_request(IP_A)) is None
    assert app_b.rate_check().check(_request(IP_B)) is None
    keys_a, keys_b = (
        _keys(app_a.config.redis_prefix),
        _keys(app_b.config.redis_prefix),
    )
    assert any("rate_limit" in key and IP_A in key for key in keys_a)
    assert not any(IP_B in key for key in keys_a)
    assert any("rate_limit" in key and IP_B in key for key in keys_b)
    assert not any(IP_A in key for key in keys_b)
    limited = app_a.rate_check().check(_request(IP_A))
    assert limited is not None
    assert limited.status_code == 429
    assert app_b.rate_check().check(_request(IP_A)) is None


def test_strikes_through_each_app_land_only_under_its_prefix(
    apps: tuple[_App, _App],
) -> None:
    app_a, app_b = apps
    first: Any = record_shared_detection_strikes(app_a.middleware, IP_A, "xss", 60, 100)
    second: Any = record_shared_detection_strikes(
        app_b.middleware, IP_B, "sqli", 60, 100
    )
    assert first is not None
    assert second is not None
    keys_a, keys_b = (
        _keys(app_a.config.redis_prefix),
        _keys(app_b.config.redis_prefix),
    )
    assert any("detection" in key and IP_A in key for key in keys_a)
    assert not any(IP_B in key for key in keys_a)
    assert any("detection" in key and IP_B in key for key in keys_b)
    assert not any(IP_A in key for key in keys_b)
    assert app_a.redis.read_detection_categories(IP_B, 0.0) == []
    assert app_b.redis.read_detection_categories(IP_A, 0.0) == []
