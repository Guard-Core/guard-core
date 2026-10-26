import hashlib
import logging
import uuid
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from redis.asyncio import Redis

from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.decorators.base import RouteConfig
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, MockGuardRequest, MockGuardResponse
from tests.engine_redis_commands import server_loses_the_script_of_the_next_evalsha

IP = "198.51.100.20"
ROUTE_ID = "app.module.handler"


def _config(**settings: Any) -> SecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": True,
        "rate_limit": 1000,
        "rate_limit_window": 60,
    }
    config = SecurityConfig(**{**defaults, **settings})
    config.geo_ip_handler = Mock(get_country=Mock(return_value="US"))
    return config


def _middleware(config: SecurityConfig, manager: RateLimitManager) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_rate_limit_tiers")
    middleware.resolve_route = None
    middleware.rate_limit_handler = manager
    middleware.event_bus = Mock(send_middleware_event=AsyncMock())
    middleware.suspicious_request_counts = {}
    middleware.create_error_response = AsyncMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    middleware.route_resolver = Mock(should_bypass_check=Mock(return_value=False))
    middleware.geo_ip_handler = config.geo_ip_handler
    return middleware


def _request(path: str = "/x", route_config: RouteConfig | None = None) -> Any:
    request = MockGuardRequest(path=path, client_host=IP)
    request.state.client_ip = IP
    request.state.route_config = route_config
    request.state.guard_route_id = ROUTE_ID
    request.state.is_whitelisted = False
    return request


async def _statuses(
    check: RateLimitCheck, route_config: RouteConfig, count: int
) -> Any:
    statuses = []
    for _ in range(count):
        response = await check.check(_request(route_config=route_config))
        statuses.append(None if response is None else response.status_code)
    return statuses


async def test_route_and_geo_limits_count_in_their_own_buckets() -> None:
    config = _config()
    check = RateLimitCheck(_middleware(config, RateLimitManager(config)))
    route_config = RouteConfig()
    route_config.rate_limit = 4
    route_config.rate_limit_window = 60
    route_config.geo_rate_limits = {"*": (100, 60)}

    assert await _statuses(check, route_config, 6) == [None] * 4 + [429, 429]


async def test_endpoint_and_route_limits_count_in_their_own_buckets() -> None:
    config = _config(endpoint_rate_limits={"/x": (100, 60)})
    check = RateLimitCheck(_middleware(config, RateLimitManager(config)))
    route_config = RouteConfig()
    route_config.rate_limit = 4
    route_config.rate_limit_window = 60

    assert await _statuses(check, route_config, 6) == [None] * 4 + [429, 429]


async def test_a_blocked_request_is_recorded_in_no_tier() -> None:
    config = _config(endpoint_rate_limits={"/x": (100, 60)})
    manager = RateLimitManager(config)
    check = RateLimitCheck(_middleware(config, manager))
    route_config = RouteConfig()
    route_config.rate_limit = 1
    route_config.rate_limit_window = 60

    await _statuses(check, route_config, 10)

    assert sorted(len(hits) for hits in manager.request_timestamps.values()) == [
        1,
        1,
        1,
    ]


@pytest.fixture
async def redis_stack() -> AsyncGenerator[
    tuple[RateLimitManager, RedisManager, SecurityConfig, Mock], None
]:
    config = _config(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"test:wp3:{uuid.uuid4().hex}:",
        endpoint_rate_limits={"/x": (100, 60)},
    )
    redis = RedisManager(config)
    await redis.initialize()
    manager = RateLimitManager(config)
    await manager.initialize_redis(redis)
    middleware = _middleware(config, manager)
    try:
        yield manager, redis, config, middleware
    finally:
        await redis.delete_pattern("*")
        await redis.close()


def _all_limits_route_config() -> RouteConfig:
    route_config = RouteConfig()
    route_config.rate_limit = 50
    route_config.rate_limit_window = 60
    route_config.geo_rate_limits = {"*": (60, 60)}
    return route_config


def _record_commands(client: Redis, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    commands: list[str] = []
    original = client.execute_command

    async def recording(*args: Any, **kwargs: Any) -> Any:
        name = str(args[0])
        if name == "SCRIPT LOAD" and commands[-1:] == ["EVALSHA"]:
            commands.pop()
        else:
            commands.append(name)
        return await original(*args, **kwargs)

    monkeypatch.setattr(client, "execute_command", recording)
    return commands


async def test_every_tier_of_a_request_costs_one_redis_command(
    redis_stack: tuple[RateLimitManager, RedisManager, SecurityConfig, Mock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, redis, _, middleware = redis_stack
    check = RateLimitCheck(middleware)
    client = redis._redis
    assert client is not None
    commands = _record_commands(client, monkeypatch)
    response = await check.check(_request(route_config=_all_limits_route_config()))

    assert response is None
    assert commands == ["EVALSHA"]


async def test_a_script_the_server_lost_still_costs_one_redis_command(
    redis_stack: tuple[RateLimitManager, RedisManager, SecurityConfig, Mock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, redis, _, middleware = redis_stack
    check = RateLimitCheck(middleware)
    client = redis._redis
    assert client is not None
    commands = _record_commands(client, monkeypatch)
    turned = server_loses_the_script_of_the_next_evalsha(monkeypatch)
    response = await check.check(_request(route_config=_all_limits_route_config()))

    assert response is None
    assert len(turned) == 1
    assert commands == ["EVALSHA"]


async def test_each_tier_kind_is_part_of_its_redis_key(
    redis_stack: tuple[RateLimitManager, RedisManager, SecurityConfig, Mock],
) -> None:
    _, redis, config, middleware = redis_stack
    check = RateLimitCheck(middleware)
    await check.check(_request(route_config=_all_limits_route_config()))

    async with redis.get_connection() as conn:
        keys = sorted([key async for key in conn.scan_iter(f"{config.redis_prefix}*")])

    prefix = f"{config.redis_prefix}rate_limit:rate:{IP}"

    def bucket(kind: str, identity: str) -> str:
        return f"{prefix}:{kind}:{hashlib.sha256(identity.encode()).hexdigest()}"

    assert keys == sorted(
        [
            bucket("endpoint", "/x"),
            bucket("route", ROUTE_ID),
            bucket("geo", ROUTE_ID),
            prefix,
        ]
    )
