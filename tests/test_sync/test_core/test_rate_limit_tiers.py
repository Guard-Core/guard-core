import hashlib
import logging
import uuid
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL, MockGuardResponse, SyncMockGuardRequest

IP = "198.51.100.20"
ROUTE_ID = "app.module.handler"


def _config(**settings: Any) -> SyncSecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": True,
        "rate_limit": 1000,
        "rate_limit_window": 60,
    }
    config = SyncSecurityConfig(**{**defaults, **settings})
    config.geo_ip_handler = Mock(get_country=Mock(return_value="US"))
    return config


def _middleware(config: SyncSecurityConfig, manager: RateLimitManager) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_rate_limit_tiers")
    middleware.resolve_route = None
    middleware.rate_limit_handler = manager
    middleware.event_bus = Mock(send_middleware_event=MagicMock())
    middleware.suspicious_request_counts = {}
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    middleware.route_resolver = Mock(should_bypass_check=Mock(return_value=False))
    middleware.geo_ip_handler = config.geo_ip_handler
    return middleware


def _request(path: str = "/x", route_config: RouteConfig | None = None) -> Any:
    request = SyncMockGuardRequest(path=path, client_host=IP)
    request.state.client_ip = IP
    request.state.route_config = route_config
    request.state.guard_route_id = ROUTE_ID
    request.state.is_whitelisted = False
    return request


def _statuses(check: RateLimitCheck, route_config: RouteConfig, count: int) -> Any:
    statuses = []
    for _ in range(count):
        response = check.check(_request(route_config=route_config))
        statuses.append(None if response is None else response.status_code)
    return statuses


def test_route_and_geo_limits_count_in_their_own_buckets() -> None:
    config = _config()
    check = RateLimitCheck(_middleware(config, RateLimitManager(config)))
    route_config = RouteConfig()
    route_config.rate_limit = 4
    route_config.rate_limit_window = 60
    route_config.geo_rate_limits = {"*": (100, 60)}

    assert _statuses(check, route_config, 6) == [None] * 4 + [429, 429]


def test_endpoint_and_route_limits_count_in_their_own_buckets() -> None:
    config = _config(endpoint_rate_limits={"/x": (100, 60)})
    check = RateLimitCheck(_middleware(config, RateLimitManager(config)))
    route_config = RouteConfig()
    route_config.rate_limit = 4
    route_config.rate_limit_window = 60

    assert _statuses(check, route_config, 6) == [None] * 4 + [429, 429]


def test_a_blocked_request_is_recorded_in_no_tier() -> None:
    config = _config(endpoint_rate_limits={"/x": (100, 60)})
    manager = RateLimitManager(config)
    check = RateLimitCheck(_middleware(config, manager))
    route_config = RouteConfig()
    route_config.rate_limit = 1
    route_config.rate_limit_window = 60

    _statuses(check, route_config, 10)

    assert sorted(len(hits) for hits in manager.request_timestamps.values()) == [
        1,
        1,
        1,
    ]


@pytest.fixture
def redis_stack() -> Generator[
    tuple[RateLimitManager, RedisManager, SyncSecurityConfig, Mock], None
]:
    config = _config(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"test:wp3:{uuid.uuid4().hex}:",
        endpoint_rate_limits={"/x": (100, 60)},
    )
    redis = RedisManager(config)
    redis.initialize()
    manager = RateLimitManager(config)
    manager.initialize_redis(redis)
    middleware = _middleware(config, manager)
    try:
        yield manager, redis, config, middleware
    finally:
        redis.delete_pattern("*")
        redis.close()


def _all_limits_route_config() -> RouteConfig:
    route_config = RouteConfig()
    route_config.rate_limit = 50
    route_config.rate_limit_window = 60
    route_config.geo_rate_limits = {"*": (60, 60)}
    return route_config


def test_every_tier_of_a_request_costs_one_redis_command(
    redis_stack: tuple[RateLimitManager, RedisManager, SyncSecurityConfig, Mock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, redis, _, middleware = redis_stack
    check = RateLimitCheck(middleware)
    commands: list[str] = []
    client = redis._redis
    assert client is not None
    original = client.execute_command

    def recording(*args: Any, **kwargs: Any) -> Any:
        commands.append(str(args[0]))
        return original(*args, **kwargs)

    monkeypatch.setattr(client, "execute_command", recording)
    response = check.check(_request(route_config=_all_limits_route_config()))

    assert response is None
    assert commands == ["EVALSHA"]


def test_each_tier_kind_is_part_of_its_redis_key(
    redis_stack: tuple[RateLimitManager, RedisManager, SyncSecurityConfig, Mock],
) -> None:
    _, redis, config, middleware = redis_stack
    check = RateLimitCheck(middleware)
    check.check(_request(route_config=_all_limits_route_config()))

    with redis.get_connection() as conn:
        keys = sorted([key for key in conn.scan_iter(f"{config.redis_prefix}*")])

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
