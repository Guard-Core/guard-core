import uuid
from collections.abc import Generator
from typing import Any

import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL, MockGuardResponse

POOL_SIZE = 3


def _error_response(status_code: int, message: str) -> MockGuardResponse:
    return MockGuardResponse(message, status_code)


def _config(**settings: Any) -> SecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": True,
        "redis_url": REDIS_URL,
        "redis_prefix": f"test:wp3:{uuid.uuid4().hex}:",
        "redis_max_connections": POOL_SIZE,
        "rate_limit": 1000,
        "rate_limit_window": 60,
    }
    return SecurityConfig(**{**defaults, **settings})


def _stack(
    config: SecurityConfig,
) -> tuple[RateLimitManager, RedisManager]:
    redis = RedisManager(config)
    redis.initialize()
    manager = RateLimitManager(config)
    manager.initialize_redis(redis)
    return manager, redis


@pytest.fixture
def stack_factory() -> Generator[Any, None]:
    opened: list[RedisManager] = []

    def make(**settings: Any) -> tuple[RateLimitManager, RedisManager]:
        manager, redis = _stack(_config(**settings))
        opened.append(redis)
        return manager, redis

    yield make
    for redis in opened:
        redis.delete_pattern("*")
        redis.close()


def test_the_pool_timeout_is_a_config_field_defaulting_to_one_second() -> None:
    assert SecurityConfig(enable_redis=False).redis_pool_timeout == 1.0


@pytest.mark.parametrize("value", [0, -1.0])
def test_a_pool_timeout_that_is_not_positive_is_rejected(value: float) -> None:
    with pytest.raises(ValidationError):
        SecurityConfig(enable_redis=False, redis_pool_timeout=value)
