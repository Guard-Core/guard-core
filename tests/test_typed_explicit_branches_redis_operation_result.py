from collections.abc import Awaitable, Callable
from typing import Concatenate, ParamSpec, TypeVar

import pytest
from redis.asyncio import Redis

from guard_core.handlers.redis_handler import RedisHandlerBase
from guard_core.models import SecurityConfig

P = ParamSpec("P")
T = TypeVar("T")


class _NoResultHandler(RedisHandlerBase):
    async def safe_operation(
        self,
        func: Callable[Concatenate[Redis, P], Awaitable[T]],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> T | None:
        return None


def _handler() -> RedisHandlerBase:
    return _NoResultHandler(SecurityConfig(enable_redis=True, redis_url="redis://x"))


async def test_a_ban_write_that_returns_no_result_is_refused_not_coerced() -> None:
    with pytest.raises(TypeError, match="returned no result"):
        await _handler().write_ban_extending_only(
            "banned_ips", "1.2.3.4", "100.0", 60, version=("ban_version", "counter")
        )


async def test_a_strike_record_that_returns_no_result_is_refused_not_indexed() -> None:
    with pytest.raises(TypeError, match="returned no result"):
        await _handler().record_detection_strikes(
            "1.2.3.4", ["xss"], 100.0, 40.0, 60, 10
        )


async def test_a_category_read_that_returns_no_result_is_refused_not_sorted() -> None:
    with pytest.raises(TypeError, match="returned no result"):
        await _handler().read_detection_categories("1.2.3.4", 40.0)
