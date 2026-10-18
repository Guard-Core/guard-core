from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.checks.factory import build_default_pipeline
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.decorators import SecurityDecorator
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest
from tests.test_core.conftest import build_middleware


@pytest.fixture(autouse=True)
async def _redis_down() -> AsyncGenerator[None, None]:
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    redis = Mock()
    redis.get_key = AsyncMock(side_effect=GuardRedisError(503, "down"))
    ip_ban_manager.redis_handler = redis
    yield
    ip_ban_manager.redis_handler = None
    ip_ban_manager.banned_ips.clear()


def _pipeline(**settings: Any) -> SecurityCheckPipeline:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        **settings,
    )
    return build_default_pipeline(build_middleware(config, SecurityDecorator(config)))


async def _status(pipeline: SecurityCheckPipeline, ip: str) -> int | None:
    response = await pipeline.execute(MockGuardRequest(path="/x", client_host=ip))
    return None if response is None else response.status_code


async def test_a_blacklisted_ip_is_still_denied_when_redis_is_down_and_fails_open() -> (
    None
):
    pipeline = _pipeline(redis_fail_open=True, blacklist=["198.51.100.9"])

    assert await _status(pipeline, "198.51.100.9") == 403


async def test_an_ip_outside_the_whitelist_is_still_denied_when_redis_fails_open() -> (
    None
):
    pipeline = _pipeline(redis_fail_open=True, whitelist=["198.51.100.1"])

    assert await _status(pipeline, "203.0.113.5") == 403


async def test_a_locally_banned_ip_is_still_denied_when_redis_fails_open() -> None:
    pipeline = _pipeline(redis_fail_open=True)
    ip_ban_manager.banned_ips["203.0.113.7"] = 4_000_000_000

    assert await _status(pipeline, "203.0.113.7") == 403


async def test_a_clean_ip_passes_when_redis_fails_open() -> None:
    pipeline = _pipeline(redis_fail_open=True)

    assert await _status(pipeline, "203.0.113.8") is None


async def test_redis_down_without_fail_open_still_answers_500() -> None:
    pipeline = _pipeline()

    assert await _status(pipeline, "203.0.113.8") == 500
