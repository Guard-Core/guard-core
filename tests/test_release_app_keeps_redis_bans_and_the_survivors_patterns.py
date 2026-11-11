import uuid
from collections.abc import Iterator

import pytest

from guard_core._utils.app_managers import release_app
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers import suspatterns_handler as patterns_module
from guard_core.handlers.ipban_handler import IPBanManager, ip_ban_manager_for
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest
from tests.protocol_only_redis import REDIS_URL

_BANNED_BY_ANOTHER_WORKER = "203.0.113.50"


@pytest.fixture(autouse=True)
def _defaults_unserved() -> Iterator[None]:
    ipban_module._APP_BAN_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()
    yield
    ipban_module._APP_BAN_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()
    ipban_module.ip_ban_manager.banned_ips.clear()


def _config(prefix: str) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_ip_banning=True,
        enable_rate_limiting=False,
    )


async def test_a_ban_another_worker_makes_in_redis_still_refuses_after_release() -> (
    None
):
    prefix = f"wp616:r3-{uuid.uuid4().hex[:8]}:"
    config = _config(prefix)
    redis = RedisManager(config)
    await HandlerInitializer(config, redis_handler=redis).initialize_redis_handlers()
    other_redis = RedisManager(_config(prefix))
    await other_redis.initialize()
    other_worker = IPBanManager._fresh()
    await other_worker.initialize_redis(other_redis)
    try:
        release_app(config)
        assert await other_worker.ban_ip(_BANNED_BY_ANOTHER_WORKER, 120)
        manager = ip_ban_manager_for(config)
        assert await manager.is_ip_banned(_BANNED_BY_ANOTHER_WORKER, config=config)
        ip_ban_manager_for(config, bind=True)
        assert await manager.is_ip_banned(_BANNED_BY_ANOTHER_WORKER, config=config)
    finally:
        await other_redis.delete_pattern("*")
        await redis.close()
        await other_redis.close()


async def test_the_survivor_keeps_its_runtime_pattern_when_the_other_is_released() -> (
    None
):
    first = _config("wp616:r3-shared:")
    second = _config("wp616:r3-shared:")
    HandlerInitializer(first)
    HandlerInitializer(second)
    manager = sus_patterns_manager_for(second)
    assert manager is sus_patterns_manager_for(first)
    assert await manager.add_pattern(r"zzcustomzz", custom=True)
    request = MockGuardRequest(path="/s?q=zzcustomzz", client_host="203.0.113.9")
    assert (await detect_penetration_attempt(request, second)).is_threat
    assert (await detect_penetration_attempt(request, first)).is_threat
    release_app(first)
    assert (await detect_penetration_attempt(request, second)).is_threat
