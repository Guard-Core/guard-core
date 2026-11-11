import uuid
from collections.abc import Iterator

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.app_managers import release_app
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers import ipban_handler as ipban_module
from guard_core.sync.handlers import suspatterns_handler as patterns_module
from guard_core.sync.handlers.ipban_handler import IPBanManager, ip_ban_manager_for
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.protocol_only_redis import REDIS_URL

_BANNED_BY_ANOTHER_WORKER = "203.0.113.50"


@pytest.fixture(autouse=True)
def _defaults_unserved() -> Iterator[None]:
    ipban_module._APP_BAN_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()
    yield
    ipban_module._APP_BAN_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()
    ipban_module.ip_ban_manager.banned_ips.clear()


def _config(prefix: str) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_ip_banning=True,
        enable_rate_limiting=False,
    )


def test_a_ban_another_worker_makes_in_redis_still_refuses_after_release() -> None:
    prefix = f"wp616:r3-{uuid.uuid4().hex[:8]}:"
    config = _config(prefix)
    redis = RedisManager(config)
    HandlerInitializer(config, redis_handler=redis).initialize_redis_handlers()
    other_redis = RedisManager(_config(prefix))
    other_redis.initialize()
    other_worker = IPBanManager._fresh()
    other_worker.initialize_redis(other_redis)
    try:
        release_app(config)
        assert other_worker.ban_ip(_BANNED_BY_ANOTHER_WORKER, 120)
        manager = ip_ban_manager_for(config)
        assert manager.is_ip_banned(_BANNED_BY_ANOTHER_WORKER, config=config)
        ip_ban_manager_for(config, bind=True)
        assert manager.is_ip_banned(_BANNED_BY_ANOTHER_WORKER, config=config)
    finally:
        other_redis.delete_pattern("*")
        redis.close()
        other_redis.close()


def test_the_survivor_keeps_its_runtime_pattern_when_the_other_is_released() -> None:
    first = _config("wp616:r3-shared:")
    second = _config("wp616:r3-shared:")
    HandlerInitializer(first)
    HandlerInitializer(second)
    manager = sus_patterns_manager_for(second)
    assert manager is sus_patterns_manager_for(first)
    assert manager.add_pattern(r"zzcustomzz", custom=True)
    request = SyncMockGuardRequest(path="/s?q=zzcustomzz", client_host="203.0.113.9")
    assert (detect_penetration_attempt(request, second)).is_threat
    assert (detect_penetration_attempt(request, first)).is_threat
    release_app(first)
    assert (detect_penetration_attempt(request, second)).is_threat
