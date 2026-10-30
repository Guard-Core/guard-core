import time
import uuid
from collections.abc import AsyncGenerator
from typing import Any

import pytest

from guard_core.handlers._ipban_cache import _BanStore
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL

MEMORY_ONLY_IP = "198.51.100.20"
SHARED_IP = "198.51.100.21"


@pytest.fixture
async def stack() -> AsyncGenerator[tuple[IPBanManager, RedisManager], None]:
    prefix = f"wp320:{uuid.uuid4().hex[:8]}:"
    config = SecurityConfig(enable_redis=True, redis_url=REDIS_URL, redis_prefix=prefix)
    redis = RedisManager(config)
    await redis.initialize()
    manager = IPBanManager._fresh()
    manager.config = config
    await manager.initialize_redis(redis)
    yield manager, redis
    async with redis.get_connection() as conn:
        async for key in conn.scan_iter(match=f"{prefix}*"):
            await conn.unlink(key)
    await redis.close()


async def test_a_memory_only_ban_survives_another_workers_version_bump(
    stack: tuple[IPBanManager, RedisManager], monkeypatch: pytest.MonkeyPatch
) -> None:
    manager, redis = stack
    manager._VERSION_RECHECK_SECONDS = 0.0

    async def failing_write(*_args: Any, **_kwargs: Any) -> None:
        raise ConnectionError("simulated Redis outage during the ban write")

    with monkeypatch.context() as outage:
        outage.setattr(redis, "write_ban_extending_only", failing_write)
        await manager.ban_ip(MEMORY_ONLY_IP, 3600, "threshold_exceeded")
    await manager.ban_ip(SHARED_IP, 3600, "threshold_exceeded")
    assert await manager.is_ip_banned(MEMORY_ONLY_IP)

    await redis.incr("ban_version", "counter")

    assert await manager.is_ip_banned(MEMORY_ONLY_IP)
    assert await manager.is_ip_banned(SHARED_IP)


def test_clear_shared_keeps_memory_only_and_foreign_memory_bans() -> None:
    now = time.time()
    store = _BanStore(10, lambda *_: None)
    store["shared"] = now + 100
    store["memory"] = now + 100
    store.mark_memory_only("memory")
    store["foreign"] = now + 100
    store.record_foreign_memory("foreign", now + 100)

    store.clear_shared()

    assert sorted(store) == ["foreign", "memory"]
    assert store.is_memory_only("memory")
    assert store.foreign_memory_expiry("foreign") == now + 100


async def test_a_version_move_clears_a_plain_mapping_of_bans(
    stack: tuple[IPBanManager, RedisManager],
) -> None:
    manager, redis = stack
    manager.banned_ips = {SHARED_IP: time.time() + 100}
    await manager._adopt_version(redis, "1", time.time())
    await manager._adopt_version(redis, "2", time.time())

    assert manager.banned_ips == {}
