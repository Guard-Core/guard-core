import os
import uuid
from collections.abc import AsyncGenerator

import pytest

from guard_core.handlers._dynamic_rule_application import RuleSideEffects
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
IP = "198.51.100.50"
NETWORK = "203.0.113.0/24"
DAY = 86400
VERSION = ("ban_version", "counter")


@pytest.fixture
async def live_redis() -> AsyncGenerator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=f"wp17-floors:{uuid.uuid4().hex}:"
    )
    manager = RedisManager(config)
    await manager.initialize()
    ip_ban_manager.config = config
    ip_ban_manager.redis_handler = manager
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    yield manager
    await manager.delete_pattern("*")
    await manager.close()


async def _rule(redis: RedisManager, target: str, duration: int) -> None:
    DynamicRuleManager._instance = None
    worker = DynamicRuleManager(redis.config)
    worker.redis_handler = redis
    effects = RuleSideEffects()
    await worker._apply_ip_bans(
        [target], duration, effects.created_bans, effects.skipped
    )


async def _ttl(redis: RedisManager, namespace: str, key: str) -> float:
    async with redis.get_connection() as conn:
        return float(await conn.pttl(f"{redis.config.redis_prefix}{namespace}:{key}"))


async def _floor_exists(redis: RedisManager, namespace: str, key: str) -> bool:
    return bool(await redis.exists("ban_floors", f"{namespace}:{key}"))


async def _hide_a_rule_ban_under_a_foreign_one(redis: RedisManager, key: str) -> None:
    await _rule(redis, key, 3600)
    await ip_ban_manager.ban_ip(key, 60, "threshold_exceeded")
    assert await _floor_exists(
        redis, "banned_networks" if "/" in key else "banned_ips", key
    )


async def test_unban_ip_deletes_the_floor(live_redis: RedisManager) -> None:
    await _hide_a_rule_ban_under_a_foreign_one(live_redis, IP)

    await ip_ban_manager.unban_ip(IP)

    assert not await _floor_exists(live_redis, "banned_ips", IP)


async def test_unbanning_a_network_deletes_its_floor(
    live_redis: RedisManager,
) -> None:
    await _hide_a_rule_ban_under_a_foreign_one(live_redis, NETWORK)

    await ip_ban_manager.unban_ip(NETWORK)

    assert not await _floor_exists(live_redis, "banned_networks", NETWORK)


async def test_unban_inside_deletes_the_floor(live_redis: RedisManager) -> None:
    await _hide_a_rule_ban_under_a_foreign_one(live_redis, IP)

    await ip_ban_manager.unban_inside(["198.51.100.0/24"])

    assert not await _floor_exists(live_redis, "banned_ips", IP)
    assert await _ttl(live_redis, "banned_ips", IP) == -2


async def test_reset_deletes_every_floor(live_redis: RedisManager) -> None:
    await _hide_a_rule_ban_under_a_foreign_one(live_redis, IP)
    await _hide_a_rule_ban_under_a_foreign_one(live_redis, NETWORK)

    await ip_ban_manager.reset()

    assert not await _floor_exists(live_redis, "banned_ips", IP)
    assert not await _floor_exists(live_redis, "banned_networks", NETWORK)


async def test_the_whitelist_path_deletes_the_floor(live_redis: RedisManager) -> None:
    await _hide_a_rule_ban_under_a_foreign_one(live_redis, IP)
    worker = DynamicRuleManager(live_redis.config)

    await worker._apply_ip_whitelist([IP])

    assert not await _floor_exists(live_redis, "banned_ips", IP)


async def test_the_floor_lives_exactly_as_long_as_the_foreign_ban(
    live_redis: RedisManager,
) -> None:
    await _hide_a_rule_ban_under_a_foreign_one(live_redis, IP)

    floor = await _ttl(live_redis, "ban_floors", f"banned_ips:{IP}")

    assert 55_000 < floor <= 60_000


async def test_the_carve_rewrite_moves_the_floor_with_the_ban(
    live_redis: RedisManager,
) -> None:
    prefix = live_redis.config.redis_prefix
    carved, base = "2001:db8:1:2::/64", "2001:db8:1::/48"
    async with live_redis.get_connection() as conn:
        await conn.set(f"{prefix}banned_identities:{carved}", "9999999999.5", ex=600)
        await conn.set(
            f"{prefix}ban_floors:banned_identities:{carved}", "9999999999.5", px=300_000
        )
        await ip_ban_manager._move_identity_key(
            conn,
            f"{prefix}banned_identities:",
            f"{prefix}banned_identities:{carved}",
            base,
            "9999999999.5",
            600_000,
        )
        assert await conn.exists(f"{prefix}ban_floors:banned_identities:{carved}") == 0
        assert await conn.pttl(f"{prefix}ban_floors:banned_identities:{base}") > 290_000


async def test_the_legacy_key_migration_never_meets_a_floor_key(
    live_redis: RedisManager,
) -> None:
    await _hide_a_rule_ban_under_a_foreign_one(live_redis, IP)
    before = await _ttl(live_redis, "ban_floors", f"banned_ips:{IP}")

    await ip_ban_manager._migrate_legacy_ban_keys()

    assert await _ttl(live_redis, "ban_floors", f"banned_ips:{IP}") > before - 5000
    assert await _floor_exists(live_redis, "banned_ips", IP)
