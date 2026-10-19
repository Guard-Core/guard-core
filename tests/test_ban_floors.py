import ipaddress
import os
import time
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


async def _seconds_left(redis: RedisManager, key: str = IP) -> float:
    return await _ttl(redis, "banned_ips", key) / 1000


async def _floor_exists(redis: RedisManager, namespace: str, key: str) -> bool:
    return bool(await redis.exists("ban_floors", f"{namespace}:{key}"))


async def _purge() -> dict[str, int]:
    counts = await ip_ban_manager.purge_rule_owned_bans()
    ip_ban_manager.banned_ips.clear()
    return counts


async def test_a_rule_then_a_shorter_auto_ban_then_a_purge_keeps_the_auto_ban(
    live_redis: RedisManager,
) -> None:
    await _rule(live_redis, IP, 3600)
    await ip_ban_manager.ban_ip(IP, 60, "threshold_exceeded")
    assert await _seconds_left(live_redis) > 3590

    counts = await _purge()

    assert counts["rewritten"] == 1
    assert 55 < await _seconds_left(live_redis) <= 60
    assert await ip_ban_manager.is_ip_banned(IP) is True


async def test_the_same_then_a_manual_unban_then_a_purge_stays_unbanned(
    live_redis: RedisManager,
) -> None:
    await _rule(live_redis, IP, 3600)
    await ip_ban_manager.ban_ip(IP, 60, "threshold_exceeded")
    await ip_ban_manager.unban_ip(IP)

    await _purge()

    assert await ip_ban_manager.is_ip_banned(IP) is False
    assert await _ttl(live_redis, "banned_ips", IP) == -2


async def test_an_auto_ban_then_a_longer_rule_then_a_purge_keeps_the_auto_ban(
    live_redis: RedisManager,
) -> None:
    await ip_ban_manager.ban_ip(IP, 60, "threshold_exceeded")
    await _rule(live_redis, IP, 3600)
    assert await _seconds_left(live_redis) > 3590

    await _purge()

    assert 50 < await _seconds_left(live_redis) <= 60
    assert await ip_ban_manager.is_ip_banned(IP) is True


async def test_a_rule_rewrite_over_its_own_ban_writes_no_floor(
    live_redis: RedisManager,
) -> None:
    await _rule(live_redis, IP, 3600)
    await _rule(live_redis, IP, 7200)

    assert not await _floor_exists(live_redis, "banned_ips", IP)
    await _purge()
    assert await _ttl(live_redis, "banned_ips", IP) == -2


async def test_a_seven_day_manual_ban_survives_a_one_hour_rule_and_a_purge(
    live_redis: RedisManager,
) -> None:
    await ip_ban_manager.ban_ip(IP, 7 * DAY, "operator")
    await _rule(live_redis, IP, 3600)

    counts = await _purge()

    assert counts == {"gone": 0, "deleted": 0, "rewritten": 0, "kept": 0, "failed": 0}
    assert await _seconds_left(live_redis) > 7 * DAY - 5


async def test_a_ban_the_rule_extended_past_a_longer_foreign_one_is_left_alone(
    live_redis: RedisManager,
) -> None:
    await _rule(live_redis, IP, 3600)
    await ip_ban_manager.ban_ip(IP, 7 * DAY, "operator")

    counts = await _purge()

    assert counts["kept"] == 1
    assert await _seconds_left(live_redis) > 7 * DAY - 5


async def test_a_v440_rule_ban_has_no_owned_entry_and_counts_as_foreign(
    live_redis: RedisManager,
) -> None:
    await ip_ban_manager.ban_ip(IP, 1800, "dynamic_rule_from_a_v4_4_0_worker")
    await _rule(live_redis, IP, 7200)
    assert await _seconds_left(live_redis) > 7190

    await _purge()

    assert 1790 < await _seconds_left(live_redis) <= 1800


async def test_a_thirty_and_a_sixty_second_foreign_ban_keep_sixty(
    live_redis: RedisManager,
) -> None:
    await ip_ban_manager.ban_ip(IP, 60, "threshold_exceeded")
    await ip_ban_manager.ban_ip(IP, 30, "threshold_exceeded")
    await ip_ban_manager.ban_ip(IP, 60, "threshold_exceeded")

    assert 55 < await _seconds_left(live_redis) <= 60


async def test_a_seventeen_digit_expiry_is_compared_exactly(
    live_redis: RedisManager,
) -> None:
    now = time.time()
    first = f"{int(now) + 3600}.1234567"
    other = f"{int(now) + 3600}.1234572"
    await live_redis.write_ban_extending_only(
        "banned_ips", IP, first, 3600, version=VERSION, rule_owned=True
    )
    member = f"{live_redis.config.redis_prefix}banned_ips:{IP}"
    async with live_redis.get_connection() as conn:
        assert float(await conn.zscore(live_redis._owned_bans_key(), member)) == float(
            first
        )
        await conn.set(member, other, ex=3600)

    assert await live_redis.purge_owned_ban(member) == 3
    assert await live_redis.get_key("banned_ips", IP) == other

    await live_redis.write_ban_extending_only(
        "banned_ips", "198.51.100.51", first, 3600, version=VERSION, rule_owned=True
    )
    other_member = f"{live_redis.config.redis_prefix}banned_ips:198.51.100.51"
    assert await live_redis.purge_owned_ban(other_member) == 1


async def test_a_v440_unban_then_a_rule_write_then_a_purge_never_rebans(
    live_redis: RedisManager,
) -> None:
    await _rule(live_redis, IP, 3600)
    await ip_ban_manager.ban_ip(IP, 60, "threshold_exceeded")
    await live_redis.delete("banned_ips", IP)
    assert await _floor_exists(live_redis, "banned_ips", IP)

    await _rule(live_redis, IP, 1200)
    assert not await _floor_exists(live_redis, "banned_ips", IP)
    await _purge()

    assert await ip_ban_manager.is_ip_banned(IP) is False


async def test_a_v440_unban_then_a_purge_never_rebans(
    live_redis: RedisManager,
) -> None:
    await _rule(live_redis, IP, 3600)
    await ip_ban_manager.ban_ip(IP, 60, "threshold_exceeded")
    await live_redis.delete("banned_ips", IP)

    counts = await _purge()

    assert counts["gone"] == 1
    assert await ip_ban_manager.is_ip_banned(IP) is False
    assert not await _floor_exists(live_redis, "banned_ips", IP)


async def test_the_purge_deletes_the_floor_it_rewrote_from(
    live_redis: RedisManager,
) -> None:
    await _hide_a_rule_ban_under_a_foreign_one(live_redis, IP)

    await _purge()

    assert not await _floor_exists(live_redis, "banned_ips", IP)


async def _hide_a_rule_ban_under_a_foreign_one(redis: RedisManager, key: str) -> None:
    await _rule(redis, key, 3600)
    await ip_ban_manager.ban_ip(key, 60, "threshold_exceeded")
    assert await _floor_exists(
        redis, "banned_networks" if "/" in key else "banned_ips", key
    )


async def test_the_purge_without_redis_changes_nothing() -> None:
    saved = ip_ban_manager.redis_handler
    ip_ban_manager.redis_handler = None
    try:
        counts = await ip_ban_manager.purge_rule_owned_bans()
    finally:
        ip_ban_manager.redis_handler = saved

    assert counts == {"gone": 0, "deleted": 0, "rewritten": 0, "kept": 0, "failed": 0}


async def test_a_purged_network_ban_leaves_the_local_list(
    live_redis: RedisManager,
) -> None:
    await _rule(live_redis, NETWORK, 3600)
    network = ipaddress.ip_network(NETWORK)
    ip_ban_manager.banned_networks.append((network, time.time() + 3600))

    await _purge()

    assert ip_ban_manager.banned_networks == []
    assert await _ttl(live_redis, "banned_networks", NETWORK) == -2


async def test_a_purge_advances_the_ban_version_once_for_the_whole_batch(
    live_redis: RedisManager,
) -> None:
    for last_octet in (51, 52, 53):
        await _rule(live_redis, f"198.51.100.{last_octet}", 3600)
    assert await live_redis.get_key("ban_version", "counter") is None

    counts = await _purge()

    assert counts["deleted"] == 3
    assert await live_redis.get_key("ban_version", "counter") == "1"
