import os
from collections.abc import AsyncGenerator
from unittest.mock import patch

import pytest

from guard_core.handlers._dynamic_rule_application import RuleSideEffects
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import suite_redis_prefix

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
RULE_IP = "198.51.100.40"
OTHER_RULE_IP = "198.51.100.41"
RULE_NETWORK = "203.0.113.0/24"
OWNED = ("dynamic_rules", "owned_bans")


@pytest.fixture
async def live_redis() -> AsyncGenerator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=suite_redis_prefix("wp17-owned")
    )
    manager = RedisManager(config)
    await manager.initialize()
    ip_ban_manager.config = config
    ip_ban_manager.redis_handler = manager
    yield manager
    await manager.delete_pattern("*")
    await manager.close()


def _worker(redis: RedisManager) -> DynamicRuleManager:
    DynamicRuleManager._instance = None
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    worker = DynamicRuleManager(redis.config)
    worker.redis_handler = redis
    return worker


async def _owned(redis: RedisManager) -> dict[str, float]:
    async with redis.get_connection() as conn:
        members = await conn.zrange(
            f"{redis.config.redis_prefix}{OWNED[0]}:{OWNED[1]}", 0, -1, withscores=True
        )
    prefix = redis.config.redis_prefix
    return {member.removeprefix(prefix): score for member, score in members}


async def _apply(
    worker: DynamicRuleManager, ips: list[str], duration: int
) -> RuleSideEffects:
    effects = RuleSideEffects()
    await worker._apply_ip_bans(ips, duration, effects.created_bans, effects.skipped)
    return effects


async def _ttl_seconds(redis: RedisManager, namespace: str, key: str) -> float:
    async with redis.get_connection() as conn:
        pttl = await conn.pttl(f"{redis.config.redis_prefix}{namespace}:{key}")
    return float(pttl) / 1000


async def test_two_workers_applying_the_same_set_both_record_their_bans(
    live_redis: RedisManager,
) -> None:
    first = _worker(live_redis)
    await _apply(first, [RULE_IP, OTHER_RULE_IP], 3600)
    second = _worker(live_redis)

    await _apply(second, [RULE_IP, OTHER_RULE_IP], 7200)

    owned = await _owned(live_redis)
    assert set(owned) == {f"banned_ips:{RULE_IP}", f"banned_ips:{OTHER_RULE_IP}"}
    assert await _ttl_seconds(live_redis, "banned_ips", RULE_IP) > 7190
    value = await live_redis.get_key("banned_ips", RULE_IP)
    assert value is not None
    assert owned[f"banned_ips:{RULE_IP}"] == float(value)


async def test_a_rule_lasts_its_duration_over_a_shorter_auto_ban(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    await ip_ban_manager.ban_ip(RULE_IP, 60, "threshold_exceeded")

    await _apply(worker, [RULE_IP], 3600)

    assert await _ttl_seconds(live_redis, "banned_ips", RULE_IP) > 3590
    assert await ip_ban_manager.is_ip_banned(RULE_IP) is True


async def test_the_owned_score_is_the_expiry_the_rule_wrote_not_the_longer_ban(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    await ip_ban_manager.ban_ip(RULE_IP, 7 * 86400, "operator")

    effects = await _apply(worker, [RULE_IP], 3600)

    assert await _ttl_seconds(live_redis, "banned_ips", RULE_IP) > 7 * 86400 - 5
    assert await _owned(live_redis) == {}
    assert effects.created_bans == []


async def test_a_rule_rewrite_over_its_own_ban_extends_it_and_keeps_one_entry(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    await _apply(worker, [RULE_IP], 3600)
    first = (await _owned(live_redis))[f"banned_ips:{RULE_IP}"]

    await _apply(worker, [RULE_IP], 7200)

    owned = await _owned(live_redis)
    assert list(owned) == [f"banned_ips:{RULE_IP}"]
    assert owned[f"banned_ips:{RULE_IP}"] > first
    held = await live_redis.get_key("banned_ips", RULE_IP)
    assert held is not None
    assert owned[f"banned_ips:{RULE_IP}"] == float(held)


async def test_a_rule_banned_network_is_recorded_under_its_network_key(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)

    await _apply(worker, [RULE_NETWORK], 3600)

    assert list(await _owned(live_redis)) == [f"banned_networks:{RULE_NETWORK}"]


async def test_a_manual_ban_is_never_recorded_as_rule_owned(
    live_redis: RedisManager,
) -> None:
    await ip_ban_manager.ban_ip(RULE_IP, 3600, "operator")
    await ip_ban_manager.ban_ip(RULE_NETWORK, 3600, "operator")

    assert await _owned(live_redis) == {}


async def test_revoking_a_rule_ban_removes_its_owned_entry(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    await _apply(worker, [RULE_IP, RULE_NETWORK], 3600)

    await worker._revoke_owned([RULE_IP, RULE_NETWORK], [])

    assert await _owned(live_redis) == {}
    assert await ip_ban_manager.is_ip_banned(RULE_IP) is False


async def test_a_failed_owned_removal_is_logged_and_does_not_stop_the_revoke(
    live_redis: RedisManager, caplog: pytest.LogCaptureFixture
) -> None:
    worker = _worker(live_redis)
    await _apply(worker, [RULE_IP, OTHER_RULE_IP], 3600)
    purge = RedisManager.purge_owned_ban
    failed: list[str] = []

    async def fail_the_first(self: RedisManager, member: str) -> int:
        if not failed:
            failed.append(member)
            raise OSError("down")
        return await purge(self, member)

    with patch.object(RedisManager, "purge_owned_ban", fail_the_first):
        await worker._revoke_owned([RULE_IP, OTHER_RULE_IP], [])

    assert "Failed to revoke IP ban" in caplog.text
    assert await ip_ban_manager.is_ip_banned(RULE_IP) is True
    assert await ip_ban_manager.is_ip_banned(OTHER_RULE_IP) is False
