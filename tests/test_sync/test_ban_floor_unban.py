import math
import os
import time
from collections.abc import Generator

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers._dynamic_rule_application import RuleSideEffects
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import suite_redis_prefix

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
IP = "198.51.100.50"
NETWORK = "203.0.113.0/24"
DAY = 86400
VERSION = ("ban_version", "counter")


@pytest.fixture
def live_redis() -> Generator[RedisManager, None]:
    config = SyncSecurityConfig(
        redis_url=REDIS_URL, redis_prefix=suite_redis_prefix("wp17-floors")
    )
    manager = RedisManager(config)
    manager.initialize()
    ip_ban_manager.config = config
    ip_ban_manager.redis_handler = manager
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    yield manager
    manager.delete_pattern("*")
    manager.close()


def _rule(redis: RedisManager, target: str, duration: int) -> None:
    DynamicRuleManager._instance = None
    worker = DynamicRuleManager(redis.config)
    worker.redis_handler = redis
    effects = RuleSideEffects()
    worker._apply_ip_bans([target], duration, effects.created_bans, effects.skipped)


def _ttl(redis: RedisManager, namespace: str, key: str) -> float:
    with redis.get_connection() as conn:
        return float(conn.pttl(f"{redis.config.redis_prefix}{namespace}:{key}"))


def _floor_exists(redis: RedisManager, namespace: str, key: str) -> bool:
    return bool(redis.exists("ban_floors", f"{namespace}:{key}"))


def _hide_a_rule_ban_under_a_foreign_one(redis: RedisManager, key: str) -> None:
    _rule(redis, key, 3600)
    ip_ban_manager.ban_ip(key, 60, "threshold_exceeded")
    assert _floor_exists(redis, "banned_networks" if "/" in key else "banned_ips", key)


def test_unban_ip_deletes_the_floor(live_redis: RedisManager) -> None:
    _hide_a_rule_ban_under_a_foreign_one(live_redis, IP)

    ip_ban_manager.unban_ip(IP)

    assert not _floor_exists(live_redis, "banned_ips", IP)


def test_unbanning_a_network_deletes_its_floor(
    live_redis: RedisManager,
) -> None:
    _hide_a_rule_ban_under_a_foreign_one(live_redis, NETWORK)

    ip_ban_manager.unban_ip(NETWORK)

    assert not _floor_exists(live_redis, "banned_networks", NETWORK)


def test_unban_inside_deletes_the_floor(live_redis: RedisManager) -> None:
    _hide_a_rule_ban_under_a_foreign_one(live_redis, IP)

    ip_ban_manager.unban_inside(["198.51.100.0/24"])

    assert not _floor_exists(live_redis, "banned_ips", IP)
    assert _ttl(live_redis, "banned_ips", IP) == -2


def test_reset_deletes_every_floor(live_redis: RedisManager) -> None:
    _hide_a_rule_ban_under_a_foreign_one(live_redis, IP)
    _hide_a_rule_ban_under_a_foreign_one(live_redis, NETWORK)

    ip_ban_manager.reset()

    assert not _floor_exists(live_redis, "banned_ips", IP)
    assert not _floor_exists(live_redis, "banned_networks", NETWORK)


def test_the_whitelist_path_deletes_the_floor(live_redis: RedisManager) -> None:
    _hide_a_rule_ban_under_a_foreign_one(live_redis, IP)
    worker = DynamicRuleManager(live_redis.config)

    worker._apply_ip_whitelist([IP])

    assert not _floor_exists(live_redis, "banned_ips", IP)


def test_the_floor_lives_exactly_as_long_as_the_foreign_ban(
    live_redis: RedisManager,
) -> None:
    before = time.time()
    _hide_a_rule_ban_under_a_foreign_one(live_redis, IP)
    after = time.time()
    floor_key = f"{live_redis.config.redis_prefix}ban_floors:banned_ips:{IP}"

    with live_redis.get_connection() as conn:
        foreign_expiry = float(conn.get(floor_key))
        floor_expires_at_ms = int(conn.pexpiretime(floor_key))

    assert before + 60 <= foreign_expiry <= after + 60
    assert floor_expires_at_ms == math.floor(foreign_expiry * 1000)


def test_the_carve_rewrite_moves_the_floor_with_the_ban(
    live_redis: RedisManager,
) -> None:
    prefix = live_redis.config.redis_prefix
    carved, base = "2001:db8:1:2::/64", "2001:db8:1::/48"
    with live_redis.get_connection() as conn:
        conn.set(f"{prefix}banned_identities:{carved}", "9999999999.5", ex=600)
        conn.set(
            f"{prefix}ban_floors:banned_identities:{carved}", "9999999999.5", px=300_000
        )
        ip_ban_manager._move_identity_key(
            live_redis,
            conn,
            f"{prefix}banned_identities:",
            f"{prefix}banned_identities:{carved}",
            base,
            "9999999999.5",
            600_000,
        )
        assert conn.exists(f"{prefix}ban_floors:banned_identities:{carved}") == 0
        assert conn.pttl(f"{prefix}ban_floors:banned_identities:{base}") > 290_000


def test_the_legacy_key_migration_never_meets_a_floor_key(
    live_redis: RedisManager,
) -> None:
    _hide_a_rule_ban_under_a_foreign_one(live_redis, IP)
    before = _ttl(live_redis, "ban_floors", f"banned_ips:{IP}")

    ip_ban_manager._migrate_legacy_ban_keys()

    assert _ttl(live_redis, "ban_floors", f"banned_ips:{IP}") > before - 5000
    assert _floor_exists(live_redis, "banned_ips", IP)
