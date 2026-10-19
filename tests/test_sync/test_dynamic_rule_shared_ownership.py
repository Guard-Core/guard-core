import os
import uuid
from collections.abc import Generator
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers._dynamic_rule_application import RuleSideEffects
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.redis_handler import RedisManager

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
RULE_IP = "198.51.100.40"
OTHER_RULE_IP = "198.51.100.41"
RULE_NETWORK = "203.0.113.0/24"
OWNED = ("dynamic_rules", "owned_bans")


@pytest.fixture
def live_redis() -> Generator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=f"wp17-owned:{uuid.uuid4().hex}:"
    )
    manager = RedisManager(config)
    manager.initialize()
    ip_ban_manager.config = config
    ip_ban_manager.redis_handler = manager
    yield manager
    manager.delete_pattern("*")
    manager.close()


def _worker(redis: RedisManager) -> DynamicRuleManager:
    DynamicRuleManager._instance = None
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    worker = DynamicRuleManager(redis.config)
    worker.redis_handler = redis
    return worker


def _owned(redis: RedisManager) -> dict[str, float]:
    with redis.get_connection() as conn:
        members = conn.zrange(
            f"{redis.config.redis_prefix}{OWNED[0]}:{OWNED[1]}", 0, -1, withscores=True
        )
    prefix = redis.config.redis_prefix
    return {member.removeprefix(prefix): score for member, score in members}


def _apply(
    worker: DynamicRuleManager, ips: list[str], duration: int
) -> RuleSideEffects:
    effects = RuleSideEffects()
    worker._apply_ip_bans(ips, duration, effects.created_bans, effects.skipped)
    return effects


def _ttl_seconds(redis: RedisManager, namespace: str, key: str) -> float:
    with redis.get_connection() as conn:
        pttl = conn.pttl(f"{redis.config.redis_prefix}{namespace}:{key}")
    return float(pttl) / 1000


def test_two_workers_applying_the_same_set_both_record_their_bans(
    live_redis: RedisManager,
) -> None:
    first = _worker(live_redis)
    _apply(first, [RULE_IP, OTHER_RULE_IP], 3600)
    second = _worker(live_redis)

    _apply(second, [RULE_IP, OTHER_RULE_IP], 7200)

    owned = _owned(live_redis)
    assert set(owned) == {f"banned_ips:{RULE_IP}", f"banned_ips:{OTHER_RULE_IP}"}
    assert _ttl_seconds(live_redis, "banned_ips", RULE_IP) > 7190
    value = live_redis.get_key("banned_ips", RULE_IP)
    assert owned[f"banned_ips:{RULE_IP}"] == float(value)


def test_a_rule_lasts_its_duration_over_a_shorter_auto_ban(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    ip_ban_manager.ban_ip(RULE_IP, 60, "threshold_exceeded")

    _apply(worker, [RULE_IP], 3600)

    assert _ttl_seconds(live_redis, "banned_ips", RULE_IP) > 3590
    assert ip_ban_manager.is_ip_banned(RULE_IP) is True


def test_the_owned_score_is_the_expiry_the_rule_wrote_not_the_longer_ban(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    ip_ban_manager.ban_ip(RULE_IP, 7 * 86400, "operator")

    effects = _apply(worker, [RULE_IP], 3600)

    assert _ttl_seconds(live_redis, "banned_ips", RULE_IP) > 7 * 86400 - 5
    assert _owned(live_redis) == {}
    assert effects.created_bans == []


def test_a_rule_rewrite_over_its_own_ban_extends_it_and_keeps_one_entry(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    _apply(worker, [RULE_IP], 3600)
    first = (_owned(live_redis))[f"banned_ips:{RULE_IP}"]

    _apply(worker, [RULE_IP], 7200)

    owned = _owned(live_redis)
    assert list(owned) == [f"banned_ips:{RULE_IP}"]
    assert owned[f"banned_ips:{RULE_IP}"] > first
    assert owned[f"banned_ips:{RULE_IP}"] == float(
        live_redis.get_key("banned_ips", RULE_IP)
    )


def test_a_rule_banned_network_is_recorded_under_its_network_key(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)

    _apply(worker, [RULE_NETWORK], 3600)

    assert list(_owned(live_redis)) == [f"banned_networks:{RULE_NETWORK}"]


def test_a_manual_ban_is_never_recorded_as_rule_owned(
    live_redis: RedisManager,
) -> None:
    ip_ban_manager.ban_ip(RULE_IP, 3600, "operator")
    ip_ban_manager.ban_ip(RULE_NETWORK, 3600, "operator")

    assert _owned(live_redis) == {}


def test_revoking_a_rule_ban_removes_its_owned_entry(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    _apply(worker, [RULE_IP, RULE_NETWORK], 3600)

    worker._revoke_owned([RULE_IP, RULE_NETWORK], [])

    assert _owned(live_redis) == {}
    assert ip_ban_manager.is_ip_banned(RULE_IP) is False


def test_a_failed_owned_removal_is_logged_and_does_not_stop_the_revoke(
    live_redis: RedisManager, caplog: pytest.LogCaptureFixture
) -> None:
    worker = _worker(live_redis)
    _apply(worker, [RULE_IP], 3600)

    with patch.object(
        RedisManager, "disown_ban", MagicMock(side_effect=OSError("down"))
    ):
        worker._revoke_owned([RULE_IP], [])

    assert "Failed to revoke IP ban" in caplog.text
    assert ip_ban_manager.is_ip_banned(RULE_IP) is False
