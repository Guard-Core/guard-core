import asyncio
import time
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import DynamicRules, SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix
from tests.test_event_attribution import (
    DYNAMIC,
    DYNAMIC_OVERLAP,
    OTHER_IP,
    RULE_IP,
    _attr,
    _config,
    _one,
    _request,
    _rules,
    _run,
)


@pytest.fixture
async def redis() -> AsyncGenerator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=suite_redis_prefix("wp23-attr")
    )
    manager = RedisManager(config)
    await manager.initialize()
    ip_ban_manager.config = config
    ip_ban_manager.redis_handler = manager
    yield manager
    await manager.delete_pattern("*")
    await manager.close()


def _redis_config(redis: RedisManager, **overrides: object) -> SecurityConfig:
    return _config(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=redis.config.redis_prefix,
        **overrides,
    )


async def _apply_on_a_fresh_worker(
    config: SecurityConfig, redis: RedisManager, rules: DynamicRules
) -> DynamicRuleManager:
    """What a worker that starts later sees: nothing cached locally, the shared
    ban state in Redis."""
    DynamicRuleManager._instance = None
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    ip_ban_manager.config = config
    ip_ban_manager.redis_handler = redis
    ip_ban_manager._rule_owned_expiries = {}
    manager = DynamicRuleManager(config)
    manager.redis_handler = redis
    agent = MagicMock()
    agent.send_event = AsyncMock()
    agent.get_dynamic_rules = AsyncMock(return_value=rules)
    manager.agent_handler = agent
    await manager.update_rules()
    assert manager.current_rules is not None
    return manager


def _fresh_client_view() -> None:
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    ip_ban_manager._operator_networks = None


async def _stamp_for(config: SecurityConfig, ip: str = RULE_IP) -> dict[str, Any]:
    middleware = await _run(config, _request(ip))
    event = await _one(middleware, "ip_blocked")
    assert event["filter_type"] == "banned"
    return _attr(event)


async def test_a_redis_backed_rule_ban_carries_the_attribution(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    await _apply_on_a_fresh_worker(config, redis, _rules(ip_blacklist=[RULE_IP]))

    assert await _stamp_for(config) == DYNAMIC


async def test_a_worker_that_applies_the_set_later_gives_the_same_stamp(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    rules = _rules(ip_blacklist=[RULE_IP], ip_ban_duration=3600)
    await _apply_on_a_fresh_worker(config, redis, rules)
    first = await _stamp_for(config)

    second_manager = await _apply_on_a_fresh_worker(config, redis, rules)
    assert second_manager._owned_bans == []

    assert first == DYNAMIC
    assert await _stamp_for(config) == DYNAMIC


async def test_a_ban_also_in_the_static_blacklist_flags_the_overlap_with_redis(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis, blacklist=(RULE_IP,))
    await _apply_on_a_fresh_worker(config, redis, _rules(ip_blacklist=[RULE_IP]))

    assert await _stamp_for(config) == DYNAMIC_OVERLAP


async def test_an_auto_ban_after_the_owned_ban_expired_is_not_the_rules_with_redis(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    await _apply_on_a_fresh_worker(
        config, redis, _rules(ip_blacklist=[RULE_IP], ip_ban_duration=1)
    )
    assert await _stamp_for(config) == DYNAMIC
    await asyncio.sleep(1.3)
    _fresh_client_view()
    assert await ip_ban_manager.ban_ip(RULE_IP, 3600, "penetration_attempt")

    assert await _stamp_for(config) == {}


async def test_an_operator_ban_inside_a_rule_cidr_is_the_deciding_entry_with_redis(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    await _apply_on_a_fresh_worker(
        config, redis, _rules(ip_blacklist=["198.51.100.0/24"])
    )
    assert await ip_ban_manager.ban_ip(OTHER_IP, 3600, "operator")

    assert await _stamp_for(config, OTHER_IP) == {}
    _fresh_client_view()
    assert await _stamp_for(config, "198.51.100.30") == DYNAMIC


async def test_a_longer_foreign_write_over_the_rules_ban_is_not_the_rules_with_redis(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    await _apply_on_a_fresh_worker(
        config, redis, _rules(ip_blacklist=[RULE_IP], ip_ban_duration=60)
    )
    assert await ip_ban_manager.ban_ip(RULE_IP, 100_000, "operator")

    assert await _stamp_for(config) == {}


async def test_a_longer_foreign_write_above_the_local_cap_is_not_the_rules(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ip_ban_manager, "_VERSION_RECHECK_SECONDS", 0.3)
    config = _redis_config(redis)
    await _apply_on_a_fresh_worker(
        config, redis, _rules(ip_blacklist=[RULE_IP], ip_ban_duration=7200)
    )
    assert await _stamp_for(config) == DYNAMIC
    assert await ip_ban_manager.ban_ip(RULE_IP, 100_000, "operator")
    _fresh_client_view()
    await asyncio.sleep(0.4)

    assert await _stamp_for(config) == {}


async def test_a_foreign_ban_the_rule_did_not_take_over_is_not_the_rules_with_redis(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    ip_ban_manager.config = config
    assert await ip_ban_manager.ban_ip(RULE_IP, 100_000, "operator")
    await _apply_on_a_fresh_worker(
        config, redis, _rules(ip_blacklist=[RULE_IP], ip_ban_duration=60)
    )
    _fresh_client_view()

    assert await _stamp_for(config) == {}


def _count_ownership_reads(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    reads: list[str] = []
    handler = ip_ban_manager.redis_handler
    assert handler is not None
    original = handler.owned_ban_state

    async def counting(namespace: str, key: str) -> object:
        reads.append(f"{namespace}:{key}")
        return await original(namespace, key)

    monkeypatch.setattr(handler, "owned_ban_state", counting)
    return reads


async def test_blocked_requests_read_the_ownership_once_not_per_request(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ip_ban_manager, "_VERSION_RECHECK_SECONDS", 60.0)
    config = _redis_config(redis)
    await _apply_on_a_fresh_worker(config, redis, _rules(ip_blacklist=[RULE_IP]))
    reads = _count_ownership_reads(monkeypatch)

    stamps = [await _stamp_for(config) for _ in range(200)]

    assert stamps == [DYNAMIC] * 200
    assert reads == [f"banned_ips:{RULE_IP}"]


async def test_the_cached_ownership_follows_a_longer_foreign_write(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ip_ban_manager, "_VERSION_RECHECK_SECONDS", 0.3)
    config = _redis_config(redis)
    await _apply_on_a_fresh_worker(config, redis, _rules(ip_blacklist=[RULE_IP]))
    assert await _stamp_for(config) == DYNAMIC
    assert await ip_ban_manager.ban_ip(RULE_IP, 100_000, "operator")
    await asyncio.sleep(0.4)

    assert await _stamp_for(config) == {}


async def test_the_cached_ownership_follows_a_later_worker_and_a_revoke(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ip_ban_manager, "_VERSION_RECHECK_SECONDS", 0.3)
    config = _redis_config(redis)
    rules = _rules(ip_blacklist=[RULE_IP])
    await _apply_on_a_fresh_worker(config, redis, rules)
    assert await _stamp_for(config) == DYNAMIC
    manager = await _apply_on_a_fresh_worker(config, redis, rules)
    await asyncio.sleep(0.4)
    assert await _stamp_for(config) == DYNAMIC

    await manager._revoke_all_owned()
    await asyncio.sleep(0.4)

    assert await ip_ban_manager.rule_owns_live_ban(f"banned_ips:{RULE_IP}") is False


async def test_a_redis_failure_while_attributing_logs_once_per_window(
    redis: RedisManager,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.handlers import _ipban_rule_revoke

    monkeypatch.setattr(ip_ban_manager, "_VERSION_RECHECK_SECONDS", 0.0)
    _ipban_rule_revoke._attribution_failure_samples.clear()
    monkeypatch.setattr(
        redis, "owned_ban_state", AsyncMock(side_effect=RuntimeError("down"))
    )
    ip_ban_manager.redis_handler = redis

    with caplog.at_level("WARNING"):
        verdicts = [
            await ip_ban_manager.rule_owns_live_ban(f"banned_ips:{RULE_IP}")
            for _ in range(25)
        ]

    assert verdicts == [False] * 25
    assert [r for r in caplog.records if "Ban attribution skipped" in r.message] != []
    assert (
        len([r for r in caplog.records if "Ban attribution skipped" in r.message]) == 1
    )


async def test_a_redis_test_leaves_a_version_check_older_than_the_recheck(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    await _apply_on_a_fresh_worker(config, redis, _rules(ip_blacklist=[RULE_IP]))
    await _stamp_for(config)
    assert ip_ban_manager._ban_version_seen is not None
    ip_ban_manager._ban_version_checked_at = time.time() - (
        2 * ip_ban_manager._VERSION_RECHECK_SECONDS
    )


async def test_the_next_redis_test_starts_without_the_earlier_ban_version(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    await _apply_on_a_fresh_worker(
        config, redis, _rules(ip_blacklist=["198.51.100.0/24"])
    )
    assert await ip_ban_manager.ban_ip(OTHER_IP, 3600, "operator")

    assert await _stamp_for(config, OTHER_IP) == {}
