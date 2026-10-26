import time
from collections.abc import AsyncIterator, Iterator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core._dynamic_rules import (
    dump_last_known_rules_snapshot,
    load_last_known_ownership,
)
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import DynamicRules, SecurityConfig
from tests.conftest import REDIS_PREFIX, REDIS_URL
from tests.fake_agent import mock_agent

PATTERN = r"wp11restartpattern\d{2,4}"
RULE_IP = "198.51.100.77"


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
        enable_agent=True,
        agent_api_key="test-api-key",
        enable_dynamic_rules=True,
    )


def _rules(**overrides: Any) -> DynamicRules:
    base: dict[str, Any] = {
        "rule_id": "R",
        "version": 1,
        "timestamp": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=60),
        "ip_blacklist": [RULE_IP, RULE_IP],
        "suspicious_patterns": [PATTERN],
    }
    base.update(overrides)
    return DynamicRules(**base)


def _manager(config: SecurityConfig, redis: RedisManager) -> DynamicRuleManager:
    manager = DynamicRuleManager(config)
    manager.redis_handler = redis
    agent = MagicMock()
    agent.send_event = AsyncMock()
    agent.get_dynamic_rules = AsyncMock()
    manager.agent_handler = agent
    return manager


async def _restart(config: SecurityConfig, redis: RedisManager) -> DynamicRuleManager:
    ip_ban_manager.banned_ips.clear()
    if PATTERN in sus_patterns_handler.patterns:
        await sus_patterns_handler.remove_pattern(PATTERN)
    DynamicRuleManager._instance = None
    return _manager(config, redis)


async def _expire(manager: DynamicRuleManager) -> None:
    assert manager.current_rules is not None
    manager.current_rules.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await manager._check_rule_expiry()
    ip_ban_manager.banned_ips.clear()


@pytest.fixture
async def stack() -> AsyncIterator[tuple[SecurityConfig, RedisManager]]:
    config = _config()
    RedisManager._instance = None
    redis = RedisManager(config)
    await redis.initialize()
    ip_ban_manager.redis_handler = redis
    ip_ban_manager.config = config
    yield config, redis
    ip_ban_manager.redis_handler = None
    await redis.close()


@pytest.mark.asyncio
async def test_a_rule_created_ban_is_revoked_after_a_restart(
    stack: tuple[SecurityConfig, RedisManager],
) -> None:
    config, redis = stack
    first = _manager(config, redis)
    mock_agent(first.agent_handler).get_dynamic_rules.return_value = _rules()
    await first.update_rules()
    assert await ip_ban_manager.is_ip_banned(RULE_IP)

    second = await _restart(config, redis)
    await second._hydrate_last_known_rules()
    assert second.current_rules is not None
    assert await ip_ban_manager.is_ip_banned(RULE_IP)
    assert PATTERN in sus_patterns_handler.patterns

    await _expire(second)

    assert not await ip_ban_manager.is_ip_banned(RULE_IP)
    assert PATTERN not in sus_patterns_handler.patterns


@pytest.mark.asyncio
async def test_an_operator_ban_on_a_listed_ip_survives_the_rule_after_a_restart(
    stack: tuple[SecurityConfig, RedisManager],
) -> None:
    config, redis = stack
    await ip_ban_manager.ban_ip(RULE_IP, 3600, "operator")
    first = _manager(config, redis)
    mock_agent(first.agent_handler).get_dynamic_rules.return_value = _rules()
    await first.update_rules()
    assert first._owned_bans == []

    second = await _restart(config, redis)
    await second._hydrate_last_known_rules()
    assert second.current_rules is not None
    await _expire(second)

    assert await ip_ban_manager.is_ip_banned(RULE_IP)
    await ip_ban_manager.unban_ip(RULE_IP)


@pytest.mark.asyncio
async def test_a_snapshot_written_by_4_4_0_owns_nothing(
    stack: tuple[SecurityConfig, RedisManager],
) -> None:
    config, redis = stack
    rules = _rules()
    legacy_payload = dump_last_known_rules_snapshot(rules)
    assert '"owned"' not in legacy_payload
    assert load_last_known_ownership(legacy_payload) == ([], [])
    await redis.set_key("dynamic_rules", "last_known", legacy_payload)
    await redis.set_key("banned_ips", RULE_IP, str(time.time() + 3600), 3600)

    manager = _manager(config, redis)
    await manager._hydrate_last_known_rules()
    assert manager.current_rules is not None
    assert manager._owned_bans == []
    await _expire(manager)

    assert await ip_ban_manager.is_ip_banned(RULE_IP)
    await ip_ban_manager.unban_ip(RULE_IP)


def test_the_snapshot_carries_ownership_as_an_additive_field() -> None:
    payload = dump_last_known_rules_snapshot(
        _rules(), owned_bans=[RULE_IP], owned_patterns=[PATTERN]
    )
    assert load_last_known_ownership(payload) == ([RULE_IP], [PATTERN])
    assert load_last_known_ownership(
        dump_last_known_rules_snapshot(_rules(), [], [])
    ) == (
        [],
        [],
    )
