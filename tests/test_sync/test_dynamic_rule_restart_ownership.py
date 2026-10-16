from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core._dynamic_rules import (
    dump_last_known_rules_snapshot,
    load_last_known_ownership,
)
from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from tests.test_sync.conftest import REDIS_PREFIX, REDIS_URL

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
    agent.send_event = MagicMock()
    agent.get_dynamic_rules = MagicMock()
    manager.agent_handler = agent
    return manager


def _restart(config: SecurityConfig, redis: RedisManager) -> DynamicRuleManager:
    ip_ban_manager.banned_ips.clear()
    if PATTERN in sus_patterns_handler.patterns:
        sus_patterns_handler.remove_pattern(PATTERN)
    DynamicRuleManager._instance = None
    return _manager(config, redis)


def _expire(manager: DynamicRuleManager) -> None:
    assert manager.current_rules is not None
    manager.current_rules.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    manager._check_rule_expiry()
    ip_ban_manager.banned_ips.clear()


@pytest.fixture
def stack() -> Iterator[tuple[SecurityConfig, RedisManager]]:
    config = _config()
    RedisManager._instance = None
    redis = RedisManager(config)
    redis.initialize()
    ip_ban_manager.redis_handler = redis
    ip_ban_manager.config = config
    yield config, redis
    ip_ban_manager.redis_handler = None
    redis.close()


def test_a_rule_created_ban_is_revoked_after_a_restart(
    stack: tuple[SecurityConfig, RedisManager],
) -> None:
    config, redis = stack
    first = _manager(config, redis)
    first.agent_handler.get_dynamic_rules.return_value = _rules()
    first.update_rules()
    assert ip_ban_manager.is_ip_banned(RULE_IP)

    second = _restart(config, redis)
    second._hydrate_last_known_rules()
    assert second.current_rules is not None
    assert ip_ban_manager.is_ip_banned(RULE_IP)
    assert PATTERN in sus_patterns_handler.patterns

    _expire(second)

    assert not ip_ban_manager.is_ip_banned(RULE_IP)
    assert PATTERN not in sus_patterns_handler.patterns


def test_an_operator_ban_on_a_listed_ip_survives_the_rule_after_a_restart(
    stack: tuple[SecurityConfig, RedisManager],
) -> None:
    config, redis = stack
    ip_ban_manager.ban_ip(RULE_IP, 3600, "operator")
    first = _manager(config, redis)
    first.agent_handler.get_dynamic_rules.return_value = _rules()
    first.update_rules()
    assert first._owned_bans == []

    second = _restart(config, redis)
    second._hydrate_last_known_rules()
    assert second.current_rules is not None
    _expire(second)

    assert ip_ban_manager.is_ip_banned(RULE_IP)
    ip_ban_manager.unban_ip(RULE_IP)


def test_a_snapshot_written_by_4_4_0_owns_nothing(
    stack: tuple[SecurityConfig, RedisManager],
) -> None:
    config, redis = stack
    rules = _rules()
    legacy_payload = dump_last_known_rules_snapshot(rules)
    assert '"owned"' not in legacy_payload
    assert load_last_known_ownership(legacy_payload) == ([], [])
    redis.set_key("dynamic_rules", "last_known", legacy_payload)
    ip_ban_manager.ban_ip(RULE_IP, 3600, "dynamic_rule")

    manager = _manager(config, redis)
    manager._hydrate_last_known_rules()
    assert manager.current_rules is not None
    assert manager._owned_bans == []
    _expire(manager)

    assert ip_ban_manager.is_ip_banned(RULE_IP)
    ip_ban_manager.unban_ip(RULE_IP)


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
