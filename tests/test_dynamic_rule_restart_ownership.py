from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import DynamicRules, SecurityConfig
from tests.conftest import REDIS_PREFIX, REDIS_URL

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


@pytest.mark.asyncio
async def test_a_restart_keeps_ownership_so_the_hydrated_rule_revokes_its_bans() -> (
    None
):
    config = _config()
    redis = RedisManager(config)
    await redis.initialize()
    ip_ban_manager.redis_handler = redis
    ip_ban_manager.config = config
    try:
        first = _manager(config, redis)
        first.agent_handler.get_dynamic_rules.return_value = _rules()
        await first.update_rules()
        assert await ip_ban_manager.is_ip_banned(RULE_IP)

        ip_ban_manager.banned_ips.clear()
        await sus_patterns_handler.remove_pattern(PATTERN)
        DynamicRuleManager._instance = None
        second = _manager(config, redis)
        await second._hydrate_last_known_rules()
        assert second.current_rules is not None
        assert await ip_ban_manager.is_ip_banned(RULE_IP)
        assert PATTERN in sus_patterns_handler.patterns

        second.current_rules.expires_at = datetime.now(timezone.utc) - timedelta(
            seconds=1
        )
        await second._check_rule_expiry()

        ip_ban_manager.banned_ips.clear()
        assert not await ip_ban_manager.is_ip_banned(RULE_IP)
        assert PATTERN not in sus_patterns_handler.patterns
    finally:
        ip_ban_manager.redis_handler = None
        await redis.close()
