import time
import uuid
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL
from tests.test_sync.test_event_attribution import (
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
def redis() -> Generator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=f"wp23-attr:{uuid.uuid4().hex}:"
    )
    manager = RedisManager(config)
    manager.initialize()
    ip_ban_manager.config = config
    ip_ban_manager.redis_handler = manager
    yield manager
    manager.delete_pattern("*")
    manager.close()


def _redis_config(redis: RedisManager, **overrides: Any) -> SecurityConfig:
    return _config(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=redis.config.redis_prefix,
        **overrides,
    )


def _apply_on_a_fresh_worker(
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
    agent.send_event = MagicMock()
    agent.get_dynamic_rules = MagicMock(return_value=rules)
    manager.agent_handler = agent
    manager.update_rules()
    assert manager.current_rules is not None
    return manager


def _fresh_client_view() -> None:
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    ip_ban_manager._operator_networks = None


def _stamp_for(config: SecurityConfig, ip: str = RULE_IP) -> dict[str, Any]:
    middleware = _run(config, _request(ip))
    event = _one(middleware, "ip_blocked")
    assert event["filter_type"] == "banned"
    return _attr(event)


def test_a_redis_backed_rule_ban_carries_the_attribution(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    _apply_on_a_fresh_worker(config, redis, _rules(ip_blacklist=[RULE_IP]))

    assert _stamp_for(config) == DYNAMIC


def test_a_worker_that_applies_the_set_later_gives_the_same_stamp(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    rules = _rules(ip_blacklist=[RULE_IP], ip_ban_duration=3600)
    _apply_on_a_fresh_worker(config, redis, rules)
    first = _stamp_for(config)

    second_manager = _apply_on_a_fresh_worker(config, redis, rules)
    assert second_manager._owned_bans == []

    assert first == DYNAMIC
    assert _stamp_for(config) == DYNAMIC


def test_a_ban_also_in_the_static_blacklist_flags_the_overlap_with_redis(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis, blacklist=(RULE_IP,))
    _apply_on_a_fresh_worker(config, redis, _rules(ip_blacklist=[RULE_IP]))

    assert _stamp_for(config) == DYNAMIC_OVERLAP


def test_an_auto_ban_after_the_owned_ban_expired_is_not_the_rules_with_redis(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    _apply_on_a_fresh_worker(
        config, redis, _rules(ip_blacklist=[RULE_IP], ip_ban_duration=1)
    )
    assert _stamp_for(config) == DYNAMIC
    time.sleep(1.3)
    _fresh_client_view()
    assert ip_ban_manager.ban_ip(RULE_IP, 3600, "penetration_attempt")

    assert _stamp_for(config) == {}


def test_an_operator_ban_inside_a_rule_cidr_is_the_deciding_entry_with_redis(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    _apply_on_a_fresh_worker(config, redis, _rules(ip_blacklist=["198.51.100.0/24"]))
    assert ip_ban_manager.ban_ip(OTHER_IP, 3600, "operator")

    assert _stamp_for(config, OTHER_IP) == {}
    _fresh_client_view()
    assert _stamp_for(config, "198.51.100.30") == DYNAMIC


def test_a_longer_foreign_write_over_the_rules_ban_is_not_the_rules_with_redis(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    _apply_on_a_fresh_worker(
        config, redis, _rules(ip_blacklist=[RULE_IP], ip_ban_duration=60)
    )
    assert ip_ban_manager.ban_ip(RULE_IP, 100_000, "operator")

    assert _stamp_for(config) == {}


def test_a_longer_foreign_write_above_the_local_cap_is_not_the_rules(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    _apply_on_a_fresh_worker(
        config, redis, _rules(ip_blacklist=[RULE_IP], ip_ban_duration=7200)
    )
    assert _stamp_for(config) == DYNAMIC
    assert ip_ban_manager.ban_ip(RULE_IP, 100_000, "operator")
    _fresh_client_view()

    assert _stamp_for(config) == {}


def test_a_foreign_ban_the_rule_did_not_take_over_is_not_the_rules_with_redis(
    redis: RedisManager,
) -> None:
    config = _redis_config(redis)
    ip_ban_manager.config = config
    assert ip_ban_manager.ban_ip(RULE_IP, 100_000, "operator")
    _apply_on_a_fresh_worker(
        config, redis, _rules(ip_blacklist=[RULE_IP], ip_ban_duration=60)
    )
    _fresh_client_view()

    assert _stamp_for(config) == {}
