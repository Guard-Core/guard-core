import json
import logging
import uuid
from collections.abc import Generator, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync._utils.app_scope import app_scope_of
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers._dynamic_rule_purge import purge_fingerprint
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from tests.test_sync.conftest import REDIS_URL

PATTERN = r"wp17purgepattern\d{2,4}"
CONFIG_PATTERN = r"wp17configpattern\d{2,4}"
RULE_IP = "198.51.100.60"
MANUAL_IP = "198.51.100.61"
MARKER = ("dynamic_rules", "purged")
LAST_KNOWN = ("dynamic_rules", "last_known")


class _AgentWithStatus:
    def __init__(self, answer: DynamicRules | None, checked: datetime | None) -> None:
        self.answer = answer
        self.checked = checked
        self.send_event = MagicMock()

    def get_dynamic_rules(self) -> DynamicRules | None:
        return self.answer

    def get_status(self) -> Any:
        return SimpleNamespace(rules_last_checked=self.checked)


class _AgentWithoutStatus:
    def __init__(self, answer: DynamicRules | None) -> None:
        self.answer = answer
        self.send_event = MagicMock()

    def get_dynamic_rules(self) -> DynamicRules | None:
        return self.answer


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


@pytest.fixture
def live_redis() -> Generator[RedisManager, None]:
    config = SyncSecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=f"wp17-purge:{uuid.uuid4().hex}:",
        enable_redis=True,
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
    for pattern in (PATTERN, CONFIG_PATTERN):
        if pattern in sus_patterns_handler.patterns:
            sus_patterns_handler.remove_pattern(pattern)


def _config(
    redis: RedisManager, tmp_path: Path, **overrides: Any
) -> SyncSecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": True,
        "redis_url": REDIS_URL,
        "redis_prefix": redis.config.redis_prefix,
        "enable_agent": True,
        "agent_api_key": "test-api-key",
        "enable_dynamic_rules": True,
        "dynamic_rules_cache_path": tmp_path / "rules.json",
    }
    settings.update(overrides)
    return SyncSecurityConfig(**settings)


def _rules(**overrides: Any) -> DynamicRules:
    base: dict[str, Any] = {
        "rule_id": "dash:board",
        "version": 4,
        "timestamp": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=2),
        "ip_blacklist": [RULE_IP],
        "ip_ban_duration": 3600,
        "suspicious_patterns": [PATTERN],
        "blocked_user_agents": ["wp17bot"],
    }
    base.update(overrides)
    return DynamicRules(**base)


def _manager(config: SyncSecurityConfig, redis: RedisManager, agent: Any = None) -> Any:
    DynamicRuleManager._instance = None
    manager = DynamicRuleManager(config)
    manager.redis_handler = redis
    manager.agent_handler = agent or _AgentWithoutStatus(None)
    return manager


def _hold(manager: DynamicRuleManager, rules: DynamicRules) -> None:
    manager._apply_rules(rules)
    manager.current_rules = rules
    manager._current_fingerprint = None


def _marker(redis: RedisManager) -> dict[str, Any] | None:
    raw = redis.get_key(*MARKER)
    return None if raw is None else json.loads(raw)


def test_a_purge_lifts_the_rule_bans_removes_patterns_and_deletes_snapshots(
    live_redis: RedisManager, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config = _config(live_redis, tmp_path)
    held = _rules()
    _hold(_manager(config, live_redis), held)
    assert ip_ban_manager.is_ip_banned(RULE_IP) is True
    assert PATTERN in sus_patterns_handler.patterns
    assert (tmp_path / "rules.json").exists()
    restarted = _manager(config, live_redis)

    with caplog.at_level(logging.INFO):
        matched = restarted.purge_dynamic_rules("dash:board", 4)

    assert matched is True
    ip_ban_manager.banned_ips.clear()
    assert ip_ban_manager.is_ip_banned(RULE_IP) is False
    assert PATTERN not in sus_patterns_handler.patterns
    assert live_redis.get_key(*LAST_KNOWN) is None
    assert not (tmp_path / "rules.json").exists()
    marker = _marker(live_redis)
    assert marker is not None
    assert (marker["rule_id"], marker["version"]) == ("dash:board", 4)
    assert marker["fingerprint"] == purge_fingerprint(held)
    assert datetime.fromisoformat(marker["purged_at"]) <= datetime.now(timezone.utc)
    with live_redis.get_connection() as conn:
        assert conn.ttl(live_redis.config.redis_prefix + "dynamic_rules:purged") == -1
    line = next(
        r.message for r in caplog.records if "Purged dynamic rules" in r.message
    )
    assert "dash:board v4" in line
    assert "1 rule bans lifted" in line
    assert "nested inside the purged rule bans are cut back to their own expiry" in line


def test_a_purge_touches_only_what_the_rule_owns(
    live_redis: RedisManager, tmp_path: Path
) -> None:
    config = _config(live_redis, tmp_path)
    sus_patterns_handler.add_pattern(CONFIG_PATTERN, custom=True)
    ip_ban_manager.ban_ip(MANUAL_IP, 3600, "operator")
    _hold(_manager(config, live_redis), _rules())

    _manager(config, live_redis).purge_dynamic_rules("dash:board", 4)

    ip_ban_manager.banned_ips.clear()
    assert ip_ban_manager.is_ip_banned(MANUAL_IP) is True
    assert CONFIG_PATTERN in sus_patterns_handler.custom_patterns


def test_a_set_the_snapshot_does_not_hold_is_not_purged(
    live_redis: RedisManager, tmp_path: Path
) -> None:
    config = _config(live_redis, tmp_path)
    _hold(_manager(config, live_redis), _rules())

    matched = _manager(config, live_redis).purge_dynamic_rules("dash:board", 5)

    assert matched is False
    assert ip_ban_manager.is_ip_banned(RULE_IP) is True
    assert _marker(live_redis) is None
    assert live_redis.get_key(*LAST_KNOWN) is not None


def test_the_file_snapshot_alone_is_enough_to_match(
    live_redis: RedisManager, tmp_path: Path
) -> None:
    config = _config(live_redis, tmp_path)
    _hold(_manager(config, live_redis), _rules())
    live_redis.delete(*LAST_KNOWN)

    matched = _manager(config, live_redis).purge_dynamic_rules("dash:board", 4)

    assert matched is True
    assert not (tmp_path / "rules.json").exists()


@pytest.mark.parametrize("enable_dynamic_rules", [True, False])
def test_the_setting_purges_at_start_whatever_dynamic_rules_say(
    live_redis: RedisManager,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    enable_dynamic_rules: bool,
) -> None:
    _hold(_manager(_config(live_redis, tmp_path), live_redis), _rules())
    DynamicRuleManager._instance = None
    config = _config(
        live_redis,
        tmp_path,
        enable_dynamic_rules=enable_dynamic_rules,
        enable_agent=enable_dynamic_rules,
        purge_dynamic_rules_on_start="dash:board:4",
    )
    initializer = HandlerInitializer(config=config, redis_handler=live_redis)

    with (
        caplog.at_level(logging.WARNING),
        patch.object(
            initializer,
            "_initialize_connected_redis_handlers",
            MagicMock(
                side_effect=lambda: setattr(
                    app_scope_of(config), "redis_handler", live_redis
                )
            ),
        ),
    ):
        initializer.initialize_redis_handlers()

    ip_ban_manager.banned_ips.clear()
    assert ip_ban_manager.is_ip_banned(RULE_IP) is False
    assert _marker(live_redis) is not None
    assert any(
        "purge_dynamic_rules_on_start='dash:board:4' is set and matched" in r.message
        for r in caplog.records
    )


def test_the_start_warning_repeats_and_says_when_nothing_matched(
    live_redis: RedisManager, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config = _config(live_redis, tmp_path, purge_dynamic_rules_on_start="gone:1")
    initializer = HandlerInitializer(config=config, redis_handler=live_redis)

    with caplog.at_level(logging.WARNING):
        initializer._purge_configured_dynamic_rules()
        initializer._purge_configured_dynamic_rules()

    warnings = [
        r.message for r in caplog.records if "purge_dynamic_rules_on_start" in r.message
    ]
    assert len(warnings) == 2
    assert all("did not match the last-known snapshot" in w for w in warnings)


def test_no_setting_means_no_purge(live_redis: RedisManager, tmp_path: Path) -> None:
    config = _config(live_redis, tmp_path)
    _hold(_manager(config, live_redis), _rules())
    initializer = HandlerInitializer(config=config, redis_handler=live_redis)

    initializer._purge_configured_dynamic_rules()

    assert ip_ban_manager.is_ip_banned(RULE_IP) is True
    assert _marker(live_redis) is None


@pytest.mark.parametrize("value", ["", "nocolon", ":3", "id:", "id:x", "id:-1"])
def test_a_malformed_setting_is_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        SyncSecurityConfig(enable_redis=False, purge_dynamic_rules_on_start=value)


def test_a_rule_id_with_colons_keeps_them() -> None:
    config = SyncSecurityConfig(
        enable_redis=False, purge_dynamic_rules_on_start="a:b:c:12"
    )

    assert config.purge_dynamic_rules_on_start == "a:b:c:12"


def _purged_worker(
    live_redis: RedisManager, tmp_path: Path, agent: Any, holder: DynamicRules
) -> tuple[DynamicRuleManager, DynamicRules, SyncSecurityConfig]:
    config = _config(live_redis, tmp_path)
    manager = _manager(config, live_redis, agent)
    _hold(manager, holder)
    _manager(config, live_redis).purge_dynamic_rules("dash:board", 4)
    DynamicRuleManager._instance = manager
    return manager, holder, config


def test_a_worker_holding_the_purged_set_reverts_on_its_next_poll_unbans_nobody(
    live_redis: RedisManager, tmp_path: Path
) -> None:
    holder = _rules()
    agent = _AgentWithoutStatus(holder)
    manager, _, config = _purged_worker(live_redis, tmp_path, agent, holder)
    manager.current_rules = holder
    assert config.blocked_user_agents == ["wp17bot"]

    with patch.object(ip_ban_manager, "unban_ip", MagicMock()) as unban:
        manager.update_rules()

    unban.assert_not_called()
    assert manager.get_current_rules() is None
    assert config.blocked_user_agents == []
    assert manager._owned_bans == [] and manager._owned_patterns == []
    assert PATTERN not in sus_patterns_handler.patterns


def test_the_purged_set_stays_off_while_the_agent_answers_its_cached_object(
    live_redis: RedisManager, tmp_path: Path
) -> None:
    holder = _rules()
    manager, _, config = _purged_worker(
        live_redis, tmp_path, _AgentWithoutStatus(holder), holder
    )
    manager.current_rules = holder

    manager.update_rules()
    manager.update_rules()

    assert manager.get_current_rules() is None
    assert config.blocked_user_agents == []
    assert _marker(live_redis) is not None


def test_a_new_object_after_the_revert_applies_without_a_status_field(
    live_redis: RedisManager, tmp_path: Path
) -> None:
    holder = _rules()
    agent = _AgentWithoutStatus(holder)
    manager, _, config = _purged_worker(live_redis, tmp_path, agent, holder)
    manager.current_rules = holder
    manager.update_rules()

    agent.answer = holder.model_copy()
    manager.update_rules()

    assert manager.get_current_rules() is agent.answer
    assert config.blocked_user_agents == ["wp17bot"]
    assert _marker(live_redis) is None


def test_a_different_set_applies_at_once_and_a_fresh_one_ends_the_marker(
    live_redis: RedisManager, tmp_path: Path
) -> None:
    holder = _rules()
    manager, _, _ = _purged_worker(
        live_redis, tmp_path, _AgentWithoutStatus(holder), holder
    )
    manager.current_rules = holder
    manager.update_rules()
    other = _rules(rule_id="other", version=1, blocked_user_agents=["wp17other"])
    manager.agent_handler = _AgentWithoutStatus(other)

    manager.update_rules()

    assert manager.get_current_rules() is other
    assert _marker(live_redis) is None


def test_the_agent_status_decides_freshness_when_it_reports_one(
    live_redis: RedisManager, tmp_path: Path
) -> None:
    holder = _rules()
    stale = datetime.now(timezone.utc) - timedelta(hours=1)
    agent = _AgentWithStatus(holder, stale)
    manager, _, config = _purged_worker(live_redis, tmp_path, agent, holder)
    manager.current_rules = holder
    manager.update_rules()
    assert manager.get_current_rules() is None

    agent.answer = holder.model_copy()
    manager.update_rules()
    assert manager.get_current_rules() is None
    assert _marker(live_redis) is not None

    agent.checked = datetime.now(timezone.utc) + timedelta(seconds=5)
    manager.update_rules()

    assert manager.get_current_rules() is agent.answer
    assert config.blocked_user_agents == ["wp17bot"]
    assert _marker(live_redis) is None


def test_a_status_without_a_check_time_is_never_fresh(
    live_redis: RedisManager, tmp_path: Path
) -> None:
    holder = _rules()
    agent = _AgentWithStatus(holder, None)
    manager, _, _ = _purged_worker(live_redis, tmp_path, agent, holder)
    manager.current_rules = holder

    manager.update_rules()
    agent.answer = holder.model_copy()
    manager.update_rules()

    assert manager.get_current_rules() is None


def test_a_restarted_worker_does_not_hydrate_the_purged_set_from_a_stale_file(
    live_redis: RedisManager, tmp_path: Path
) -> None:
    config = _config(live_redis, tmp_path)
    manager = _manager(config, live_redis)
    _hold(manager, _rules())
    stale_file = (tmp_path / "rules.json").read_text()
    _manager(config, live_redis).purge_dynamic_rules("dash:board", 4)
    (tmp_path / "rules.json").write_text(stale_file)
    restarted = _manager(config, live_redis)

    restarted._hydrate_last_known_rules()

    assert restarted.current_rules is None
    assert restarted._owned_bans == []


def test_a_poll_costs_one_redis_read_for_the_marker(
    live_redis: RedisManager, tmp_path: Path
) -> None:
    manager = _manager(_config(live_redis, tmp_path), live_redis)
    manager.agent_handler = _AgentWithoutStatus(None)
    reads = MagicMock(side_effect=live_redis.get_key)

    with patch.object(live_redis, "get_key", reads):
        manager.update_rules()

    assert reads.call_args_list[0].args == MARKER
    assert reads.call_count == 1


def test_a_purge_without_redis_still_clears_the_file_and_the_patterns(
    tmp_path: Path,
) -> None:
    config = SyncSecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-api-key",
        enable_dynamic_rules=True,
        dynamic_rules_cache_path=tmp_path / "rules.json",
    )
    ip_ban_manager.redis_handler = None
    DynamicRuleManager._instance = None
    manager = DynamicRuleManager(config)
    manager.agent_handler = _AgentWithoutStatus(None)
    _hold(manager, _rules(ip_blacklist=[]))
    assert PATTERN in sus_patterns_handler.patterns

    matched = DynamicRuleManager(config).purge_dynamic_rules("dash:board", 4)

    assert matched is True
    assert not (tmp_path / "rules.json").exists()
    assert PATTERN not in sus_patterns_handler.patterns
    assert DynamicRuleManager(config)._read_purge_marker() is None


def test_a_failed_ban_purge_is_logged_and_leaves_the_rest_purged(
    live_redis: RedisManager, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config = _config(live_redis, tmp_path)
    _hold(_manager(config, live_redis), _rules())

    with (
        patch.object(
            RedisManager, "purge_owned_ban", MagicMock(side_effect=OSError("down"))
        ),
        caplog.at_level(logging.INFO),
    ):
        matched = _manager(config, live_redis).purge_dynamic_rules("dash:board", 4)

    assert matched is True
    assert "Purging the rule ban" in caplog.text
    assert "1 failed" in caplog.text
    assert _marker(live_redis) is not None
    member = f"{live_redis.config.redis_prefix}banned_ips:{RULE_IP}"
    assert member in live_redis.owned_ban_members()


def test_without_a_setting_the_configured_purge_does_nothing(
    live_redis: RedisManager, tmp_path: Path
) -> None:
    manager = _manager(_config(live_redis, tmp_path), live_redis)

    assert manager.purge_configured_dynamic_rules() is False


def test_an_unusable_snapshot_is_logged_and_never_matches(
    live_redis: RedisManager, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config = _config(live_redis, tmp_path)
    live_redis.set_key(*LAST_KNOWN, "{not json")

    matched = _manager(config, live_redis).purge_dynamic_rules("dash:board", 4)

    assert matched is False
    assert "Unusable last-known snapshot while purging" in caplog.text


def test_a_pattern_that_cannot_be_removed_is_logged_and_the_purge_goes_on(
    live_redis: RedisManager, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config = _config(live_redis, tmp_path)
    _hold(_manager(config, live_redis), _rules())

    with patch.object(
        sus_patterns_handler.__class__,
        "remove_pattern",
        MagicMock(side_effect=RuntimeError("boom")),
    ):
        matched = _manager(config, live_redis).purge_dynamic_rules("dash:board", 4)

    assert matched is True
    assert "Failed to remove a purged pattern: boom" in caplog.text
    assert _marker(live_redis) is not None


def test_a_marker_that_cannot_be_written_is_logged(
    live_redis: RedisManager, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config = _config(live_redis, tmp_path)
    _hold(_manager(config, live_redis), _rules())

    with patch.object(
        RedisManager, "set_key", MagicMock(side_effect=OSError("read only"))
    ):
        matched = _manager(config, live_redis).purge_dynamic_rules("dash:board", 4)

    assert matched is True
    assert "Failed to write the dynamic rules purge marker" in caplog.text
    assert _marker(live_redis) is None


def test_an_unusable_marker_is_ignored_with_an_error(
    live_redis: RedisManager, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    manager = _manager(_config(live_redis, tmp_path), live_redis)
    live_redis.set_key(*MARKER, "[]")

    assert manager._read_purge_marker() is None
    assert "Unusable dynamic rules purge marker, ignored" in caplog.text


def test_the_marker_is_cleared_without_redis_and_a_failed_clear_is_logged(
    live_redis: RedisManager, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    manager = _manager(_config(live_redis, tmp_path), live_redis)
    manager.redis_handler = None
    manager._clear_purge_marker()
    manager.redis_handler = live_redis

    with patch.object(RedisManager, "delete", MagicMock(side_effect=OSError("down"))):
        manager._clear_purge_marker()

    assert "Failed to clear the dynamic rules purge marker: down" in caplog.text


def test_a_failing_agent_status_falls_back_to_the_object_check(
    live_redis: RedisManager, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    holder = _rules()
    agent = _AgentWithStatus(holder, None)
    manager, _, _ = _purged_worker(live_redis, tmp_path, agent, holder)
    manager.current_rules = holder
    manager.update_rules()
    agent.answer = holder.model_copy()

    with patch.object(agent, "get_status", MagicMock(side_effect=OSError("no"))):
        manager.update_rules()

    assert "Failed to read the agent status: no" in caplog.text
    assert manager.get_current_rules() is agent.answer


def test_a_check_time_without_a_zone_is_read_as_utc(
    live_redis: RedisManager, tmp_path: Path
) -> None:
    holder = _rules()
    agent = _AgentWithStatus(holder, None)
    manager, _, _ = _purged_worker(live_redis, tmp_path, agent, holder)
    manager.current_rules = holder
    manager.update_rules()
    agent.answer = holder.model_copy()
    agent.checked = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(
        seconds=5
    )

    manager.update_rules()

    assert manager.get_current_rules() is agent.answer


def test_a_revert_that_cannot_remove_a_pattern_is_logged(
    live_redis: RedisManager, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    holder = _rules()
    agent = _AgentWithoutStatus(holder)
    manager, _, _ = _purged_worker(live_redis, tmp_path, agent, holder)
    manager.current_rules = holder

    with patch.object(
        sus_patterns_handler.__class__,
        "remove_pattern",
        MagicMock(side_effect=RuntimeError("boom")),
    ):
        manager.update_rules()

    assert "Failed to remove a purged pattern: boom" in caplog.text
    assert manager.get_current_rules() is None


def test_the_start_purge_without_a_connected_redis_works_from_the_file(
    live_redis: RedisManager, tmp_path: Path
) -> None:
    _hold(_manager(_config(live_redis, tmp_path), live_redis), _rules())
    config = _config(live_redis, tmp_path, purge_dynamic_rules_on_start="dash:board:4")
    DynamicRuleManager._instance = None
    initializer = HandlerInitializer(config=config, redis_handler=live_redis)

    with patch(
        "guard_core.sync.handlers.redis_handler.is_connected_redis_manager",
        return_value=False,
    ):
        initializer._purge_configured_dynamic_rules()

    assert not (tmp_path / "rules.json").exists()
    assert _marker(live_redis) is None


def test_a_purge_that_raises_at_start_is_logged_not_fatal(
    live_redis: RedisManager, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config = _config(live_redis, tmp_path, purge_dynamic_rules_on_start="dash:board:4")
    initializer = HandlerInitializer(config=config, redis_handler=live_redis)

    with patch.object(
        DynamicRuleManager,
        "purge_configured_dynamic_rules",
        MagicMock(side_effect=RuntimeError("boom")),
    ):
        initializer._purge_configured_dynamic_rules()

    assert "Purging the dynamic rules at start failed" in caplog.text
