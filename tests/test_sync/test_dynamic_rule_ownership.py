from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

PATTERN = r"wp11ownedpattern\d{2,4}"
OTHER_PATTERN = r"wp11otherpattern[a-z]{2,4}"
RULE_IP = "198.51.100.9"
OPERATOR_IP = "198.51.100.10"
AUTO_IP = "198.51.100.11"


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def _rules(**overrides: Any) -> DynamicRules:
    base: dict[str, Any] = {
        "rule_id": "R",
        "version": 1,
        "timestamp": datetime.now(timezone.utc),
    }
    base.update(overrides)
    return DynamicRules(**base)


def _manager() -> DynamicRuleManager:
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-api-key",
        enable_dynamic_rules=True,
    )
    ip_ban_manager.config = config
    manager = DynamicRuleManager(config)
    agent = MagicMock()
    agent.send_event = MagicMock()
    agent.get_dynamic_rules = MagicMock()
    manager.agent_handler = agent
    return manager


def _poll(manager: DynamicRuleManager, answer: Any) -> None:
    manager.agent_handler.get_dynamic_rules.return_value = answer
    manager.update_rules()


def _pattern_present(pattern: str) -> bool:
    return pattern in sus_patterns_handler.patterns


def test_expiry_revokes_the_bans_and_patterns_the_rule_created() -> None:
    manager = _manager()
    rules = _rules(
        suspicious_patterns=[PATTERN],
        ip_blacklist=[RULE_IP],
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=30),
    )
    _poll(manager, rules)
    assert _pattern_present(PATTERN)
    assert ip_ban_manager.is_ip_banned(RULE_IP)

    assert manager.current_rules is not None
    manager.current_rules.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    manager._check_rule_expiry()

    assert not _pattern_present(PATTERN)
    assert not ip_ban_manager.is_ip_banned(RULE_IP)


def test_replacement_without_them_revokes_what_it_no_longer_lists() -> None:
    manager = _manager()
    _poll(
        manager,
        _rules(
            suspicious_patterns=[PATTERN, OTHER_PATTERN],
            ip_blacklist=[RULE_IP, OPERATOR_IP],
        ),
    )
    _poll(
        manager,
        _rules(version=2, suspicious_patterns=[OTHER_PATTERN], ip_blacklist=[RULE_IP]),
    )

    assert not _pattern_present(PATTERN)
    assert _pattern_present(OTHER_PATTERN)
    assert ip_ban_manager.is_ip_banned(RULE_IP)
    assert not ip_ban_manager.is_ip_banned(OPERATOR_IP)

    _poll(manager, _rules(version=3))
    assert not _pattern_present(OTHER_PATTERN)
    assert not ip_ban_manager.is_ip_banned(RULE_IP)


def test_version_zero_revocation_removes_owned_bans_and_patterns() -> None:
    manager = _manager()
    _poll(manager, _rules(suspicious_patterns=[PATTERN], ip_blacklist=[RULE_IP]))
    _poll(
        manager,
        DynamicRules(rule_id="none-p", version=0, timestamp=datetime.now(timezone.utc)),
    )
    assert not _pattern_present(PATTERN)
    assert not ip_ban_manager.is_ip_banned(RULE_IP)


def test_operator_and_auto_bans_and_existing_patterns_are_never_touched() -> None:
    manager = _manager()
    ip_ban_manager.ban_ip(OPERATOR_IP, 3600, "operator")
    ip_ban_manager.ban_ip(AUTO_IP, 3600, "threshold_exceeded")
    assert sus_patterns_handler.add_pattern(OTHER_PATTERN)

    _poll(
        manager,
        _rules(
            suspicious_patterns=[OTHER_PATTERN],
            ip_blacklist=[OPERATOR_IP, RULE_IP],
        ),
    )
    _poll(manager, _rules(version=2))

    assert ip_ban_manager.is_ip_banned(OPERATOR_IP)
    assert ip_ban_manager.is_ip_banned(AUTO_IP)
    assert not ip_ban_manager.is_ip_banned(RULE_IP)
    assert _pattern_present(OTHER_PATTERN)
    sus_patterns_handler.remove_pattern(OTHER_PATTERN)


def test_a_failed_apply_removes_the_bans_and_patterns_it_created() -> None:
    manager = _manager()
    _poll(manager, _rules(ip_blacklist=[RULE_IP]))
    with pytest.raises(RuntimeError, match="boom"):
        failing = _rules(
            version=2, ip_blacklist=[OPERATOR_IP], suspicious_patterns=[PATTERN]
        )
        with patch.object(
            manager, "_swap_config_or_restore", side_effect=RuntimeError("boom")
        ):
            manager._apply_rules(failing)

    assert not ip_ban_manager.is_ip_banned(OPERATOR_IP)
    assert not _pattern_present(PATTERN)
    assert ip_ban_manager.is_ip_banned(RULE_IP)


def test_a_rule_banned_network_is_revoked_with_the_rule() -> None:
    manager = _manager()
    _poll(manager, _rules(ip_blacklist=["203.0.113.0/24"]))
    assert ip_ban_manager.is_ip_banned("203.0.113.5")

    _poll(manager, _rules(version=2))

    assert not ip_ban_manager.is_ip_banned("203.0.113.5")
