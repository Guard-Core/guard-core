import logging
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core._dynamic_rules import dump_last_known_rules_snapshot
from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from tests.test_sync.fake_agent import mock_agent


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def _snapshot_rules(**overrides: Any) -> DynamicRules:
    base: dict[str, Any] = {
        "rule_id": "stored",
        "version": 3,
        "timestamp": datetime.now(timezone.utc),
        "global_rate_limit": 50,
        "global_rate_window": 60,
        "ip_blacklist": ["198.51.100.99"],
    }
    base.update(overrides)
    return DynamicRules(**base)


def _hydrating_manager(tmp_path: Path, rules: DynamicRules) -> DynamicRuleManager:
    cache = tmp_path / "rules.json"
    cache.write_text(dump_last_known_rules_snapshot(rules), encoding="utf-8")
    config = SyncSecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-api-key",
        enable_dynamic_rules=True,
        dynamic_rules_cache_path=cache,
        rate_limit=600,
    )
    ip_ban_manager.config = config
    manager = DynamicRuleManager(config)
    agent = MagicMock()
    agent.send_event = MagicMock()
    manager.agent_handler = agent
    return manager


@pytest.mark.parametrize(
    "bad",
    [
        {"ip_blacklist": ["10.0.0.0/33"]},
        {"emergency_whitelist": ["not-an-ip"], "emergency_mode": True},
        {"global_rate_limit": -4},
    ],
)
def test_a_stored_snapshot_the_validation_rejects_is_not_applied(
    tmp_path: Path, bad: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    manager = _hydrating_manager(tmp_path, _snapshot_rules(**bad))

    with caplog.at_level(
        logging.WARNING, logger="guard_core.sync.handlers.dynamic_rule"
    ):
        manager._hydrate_last_known_rules()

    assert manager.current_rules is None
    assert manager.config.rate_limit == 600
    assert manager.config.emergency_mode is False
    assert manager._active_base_snapshot is None
    assert not ip_ban_manager.is_ip_banned("198.51.100.99")
    sent = [
        call.args[0]
        for call in mock_agent(manager.agent_handler).send_event.call_args_list
    ]
    assert [(e.event_type, e.action_taken) for e in sent] == [
        ("dynamic_rule_updated", "rules_rejected")
    ]
    assert "rejected, keeping the last-known rules" in caplog.text


def test_the_rejected_snapshot_is_not_reported_again_by_the_first_poll(
    tmp_path: Path,
) -> None:
    bad = _snapshot_rules(ip_blacklist=["10.0.0.0/33"])
    manager = _hydrating_manager(tmp_path, bad)
    manager._hydrate_last_known_rules()

    mock_agent(manager.agent_handler).get_dynamic_rules = MagicMock(return_value=bad)
    manager.update_rules()

    assert mock_agent(manager.agent_handler).send_event.call_count == 1
