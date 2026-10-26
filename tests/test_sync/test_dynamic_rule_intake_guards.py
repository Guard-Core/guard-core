import logging
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core._dynamic_rules import content_fingerprint
from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from tests.fake_agent import mock_agent


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
        "global_rate_limit": 50,
        "global_rate_window": 60,
    }
    base.update(overrides)
    return DynamicRules(**base)


def _manager() -> tuple[DynamicRuleManager, SyncSecurityConfig, MagicMock]:
    config = SyncSecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-api-key",
        enable_dynamic_rules=True,
        rate_limit=600,
    )
    manager = DynamicRuleManager(config)
    agent = MagicMock()
    agent.send_event = MagicMock()
    agent.get_dynamic_rules = MagicMock()
    manager.agent_handler = agent
    return manager, config, agent.send_event


def _poll(manager: DynamicRuleManager, answer: Any) -> None:
    mock_agent(manager.agent_handler).get_dynamic_rules.return_value = answer
    manager.update_rules()


def test_a_complete_platform_default_object_is_ignored_not_applied() -> None:
    manager, config, send_event = _manager()
    wire = {**_rules().model_dump(), "is_platform_default": True}
    _poll(manager, SimpleNamespace(**wire))

    assert config.rate_limit == 600
    assert manager.current_rules is None
    send_event.assert_not_called()


def test_a_complete_object_without_the_flag_or_with_it_false_is_applied() -> None:
    manager, config, _ = _manager()
    wire = _rules().model_dump()
    _poll(manager, SimpleNamespace(**wire, is_platform_default=False))
    assert config.rate_limit == 50


def test_the_stored_fingerprint_decides_whether_a_poll_is_a_change() -> None:
    manager, _, send_event = _manager()
    rules = _rules(expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
    _poll(manager, rules)
    assert manager._current_fingerprint == content_fingerprint(rules)
    sent = send_event.call_count
    unchanged_poll = rules.model_copy()

    assert manager.current_rules is not None
    manager.current_rules.expires_at = datetime.now(timezone.utc) + timedelta(hours=2)
    _poll(manager, unchanged_poll)

    assert send_event.call_count == sent


def test_apply_records_the_time_and_the_applied_rule() -> None:
    manager, _, _ = _manager()
    rules = _rules()
    _poll(manager, rules)
    assert manager.current_rules == rules
    assert manager.last_update > 0


def test_rejection_is_logged_once_with_the_problems(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager, _, _ = _manager()
    bad = _rules(global_rate_limit=-5)
    with caplog.at_level(
        logging.WARNING, logger="guard_core.sync.handlers.dynamic_rule"
    ):
        _poll(manager, bad)
        _poll(manager, bad)

    messages = [r.getMessage() for r in caplog.records if "rejected" in r.getMessage()]
    assert len(messages) == 1
    assert messages[0].startswith("Dynamic rule R v1 rejected, keeping the last-known")
    assert "global_rate_limit: -5 (must be at least 1)" in messages[0]


def test_platform_default_and_expired_warnings_are_logged_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager, _, _ = _manager()
    default = SimpleNamespace(
        **{**_rules(rule_id="default-p").model_dump(), "is_platform_default": True}
    )
    expired = _rules(
        rule_id="old", expires_at=datetime.now(timezone.utc) - timedelta(seconds=5)
    )
    with caplog.at_level(
        logging.WARNING, logger="guard_core.sync.handlers.dynamic_rule"
    ):
        for answer in (default, default, expired, expired):
            _poll(manager, answer)

    texts = [r.getMessage() for r in caplog.records]
    assert (
        texts.count(
            "Dynamic rule default-p v1 is a platform default, not an operator rule; "
            "ignoring"
        )
        == 1
    )
    assert texts.count("Dynamic rule old v1 already expired on receipt; ignoring") == 1
    assert manager.current_rules is None


def test_update_rules_is_a_no_op_without_the_feature_or_without_an_agent() -> None:
    manager, config, _ = _manager()
    mock_agent(manager.agent_handler).get_dynamic_rules.return_value = _rules()
    manager.agent_handler = None
    manager.update_rules()
    assert manager.current_rules is None

    manager2_agent = MagicMock()
    manager2_agent.get_dynamic_rules = MagicMock(return_value=_rules())
    manager.agent_handler = manager2_agent
    object.__setattr__(config, "enable_dynamic_rules", False)
    manager.update_rules()
    manager2_agent.get_dynamic_rules.assert_not_called()


def test_applying_and_failing_updates_are_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager, _, _ = _manager()
    with caplog.at_level(logging.INFO, logger="guard_core.sync.handlers.dynamic_rule"):
        _poll(manager, _rules())
    assert "Applying dynamic rules: R v1" in [r.getMessage() for r in caplog.records]

    mock_agent(manager.agent_handler).get_dynamic_rules.side_effect = RuntimeError(
        "boom"
    )
    with caplog.at_level(logging.ERROR, logger="guard_core.sync.handlers.dynamic_rule"):
        manager.update_rules()
    assert "Failed to update dynamic rules: boom" in [
        r.getMessage() for r in caplog.records
    ]


def test_a_failing_apply_step_is_logged_before_the_update_failure(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager, _, _ = _manager()
    monkeypatch.setattr(
        manager, "_swap_config", MagicMock(side_effect=RuntimeError("boom"))
    )
    with caplog.at_level(logging.ERROR, logger="guard_core.sync.handlers.dynamic_rule"):
        _poll(manager, _rules())

    assert [r.getMessage() for r in caplog.records] == [
        "Failed to apply dynamic rules: boom",
        "Failed to update dynamic rules: boom",
    ]
    assert manager.current_rules is None
