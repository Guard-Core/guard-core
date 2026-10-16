import logging
import threading
import time
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager


def _frozen_datetime(moment: datetime) -> MagicMock:
    clock = MagicMock()
    clock.now.return_value = moment
    return clock


def _apply_plan(
    manager: DynamicRuleManager, rules: DynamicRules | None = None, **fields: Any
) -> None:
    if rules is None:
        rules = DynamicRules(
            rule_id="plan",
            version=1,
            timestamp=datetime.now(timezone.utc),
            **fields,
        )
    plan = manager._build_plan(rules, manager._snapshot_config())
    manager._swap_config(plan)
    manager._announce_plan(plan)


@pytest.fixture
def sample_rules() -> DynamicRules:
    return DynamicRules(
        rule_id="test-rule-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=["172.16.0.100", "10.0.0.50"],
        ip_whitelist=["192.168.1.200"],
        blocked_countries=["XX", "YY"],
        whitelist_countries=["US", "CA"],
        global_rate_limit=50,
        global_rate_window=30,
        endpoint_rate_limits={"/api/endpoint": (10, 60)},
        blocked_cloud_providers={"aws", "azure"},
        blocked_user_agents=["badbot", "scanner"],
        suspicious_patterns=["../", "SELECT * FROM"],
        enable_penetration_detection=True,
        enable_ip_banning=True,
        enable_rate_limiting=True,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )


@pytest.fixture
def cleanup_singleton() -> Generator[Any, Any, Any]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def test_singleton_pattern(
    config: SecurityConfig, cleanup_singleton: Generator[Any, Any, Any]
) -> None:
    DynamicRuleManager._instance = None

    instance1 = DynamicRuleManager(config)
    instance2 = DynamicRuleManager(config)

    assert instance1 is instance2
    assert DynamicRuleManager._instance is instance1


def test_singleton_preserves_state(config: SecurityConfig) -> None:
    DynamicRuleManager._instance = None

    instance1 = DynamicRuleManager(config)
    instance1.last_update = 12345.67
    test_rules = MagicMock()
    instance1.current_rules = test_rules

    instance2 = DynamicRuleManager(config)

    assert instance2.last_update == 12345.67
    assert instance2.current_rules is test_rules


def test_initialize_agent_with_dynamic_rules_enabled(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    manager.initialize_agent(mock_agent_handler)

    assert manager.agent_handler is mock_agent_handler

    assert manager.update_task is not None
    assert isinstance(manager.update_task, threading.Thread)

    manager.stop()


def test_initialize_agent_with_dynamic_rules_disabled(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    config.enable_dynamic_rules = False

    manager = DynamicRuleManager(config)

    manager.initialize_agent(mock_agent_handler)

    assert manager.agent_handler is mock_agent_handler

    assert manager.update_task is None


def test_initialize_agent_prevents_duplicate_tasks(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    manager.initialize_agent(mock_agent_handler)
    first_task = manager.update_task

    manager.initialize_agent(mock_agent_handler)
    second_task = manager.update_task

    assert first_task is second_task

    manager.stop()


def test_initialize_redis(
    config: SecurityConfig, mock_redis_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    manager.initialize_redis(mock_redis_handler)

    assert manager.redis_handler is mock_redis_handler


def test_rule_update_loop_normal_operation(
    config: SecurityConfig,
) -> None:
    DynamicRuleManager._instance = None

    config.dynamic_rule_interval = 1
    manager = DynamicRuleManager(config)

    update_count = 0

    def mock_update_rules() -> None:
        nonlocal update_count
        update_count += 1
        if update_count >= 2:
            return

    with patch.object(manager, "update_rules", mock_update_rules):
        manager.update_task = threading.Thread(
            target=manager._rule_update_loop, daemon=True
        )

        manager.update_task.start()

        time.sleep(2.5)

        manager.stop()

    assert update_count >= 2


def test_rule_update_loop_handles_exceptions(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    config.dynamic_rule_interval = 1

    manager = DynamicRuleManager(config)

    call_count = 0

    def mock_update_rules() -> None:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise Exception("Test exception")

    with patch.object(manager, "update_rules", mock_update_rules):
        with caplog.at_level(logging.ERROR):
            manager.update_task = threading.Thread(
                target=manager._rule_update_loop, daemon=True
            )

            manager.update_task.start()

            time.sleep(2.5)

            manager.stop()

    assert "Error in dynamic rule update loop: Test exception" in caplog.text
    assert call_count >= 1


def test_interruptible_sleep_returns_immediately_when_stopped(
    config: SecurityConfig,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager._stop_event.set()

    start = time.monotonic()
    manager._interruptible_sleep(30)
    elapsed = time.monotonic() - start

    assert elapsed < 1


def test_rule_update_loop_exits_when_already_stopped(
    config: SecurityConfig,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager._stop_event.set()

    manager._rule_update_loop()

    assert manager._stop_event.is_set()


def test_update_rules_disabled(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    config.enable_dynamic_rules = False
    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    manager.update_rules()

    mock_agent_handler.get_dynamic_rules.assert_not_called()


def test_update_rules_no_agent(config: SecurityConfig) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = None

    manager.update_rules()

    assert manager.current_rules is None


def test_update_rules_no_rules_returned(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    mock_agent_handler.get_dynamic_rules.return_value = None

    manager.update_rules()

    assert manager.current_rules is None
    assert manager.last_update == 0


def test_update_rules_same_version(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler
    manager.current_rules = sample_rules

    mock_agent_handler.get_dynamic_rules.return_value = sample_rules

    manager.update_rules()

    assert manager.current_rules is sample_rules
    assert manager.last_update == 0


def test_update_rules_rollback_to_an_older_version_is_applied(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    current_rules = sample_rules.model_copy()
    current_rules.version = 2
    manager.current_rules = current_rules

    mock_agent_handler.get_dynamic_rules.return_value = sample_rules

    manager.update_rules()

    assert manager.current_rules is not None
    assert manager.current_rules.version == 1
    assert manager.last_update > 0


def test_update_rules_success(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    with (
        patch.object(manager, "_apply_rules", MagicMock()) as mock_apply_rules,
        patch.object(
            manager, "_send_rule_applied_event", MagicMock()
        ) as mock_send_event,
    ):
        mock_agent_handler.get_dynamic_rules.return_value = sample_rules

        with caplog.at_level(logging.INFO):
            manager.update_rules()

        mock_apply_rules.assert_called_once_with(sample_rules)

        assert manager.current_rules == sample_rules
        assert manager.last_update > 0

        mock_send_event.assert_called_once_with(sample_rules)

    assert (
        f"Applying dynamic rules: {sample_rules.rule_id} v{sample_rules.version}"
        in caplog.text
    )


def test_update_rules_dynamic_rule_updated_event_failure(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    current_rules = sample_rules.model_copy()
    current_rules.version = 1
    manager.current_rules = current_rules

    sample_rules.version = 2

    mock_agent_handler.get_dynamic_rules.return_value = sample_rules

    mock_agent_handler.send_event.side_effect = Exception("Network error")

    with (
        patch.object(manager, "_apply_rules", MagicMock()) as mock_apply_rules,
        patch.object(
            manager, "_send_rule_applied_event", MagicMock()
        ) as mock_send_event,
    ):
        with caplog.at_level(logging.ERROR):
            manager.update_rules()

        mock_agent_handler.send_event.assert_called_once()
        sent_event = mock_agent_handler.send_event.call_args[0][0]
        assert sent_event.event_type == "dynamic_rule_updated"
        assert sent_event.action_taken == "rules_received"
        assert "Received updated rules" in sent_event.reason

        assert "Failed to send rule updated event: Network error" in caplog.text

        mock_apply_rules.assert_called_once_with(sample_rules)

        assert manager.current_rules == sample_rules
        assert manager.last_update > 0

        mock_send_event.assert_called_once_with(sample_rules)


def test_update_rules_applies_and_sends_applied_event_with_handler_name(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    rules = DynamicRules(
        rule_id="wire-test-rule",
        version=1,
        timestamp=datetime.now(timezone.utc),
    )
    mock_agent_handler.get_dynamic_rules.return_value = rules

    manager.update_rules()

    assert mock_agent_handler.send_event.call_count == 2
    received_event = mock_agent_handler.send_event.call_args_list[0].args[0]
    applied_event = mock_agent_handler.send_event.call_args_list[1].args[0]

    assert received_event.event_type == "dynamic_rule_updated"
    assert received_event.handler_name == "dynamic_rules"

    assert applied_event.event_type == "dynamic_rule_applied"
    assert applied_event.handler_name == "dynamic_rules"


def test_update_rules_emergency_mode_sends_emergency_event_with_handler_name(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    rules = DynamicRules(
        rule_id="wire-test-emergency-rule",
        version=1,
        timestamp=datetime.now(timezone.utc),
        emergency_mode=True,
        emergency_whitelist=["203.0.113.5"],
    )
    mock_agent_handler.get_dynamic_rules.return_value = rules

    manager.update_rules()

    assert mock_agent_handler.send_event.call_count == 3
    emergency_event = mock_agent_handler.send_event.call_args_list[1].args[0]

    assert emergency_event.event_type == "emergency_mode_activated"
    assert emergency_event.handler_name == "dynamic_rules"


def test_update_rules_apply_failure(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    with (
        patch.object(
            manager,
            "_apply_rules",
            MagicMock(side_effect=Exception("Apply failed")),
        ),
        patch.object(
            manager, "_send_rule_applied_event", MagicMock()
        ) as mock_send_event,
    ):
        mock_agent_handler.get_dynamic_rules.return_value = sample_rules

        with caplog.at_level(logging.ERROR):
            manager.update_rules()

        assert "Failed to update dynamic rules: Apply failed" in caplog.text

        assert manager.current_rules is None
        assert manager.last_update == 0

        mock_send_event.assert_not_called()


def test_update_rules_different_rule_id(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    current_rules = sample_rules.model_copy()
    current_rules.rule_id = "different-rule-456"
    manager.current_rules = current_rules

    with (
        patch.object(manager, "_apply_rules", MagicMock()) as mock_apply_rules,
        patch.object(manager, "_send_rule_applied_event", MagicMock()),
    ):
        mock_agent_handler.get_dynamic_rules.return_value = sample_rules

        manager.update_rules()

        mock_apply_rules.assert_called_once_with(sample_rules)
        assert manager.current_rules == sample_rules


def test_update_rules_already_expired_rule_never_applies(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    base_threshold = config.auto_ban_threshold
    sample_rules.auto_ban_threshold = 7
    sample_rules.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

    mock_agent_handler.get_dynamic_rules.return_value = sample_rules

    with caplog.at_level(logging.WARNING):
        manager.update_rules()
        manager.update_rules()

    assert config.auto_ban_threshold == base_threshold
    assert manager.current_rules is None
    assert (
        f"Dynamic rule {sample_rules.rule_id} v{sample_rules.version} already "
        "expired on receipt; ignoring" in caplog.text
    )
    assert caplog.text.count("already expired on receipt; ignoring") == 1


def test_update_rules_expiry_in_future_persists_config(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    sample_rules.auto_ban_threshold = 7
    sample_rules.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    mock_agent_handler.get_dynamic_rules.return_value = sample_rules
    manager.update_rules()

    mock_agent_handler.get_dynamic_rules.return_value = None
    manager.update_rules()

    assert config.auto_ban_threshold == 7
    assert manager.current_rules == sample_rules


def test_update_rules_no_expiry_persists_config(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    sample_rules.auto_ban_threshold = 7
    assert sample_rules.expires_at is None

    mock_agent_handler.get_dynamic_rules.return_value = sample_rules
    manager.update_rules()

    mock_agent_handler.get_dynamic_rules.return_value = None
    manager.update_rules()

    assert config.auto_ban_threshold == 7
    assert manager.current_rules == sample_rules


def test_update_rules_expiry_same_tick_ordering_new_rule_applies_after_revert(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    sample_rules.auto_ban_threshold = 8
    sample_rules.expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

    mock_agent_handler.get_dynamic_rules.return_value = sample_rules
    manager.update_rules()
    assert config.auto_ban_threshold == 8

    next_rules = sample_rules.model_copy()
    next_rules.rule_id = "next-rule"
    next_rules.version = 1
    next_rules.auto_ban_threshold = None
    next_rules.expires_at = None
    next_rules.emergency_mode = True
    next_rules.emergency_whitelist = []

    mock_agent_handler.get_dynamic_rules.return_value = next_rules

    frozen_now = sample_rules.expires_at + timedelta(seconds=1)
    with (
        patch(
            "guard_core.sync.handlers.dynamic_rule_handler.datetime",
            _frozen_datetime(frozen_now),
        ),
        patch.object(manager, "_send_emergency_event", MagicMock()),
    ):
        manager.update_rules()

    assert config.auto_ban_threshold == 2
    assert manager.current_rules == next_rules


def test_update_rules_superseding_push_then_expiry_restores_pre_a_base(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    pre_a_threshold = config.auto_ban_threshold

    rule_a = sample_rules.model_copy()
    rule_a.rule_id = "rule-a"
    rule_a.version = 1
    rule_a.auto_ban_threshold = 7

    mock_agent_handler.get_dynamic_rules.return_value = rule_a
    manager.update_rules()
    assert config.auto_ban_threshold == 7
    base_after_a = manager._active_base_snapshot

    rule_b = sample_rules.model_copy()
    rule_b.rule_id = "rule-b"
    rule_b.version = 1
    rule_b.auto_ban_threshold = 9
    rule_b.expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

    mock_agent_handler.get_dynamic_rules.return_value = rule_b
    manager.update_rules()
    assert config.auto_ban_threshold == 9
    assert manager._active_base_snapshot == base_after_a

    mock_agent_handler.get_dynamic_rules.return_value = None
    frozen_now = rule_b.expires_at + timedelta(seconds=1)
    with patch(
        "guard_core.sync.handlers.dynamic_rule_handler.datetime",
        _frozen_datetime(frozen_now),
    ):
        manager.update_rules()

    assert config.auto_ban_threshold == pre_a_threshold
    assert manager.current_rules is None
    assert manager._active_base_snapshot is None


def test_update_rules_expiry_undoes_emergency_halving(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    base_threshold = config.auto_ban_threshold
    sample_rules.emergency_mode = True
    sample_rules.emergency_whitelist = []
    sample_rules.expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

    mock_agent_handler.get_dynamic_rules.return_value = sample_rules
    with patch.object(manager, "_send_emergency_event", MagicMock()):
        manager.update_rules()

    emergency_mode_after_apply: bool = config.emergency_mode
    assert emergency_mode_after_apply is True
    assert config.auto_ban_threshold == max(1, base_threshold // 2)

    mock_agent_handler.get_dynamic_rules.return_value = None
    frozen_now = sample_rules.expires_at + timedelta(seconds=1)
    with patch(
        "guard_core.sync.handlers.dynamic_rule_handler.datetime",
        _frozen_datetime(frozen_now),
    ):
        manager.update_rules()

    emergency_mode_after_expiry: bool = config.emergency_mode
    assert emergency_mode_after_expiry is False
    assert config.auto_ban_threshold == base_threshold
    assert manager.current_rules is None


def test_update_rules_expired_active_rule_stale_agent_settles_at_base_no_flap(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    base_threshold = config.auto_ban_threshold
    expiry_moment = datetime(2030, 1, 1, tzinfo=timezone.utc)
    sample_rules.auto_ban_threshold = 8
    sample_rules.expires_at = expiry_moment

    mock_agent_handler.get_dynamic_rules.return_value = sample_rules

    before_expiry = _frozen_datetime(expiry_moment - timedelta(minutes=1))
    with patch("guard_core.sync.handlers.dynamic_rule_handler.datetime", before_expiry):
        manager.update_rules()

    applied_rules = manager.current_rules
    assert config.auto_ban_threshold == 8
    assert applied_rules == sample_rules
    events_after_apply = mock_agent_handler.send_event.call_count

    after_expiry = _frozen_datetime(expiry_moment + timedelta(minutes=1))
    with (
        patch("guard_core.sync.handlers.dynamic_rule_handler.datetime", after_expiry),
        caplog.at_level(logging.INFO),
    ):
        for _ in range(4):
            manager.update_rules()
            assert manager.current_rules is None
            assert config.auto_ban_threshold == base_threshold

    assert mock_agent_handler.send_event.call_count == events_after_apply
    assert caplog.text.count("restored base config") == 1
    assert caplog.text.count("already expired on receipt; ignoring") == 1


def test_update_rules_expiry_restores_deepcopy_independent_mutable_field(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    config.emergency_whitelist = ["base-entry"]
    original_whitelist = list(config.emergency_whitelist)

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    rule_a = sample_rules.model_copy()
    rule_a.rule_id = "rule-a"
    rule_a.version = 1
    rule_a.auto_ban_threshold = 7
    rule_a.emergency_mode = False
    rule_a.expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

    mock_agent_handler.get_dynamic_rules.return_value = rule_a
    manager.update_rules()

    assert config.auto_ban_threshold == 7
    assert config.emergency_whitelist == ["base-entry"]

    config.emergency_whitelist.append("corruption")

    mock_agent_handler.get_dynamic_rules.return_value = None
    frozen_now = rule_a.expires_at + timedelta(seconds=1)
    with patch(
        "guard_core.sync.handlers.dynamic_rule_handler.datetime",
        _frozen_datetime(frozen_now),
    ):
        manager.update_rules()

    assert config.emergency_whitelist == original_whitelist
    assert "corruption" not in config.emergency_whitelist
    assert manager.current_rules is None


def test_update_rules_expiry_exact_boundary_not_expired(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    boundary_moment = datetime(2030, 1, 1, tzinfo=timezone.utc)
    sample_rules.auto_ban_threshold = 8
    sample_rules.expires_at = boundary_moment

    mock_agent_handler.get_dynamic_rules.return_value = sample_rules

    with patch(
        "guard_core.sync.handlers.dynamic_rule_handler.datetime",
        _frozen_datetime(boundary_moment),
    ):
        manager.update_rules()

    assert config.auto_ban_threshold == 8
    assert manager.current_rules == sample_rules


def test_update_rules_stale_rule_warn_suppressed_after_valid_apply(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    stale_x = sample_rules.model_copy()
    stale_x.rule_id = "stale-x"
    stale_x.version = 1
    stale_x.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

    valid_y = sample_rules.model_copy()
    valid_y.rule_id = "valid-y"
    valid_y.version = 1
    valid_y.auto_ban_threshold = 7
    valid_y.expires_at = None

    with caplog.at_level(logging.WARNING):
        mock_agent_handler.get_dynamic_rules.return_value = stale_x
        manager.update_rules()
        rules_after_stale_x = manager.current_rules
        assert rules_after_stale_x is None

        mock_agent_handler.get_dynamic_rules.return_value = valid_y
        manager.update_rules()
        rules_after_valid_y = manager.current_rules
        assert rules_after_valid_y == valid_y
        assert config.auto_ban_threshold == 7

        mock_agent_handler.get_dynamic_rules.return_value = stale_x
        manager.update_rules()

    rules_after_second_stale_x = manager.current_rules
    assert rules_after_second_stale_x == valid_y
    assert config.auto_ban_threshold == 7
    assert caplog.text.count("already expired on receipt; ignoring") == 1


def test_update_rules_alternating_stale_rules_warn_on_each_alternation(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    stale_x = sample_rules.model_copy()
    stale_x.rule_id = "stale-x"
    stale_x.version = 1
    stale_x.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

    stale_y = sample_rules.model_copy()
    stale_y.rule_id = "stale-y"
    stale_y.version = 1
    stale_y.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

    with caplog.at_level(logging.WARNING):
        mock_agent_handler.get_dynamic_rules.return_value = stale_x
        manager.update_rules()

        mock_agent_handler.get_dynamic_rules.return_value = stale_y
        manager.update_rules()

        mock_agent_handler.get_dynamic_rules.return_value = stale_x
        manager.update_rules()

    assert manager.current_rules is None
    assert (
        caplog.text.count(
            "Dynamic rule stale-x v1 already expired on receipt; ignoring"
        )
        == 2
    )
    assert (
        caplog.text.count(
            "Dynamic rule stale-y v1 already expired on receipt; ignoring"
        )
        == 1
    )


def test_apply_rules_all_types(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    with (
        patch.object(manager, "_apply_ip_bans", MagicMock()) as mock_ip_bans,
        patch.object(manager, "_apply_ip_whitelist", MagicMock()) as mock_ip_whitelist,
        patch.object(
            manager, "_apply_pattern_rules", MagicMock()
        ) as mock_pattern_rules,
        patch.object(
            manager, "_announce_emergency_mode", MagicMock()
        ) as mock_emergency_mode,
    ):
        manager._apply_rules(sample_rules)

        mock_ip_bans.assert_called_once_with(
            sample_rules.ip_blacklist, sample_rules.ip_ban_duration
        )
        mock_ip_whitelist.assert_called_once_with(sample_rules.ip_whitelist)
        mock_pattern_rules.assert_called_once_with(sample_rules.suspicious_patterns)
        mock_emergency_mode.assert_not_called()

    assert manager.config.rate_limit == sample_rules.global_rate_limit
    assert manager.config.blocked_user_agents == sample_rules.blocked_user_agents
    assert manager.config.block_cloud_providers == frozenset({"AWS", "Azure"})


def test_apply_rules_emergency_mode(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    sample_rules.emergency_mode = True
    sample_rules.emergency_whitelist = ["192.168.1.1", "10.0.0.1"]

    with (
        patch.object(
            manager, "_announce_emergency_mode", MagicMock()
        ) as mock_emergency_mode,
        caplog.at_level(logging.WARNING),
    ):
        manager._apply_rules(sample_rules)

        mock_emergency_mode.assert_called_once_with(sample_rules.emergency_whitelist)

    assert "country rules cannot take effect" in caplog.text


def test_apply_rules_partial(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    partial_rules = DynamicRules(
        rule_id="partial-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=["172.16.0.100"],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=None,
        global_rate_window=None,
        endpoint_rate_limits={},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=None,
        enable_ip_banning=None,
        enable_rate_limiting=None,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with (
        patch.object(manager, "_apply_ip_bans", MagicMock()) as mock_ip_bans,
        patch.object(manager, "_apply_ip_whitelist", MagicMock()) as mock_ip_whitelist,
        patch.object(
            manager, "_apply_pattern_rules", MagicMock()
        ) as mock_pattern_rules,
    ):
        manager._apply_rules(partial_rules)

        mock_ip_bans.assert_called_once()
        mock_ip_whitelist.assert_not_called()
        mock_pattern_rules.assert_not_called()


def test_apply_rules_exception_handling(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    with patch.object(
        manager, "_apply_ip_bans", MagicMock(side_effect=Exception("IP ban failed"))
    ):
        with pytest.raises(Exception, match="IP ban failed"):
            manager._apply_rules(sample_rules)

    assert manager._active_base_snapshot is None


def test_apply_ip_bans_success(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
    ) as mock_ban_manager:
        mock_ban_manager.ban_ip = MagicMock()

        ip_list = ["172.16.0.100", "10.0.0.50"]
        duration = 3600

        with caplog.at_level(logging.INFO):
            manager._apply_ip_bans(ip_list, duration)

        assert mock_ban_manager.ban_ip.call_count == 2
        mock_ban_manager.ban_ip.assert_any_call("172.16.0.100", 3600, "dynamic_rule")
        mock_ban_manager.ban_ip.assert_any_call("10.0.0.50", 3600, "dynamic_rule")

        assert "Dynamic rule: Banned IP 172.16.0.100 for 3600s" in caplog.text
        assert "Dynamic rule: Banned IP 10.0.0.50 for 3600s" in caplog.text


def test_apply_ip_bans_with_failures(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
    ) as mock_ban_manager:
        mock_ban_manager.ban_ip = MagicMock(side_effect=[None, Exception("Ban failed")])

        ip_list = ["172.16.0.100", "10.0.0.50"]
        duration = 3600

        with caplog.at_level(logging.ERROR):
            manager._apply_ip_bans(ip_list, duration)

        assert mock_ban_manager.ban_ip.call_count == 2

        assert "Failed to ban IP 10.0.0.50: Ban failed" in caplog.text


def test_apply_ip_bans_does_not_log_success_when_refused(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
    ) as mock_ban_manager:
        mock_ban_manager.ban_ip = MagicMock(return_value=False)

        ip_list = ["127.0.0.1"]
        duration = 3600

        with caplog.at_level(logging.INFO):
            manager._apply_ip_bans(ip_list, duration)

        mock_ban_manager.ban_ip.assert_called_once_with(
            "127.0.0.1", 3600, "dynamic_rule"
        )
        assert "Dynamic rule: Banned IP 127.0.0.1" not in caplog.text


def test_apply_ip_whitelist_success(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
    ) as mock_ban_manager:
        mock_ban_manager.unban_ip = MagicMock()

        ip_list = ["192.168.1.200", "10.0.0.100"]

        with caplog.at_level(logging.INFO):
            manager._apply_ip_whitelist(ip_list)

        assert mock_ban_manager.unban_ip.call_count == 2
        mock_ban_manager.unban_ip.assert_any_call("192.168.1.200")
        mock_ban_manager.unban_ip.assert_any_call("10.0.0.100")

        assert "Dynamic rule: Whitelisted IP 192.168.1.200" in caplog.text
        assert "Dynamic rule: Whitelisted IP 10.0.0.100" in caplog.text


def test_apply_ip_whitelist_with_failures(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
    ) as mock_ban_manager:
        mock_ban_manager.unban_ip = MagicMock(side_effect=Exception("Unban failed"))

        ip_list = ["192.168.1.200"]

        with caplog.at_level(logging.ERROR):
            manager._apply_ip_whitelist(ip_list)

        assert "Failed to whitelist IP 192.168.1.200: Unban failed" in caplog.text


def test_apply_country_rules_blocked_only_skipped_without_geo_handler(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    blocked = ["xx", "yy"]
    allowed: list[str] = []

    with caplog.at_level(logging.WARNING):
        _apply_plan(manager, blocked_countries=blocked, whitelist_countries=allowed)

    assert manager.config.blocked_countries == frozenset()
    assert "country rules cannot take effect" in caplog.text


def test_apply_country_rules_allowed_only_skipped_without_geo_handler(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    blocked: list[str] = []
    allowed = ["us", "ca"]

    with caplog.at_level(logging.WARNING):
        _apply_plan(manager, blocked_countries=blocked, whitelist_countries=allowed)

    assert manager.config.whitelist_countries == frozenset()
    assert "country rules cannot take effect" in caplog.text


def test_apply_country_rules_both_skipped_without_geo_handler(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    blocked = ["xx", "yy"]
    allowed = ["us", "ca"]

    with caplog.at_level(logging.WARNING):
        _apply_plan(manager, blocked_countries=blocked, whitelist_countries=allowed)

    assert manager.config.blocked_countries == frozenset()
    assert manager.config.whitelist_countries == frozenset()
    assert "country rules cannot take effect" in caplog.text


def test_apply_country_rules_blocked_only_applies_with_geo_handler_configured(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    config.geo_ip_handler = MagicMock()
    manager = DynamicRuleManager(config)

    blocked = ["xx", "yy"]
    allowed: list[str] = []

    with caplog.at_level(logging.INFO):
        _apply_plan(manager, blocked_countries=blocked, whitelist_countries=allowed)

    assert manager.config.blocked_countries == frozenset({"XX", "YY"})

    assert "Dynamic rule: Blocked countries ['XX', 'YY']" in caplog.text


def test_apply_country_rules_allowed_only_applies_with_geo_handler_configured(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    config.geo_ip_handler = MagicMock()
    manager = DynamicRuleManager(config)

    blocked: list[str] = []
    allowed = ["us", "ca"]

    with caplog.at_level(logging.INFO):
        _apply_plan(manager, blocked_countries=blocked, whitelist_countries=allowed)

    assert manager.config.whitelist_countries == frozenset({"US", "CA"})

    assert "Dynamic rule: Whitelisted countries ['CA', 'US']" in caplog.text


def test_apply_rate_limit_global_only(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    rules = DynamicRules(
        rule_id="rate-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=50,
        global_rate_window=30,
        endpoint_rate_limits={},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=None,
        enable_ip_banning=None,
        enable_rate_limiting=None,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        _apply_plan(manager, rules)

    assert manager.config.rate_limit == 50
    assert manager.config.rate_limit_window == 30

    assert "Dynamic rule: Global rate limit 50 per 30s" in caplog.text


def test_apply_rate_limit_endpoint_only(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    rules = DynamicRules(
        rule_id="rate-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=None,
        global_rate_window=None,
        endpoint_rate_limits={"/api/v1": (10, 60), "/api/v2": (20, 60)},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=None,
        enable_ip_banning=None,
        enable_rate_limiting=None,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        _apply_plan(manager, rules)

    assert manager.config.endpoint_rate_limits == rules.endpoint_rate_limits

    assert (
        "Dynamic rule: Applied endpoint-specific rate limits for 2 endpoints"
        in caplog.text
    )
    assert "['/api/v1', '/api/v2']" in caplog.text


def test_apply_rate_limit_both(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    rules = DynamicRules(
        rule_id="rate-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=100,
        global_rate_window=60,
        endpoint_rate_limits={"/api/endpoint": (10, 30)},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=None,
        enable_ip_banning=None,
        enable_rate_limiting=None,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        _apply_plan(manager, rules)

    assert manager.config.rate_limit == 100
    assert manager.config.rate_limit_window == 60
    assert manager.config.endpoint_rate_limits == rules.endpoint_rate_limits


def test_apply_cloud_provider_rules(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    providers = {"AWS", "Azure", "GCP"}

    with caplog.at_level(logging.INFO):
        _apply_plan(manager, blocked_cloud_providers=providers)

    assert manager.config.block_cloud_providers == providers


def test_apply_user_agent_rules(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    user_agents = ["badbot", "scanner", "scraper"]

    with caplog.at_level(logging.INFO):
        _apply_plan(manager, blocked_user_agents=user_agents)

    assert manager.config.blocked_user_agents == user_agents

    assert (
        "Dynamic rule: Blocked user agents ['badbot', 'scanner', 'scraper']"
        in caplog.text
    )


def test_apply_user_agent_rules_rejects_catastrophic_pattern(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    user_agents = [r"(?:a+)+$", "badbot"]

    with caplog.at_level(logging.WARNING):
        _apply_plan(manager, blocked_user_agents=user_agents)

    assert manager.config.blocked_user_agents == ["badbot"]
    assert "rejected blocked_user_agents patterns" in caplog.text
    assert r"(?:a+)+$" in caplog.text


def test_apply_user_agent_rules_validates_each_pattern_exactly_once(
    config: SecurityConfig,
) -> None:
    from guard_core.sync.detection_engine.compiler import PatternCompiler

    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    calls: list[str] = []
    original = PatternCompiler.validate_pattern_safety

    def _spy(
        self: PatternCompiler,
        pattern: str,
        test_strings: list[str] | None = None,
        max_content_length: int | None = None,
    ) -> tuple[bool, str]:
        calls.append(pattern)
        return original(self, pattern, test_strings, max_content_length)

    with patch.object(PatternCompiler, "validate_pattern_safety", _spy):
        _apply_plan(manager, blocked_user_agents=["badbot", "scanner"])

    assert calls.count("badbot") == 1
    assert calls.count("scanner") == 1


def test_update_rules_expiry_restore_does_not_revalidate_patterns(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    from guard_core.sync.detection_engine.compiler import PatternCompiler

    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    sample_rules.blocked_user_agents = ["scanner-bot"]
    sample_rules.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    mock_agent_handler.get_dynamic_rules.return_value = sample_rules
    manager.update_rules()

    sample_rules.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    mock_agent_handler.get_dynamic_rules.return_value = None

    calls: list[str] = []
    original = PatternCompiler.validate_pattern_safety

    def _spy(
        self: PatternCompiler,
        pattern: str,
        test_strings: list[str] | None = None,
        max_content_length: int | None = None,
    ) -> tuple[bool, str]:
        calls.append(pattern)
        return original(self, pattern, test_strings, max_content_length)

    with patch.object(PatternCompiler, "validate_pattern_safety", _spy):
        manager.update_rules()

    assert calls == []
    assert config.blocked_user_agents != ["scanner-bot"]


def test_apply_pattern_rules(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    patterns = ["../", "SELECT * FROM", "<script>"]

    with patch(
        "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_patterns:
        mock_patterns.add_pattern = MagicMock()

        with caplog.at_level(logging.INFO):
            manager._apply_pattern_rules(patterns)

        assert mock_patterns.add_pattern.call_count == 3
        mock_patterns.add_pattern.assert_any_call("../")
        mock_patterns.add_pattern.assert_any_call("SELECT * FROM")
        mock_patterns.add_pattern.assert_any_call("<script>")

        assert (
            "Dynamic rule: Added suspicious patterns "
            "['../', 'SELECT * FROM', '<script>']" in caplog.text
        )


def test_apply_pattern_rules_logs_rejected_patterns(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    patterns = ["../", "(a+)+$"]

    with patch(
        "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_patterns:
        mock_patterns.add_pattern = MagicMock(side_effect=[True, False])

        with caplog.at_level(logging.INFO):
            manager._apply_pattern_rules(patterns)

        assert "Dynamic rule: Added suspicious patterns ['../']" in caplog.text
        assert "Dynamic rule: rejected patterns ['(a+)+$']" in caplog.text


def test_apply_pattern_rules_all_rejected_logs_no_added_line(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    patterns = ["(a+)+$"]

    with patch(
        "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_patterns:
        mock_patterns.add_pattern = MagicMock(return_value=False)

        with caplog.at_level(logging.INFO):
            manager._apply_pattern_rules(patterns)

        assert "Dynamic rule: Added suspicious patterns" not in caplog.text
        assert "Dynamic rule: rejected patterns ['(a+)+$']" in caplog.text


def test_apply_feature_toggles_all_enabled(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    rules = DynamicRules(
        rule_id="toggle-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=None,
        global_rate_window=None,
        endpoint_rate_limits={},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=True,
        enable_ip_banning=True,
        enable_rate_limiting=True,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        _apply_plan(manager, rules)

    assert manager.config.enable_penetration_detection is True
    assert manager.config.enable_ip_banning is True
    assert manager.config.enable_rate_limiting is True

    assert "Dynamic rule: Penetration detection True" in caplog.text
    assert "Dynamic rule: IP banning True" in caplog.text
    assert "Dynamic rule: Rate limiting True" in caplog.text


def test_apply_feature_toggles_all_disabled(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    rules = DynamicRules(
        rule_id="toggle-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=None,
        global_rate_window=None,
        endpoint_rate_limits={},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=False,
        enable_ip_banning=False,
        enable_rate_limiting=False,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        _apply_plan(manager, rules)

    assert manager.config.enable_penetration_detection is False
    assert manager.config.enable_ip_banning is False
    assert manager.config.enable_rate_limiting is False

    assert "Dynamic rule: Penetration detection False" in caplog.text
    assert "Dynamic rule: IP banning False" in caplog.text
    assert "Dynamic rule: Rate limiting False" in caplog.text


def test_apply_feature_toggles_none_values(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    orig_pen = config.enable_penetration_detection
    orig_ban = config.enable_ip_banning
    orig_rate = config.enable_rate_limiting

    rules = DynamicRules(
        rule_id="toggle-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=None,
        global_rate_window=None,
        endpoint_rate_limits={},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=None,
        enable_ip_banning=None,
        enable_rate_limiting=None,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        _apply_plan(manager, rules)

    assert manager.config.enable_penetration_detection == orig_pen
    assert manager.config.enable_ip_banning == orig_ban
    assert manager.config.enable_rate_limiting == orig_rate

    assert "Dynamic rule: Penetration detection" not in caplog.text
    assert "Dynamic rule: IP banning" not in caplog.text
    assert "Dynamic rule: Rate limiting" not in caplog.text


def test_apply_feature_toggles_auto_ban_overrides(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    rules = DynamicRules(
        rule_id="toggle-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=None,
        global_rate_window=None,
        endpoint_rate_limits={},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=None,
        enable_ip_banning=None,
        enable_rate_limiting=None,
        auto_ban_threshold=7,
        auto_ban_duration=1800,
        enable_rate_limit_auto_ban=True,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        _apply_plan(manager, rules)

    assert manager.config.auto_ban_threshold == 7
    assert manager.config.auto_ban_duration == 1800
    assert manager.config.enable_rate_limit_auto_ban is True

    assert "Dynamic rule: Auto-ban threshold 7" in caplog.text
    assert "Dynamic rule: Auto-ban duration 1800" in caplog.text
    assert "Dynamic rule: Rate-limit auto-ban True" in caplog.text


def test_apply_feature_toggles_auto_ban_none_values(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    orig_threshold = config.auto_ban_threshold
    orig_duration = config.auto_ban_duration
    orig_rate_auto_ban = config.enable_rate_limit_auto_ban

    rules = DynamicRules(
        rule_id="toggle-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=None,
        global_rate_window=None,
        endpoint_rate_limits={},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=None,
        enable_ip_banning=None,
        enable_rate_limiting=None,
        auto_ban_threshold=None,
        auto_ban_duration=None,
        enable_rate_limit_auto_ban=None,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        _apply_plan(manager, rules)

    assert manager.config.auto_ban_threshold == orig_threshold
    assert manager.config.auto_ban_duration == orig_duration
    assert manager.config.enable_rate_limit_auto_ban == orig_rate_auto_ban

    assert "Dynamic rule: Auto-ban threshold" not in caplog.text
    assert "Dynamic rule: Auto-ban duration" not in caplog.text
    assert "Dynamic rule: Rate-limit auto-ban" not in caplog.text


def test_apply_feature_toggles_rate_limit_auto_ban_false_override(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    config.enable_rate_limit_auto_ban = True
    manager = DynamicRuleManager(config)

    rules = DynamicRules(
        rule_id="toggle-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=[],
        blocked_countries=[],
        whitelist_countries=[],
        global_rate_limit=None,
        global_rate_window=None,
        endpoint_rate_limits={},
        blocked_cloud_providers=set(),
        blocked_user_agents=[],
        suspicious_patterns=[],
        enable_penetration_detection=None,
        enable_ip_banning=None,
        enable_rate_limiting=None,
        auto_ban_threshold=None,
        auto_ban_duration=None,
        enable_rate_limit_auto_ban=False,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )

    with caplog.at_level(logging.INFO):
        _apply_plan(manager, rules)

    assert manager.config.enable_rate_limit_auto_ban is False

    assert "Dynamic rule: Rate-limit auto-ban False" in caplog.text


def test_activate_emergency_mode_with_agent(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    with patch.object(manager, "_send_emergency_event", MagicMock()) as mock_send_event:
        config.auto_ban_threshold = 10

        whitelist = ["192.168.1.1", "10.0.0.1"]

        with caplog.at_level(logging.WARNING):
            _apply_plan(manager, emergency_mode=True, emergency_whitelist=whitelist)

        assert manager.config.emergency_mode is True
        assert manager.config.emergency_whitelist == whitelist
        assert manager.config.auto_ban_threshold == 5

        assert (
            "[EMERGENCY MODE] ACTIVATED - Enhanced security posture enabled"
            in caplog.text
        )
        assert "[EMERGENCY MODE] Reduced auto-ban threshold from 10 to 5" in caplog.text

        mock_send_event.assert_called_once_with(whitelist)


def test_activate_emergency_mode_without_agent(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = None

    config.auto_ban_threshold = 3

    whitelist = ["192.168.1.1"]

    with caplog.at_level(logging.CRITICAL):
        _apply_plan(manager, emergency_mode=True, emergency_whitelist=whitelist)

    assert manager.config.emergency_mode is True
    assert manager.config.emergency_whitelist == whitelist
    assert manager.config.auto_ban_threshold == 1


def test_activate_emergency_mode_minimum_threshold(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    config.auto_ban_threshold = 1

    whitelist: list[str] = []

    with caplog.at_level(logging.WARNING):
        _apply_plan(manager, emergency_mode=True, emergency_whitelist=whitelist)

    assert manager.config.auto_ban_threshold == 1

    assert "[EMERGENCY MODE] Reduced auto-ban threshold from 1 to 1" in caplog.text


def test_apply_rules_emergency_mode_halves_overridden_auto_ban_threshold(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    sample_rules.auto_ban_threshold = 7
    sample_rules.emergency_mode = True
    sample_rules.emergency_whitelist = []

    with patch.object(manager, "_send_emergency_event", MagicMock()):
        manager._apply_rules(sample_rules)

    assert manager.config.auto_ban_threshold == 3


def test_send_rule_applied_event_success(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    manager._send_rule_applied_event(sample_rules)

    mock_agent_handler.send_event.assert_called_once()

    sent_event = mock_agent_handler.send_event.call_args[0][0]
    assert sent_event.event_type == "dynamic_rule_applied"
    assert sent_event.ip_address == "system"
    assert sent_event.action_taken == "rules_updated"
    assert "Applied dynamic rules" in sent_event.reason
    assert sent_event.metadata["rule_id"] == sample_rules.rule_id
    assert sent_event.metadata["version"] == sample_rules.version
    assert sent_event.metadata["ip_bans"] == len(sample_rules.ip_blacklist)
    assert sent_event.metadata["country_blocks"] == len(sample_rules.blocked_countries)
    assert sent_event.metadata["emergency_mode"] == sample_rules.emergency_mode
    assert sent_event.handler_name == "dynamic_rules"


def test_send_rule_applied_event_no_agent(
    config: SecurityConfig, sample_rules: DynamicRules
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = None

    manager._send_rule_applied_event(sample_rules)


def test_send_rule_applied_event_failure(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    mock_agent_handler.send_event.side_effect = Exception("Send failed")

    with caplog.at_level(logging.ERROR):
        manager._send_rule_applied_event(sample_rules)

    assert "Failed to send rule applied event: Send failed" in caplog.text


def test_send_emergency_event_success(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    whitelist = ["192.168.1.1", "10.0.0.1"]

    manager._send_emergency_event(whitelist)

    mock_agent_handler.send_event.assert_called_once()

    sent_event = mock_agent_handler.send_event.call_args[0][0]
    assert sent_event.event_type == "emergency_mode_activated"
    assert sent_event.ip_address == "system"
    assert sent_event.action_taken == "emergency_lockdown"
    assert "[EMERGENCY MODE] activated" in sent_event.reason
    assert sent_event.metadata["whitelist_count"] == 2
    assert sent_event.metadata["whitelist"] == whitelist
    assert sent_event.handler_name == "dynamic_rules"


def test_send_emergency_event_large_whitelist(
    config: SecurityConfig, mock_agent_handler: MagicMock
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    whitelist = [f"192.168.1.{i}" for i in range(20)]

    manager._send_emergency_event(whitelist)

    sent_event = mock_agent_handler.send_event.call_args[0][0]
    assert sent_event.metadata["whitelist_count"] == 20
    assert len(sent_event.metadata["whitelist"]) == 10


def test_send_emergency_event_no_agent(config: SecurityConfig) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = None

    manager._send_emergency_event(["192.168.1.1"])


def test_send_emergency_event_failure(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    mock_agent_handler.send_event.side_effect = Exception("Send failed")

    with caplog.at_level(logging.ERROR):
        manager._send_emergency_event(["192.168.1.1"])

    assert "Failed to send emergency event: Send failed" in caplog.text


def test_get_current_rules(config: SecurityConfig, sample_rules: DynamicRules) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)

    assert manager.get_current_rules() is None

    manager.current_rules = sample_rules

    assert manager.get_current_rules() == sample_rules


def test_force_update(
    config: SecurityConfig,
    mock_agent_handler: MagicMock,
    sample_rules: DynamicRules,
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.agent_handler = mock_agent_handler

    with patch.object(manager, "update_rules", MagicMock()) as mock_update_rules:
        manager.force_update()

        mock_update_rules.assert_called_once()


def test_stop_without_task(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    DynamicRuleManager._instance = None

    manager = DynamicRuleManager(config)
    manager.update_task = None

    with caplog.at_level(logging.INFO):
        manager.stop()

    assert manager.update_task is None
    assert "Stopped dynamic rule update loop" not in caplog.text


def test_apply_ip_rules_whitelist_only() -> None:
    from datetime import datetime, timezone

    from guard_core.models import DynamicRules, SecurityConfig
    from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager

    DynamicRuleManager._instance = None
    mgr = DynamicRuleManager(SecurityConfig())
    rules = DynamicRules(
        rule_id="r1",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[],
        ip_whitelist=["10.0.0.1"],
    )
    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager.unban_ip",
        new=MagicMock(),
    ):
        mgr._apply_side_effects(rules)
    DynamicRuleManager._instance = None


def test_apply_rate_limit_rules_global_without_window() -> None:
    from datetime import datetime, timezone

    from guard_core.models import DynamicRules, SecurityConfig
    from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager

    DynamicRuleManager._instance = None
    mgr = DynamicRuleManager(SecurityConfig())
    rules = DynamicRules(
        rule_id="r1",
        version=1,
        timestamp=datetime.now(timezone.utc),
        global_rate_limit=100,
        global_rate_window=None,
    )
    plan = mgr._build_plan(rules, mgr._snapshot_config())
    mgr._swap_config(plan)
    assert mgr.config.rate_limit == 100
    DynamicRuleManager._instance = None
