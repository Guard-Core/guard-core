import threading
import time
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler


def _rules(**kwargs: object) -> DynamicRules:
    base = {
        "rule_id": "test-rule",
        "version": 1,
        "timestamp": datetime.now(timezone.utc),
    }
    base.update(kwargs)
    return DynamicRules(**base)


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def test_apply_rules_rolls_back_on_partial_failure() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler),
        blocked_countries=frozenset({"XX"}),
    )
    manager = DynamicRuleManager(config)

    rules = _rules(blocked_countries=["NEW"])

    with patch.object(
        manager, "_apply_blocking_rules", MagicMock(side_effect=RuntimeError("kaboom"))
    ):
        with pytest.raises(RuntimeError, match="kaboom"):
            manager._apply_rules(rules)

    assert config.blocked_countries == frozenset({"XX"})


def test_apply_rules_persists_on_success() -> None:
    config = SecurityConfig(geo_ip_handler=MagicMock(spec=SyncGeoIPHandler))
    manager = DynamicRuleManager(config)

    rules = _rules(blocked_countries=["NEW"])
    manager._apply_rules(rules)

    assert config.blocked_countries == frozenset({"NEW"})


def test_concurrent_threads_serialize() -> None:
    config = SecurityConfig(geo_ip_handler=MagicMock(spec=SyncGeoIPHandler))
    manager = DynamicRuleManager(config)
    observed: list[list[str]] = []

    original = manager._apply_blocking_rules

    def slow(rules: DynamicRules) -> None:
        observed.append(list(config.blocked_countries))
        time.sleep(0.05)
        original(rules)

    with patch.object(manager, "_apply_blocking_rules", side_effect=slow):
        threads = [
            threading.Thread(
                target=manager._apply_rules,
                args=(_rules(blocked_countries=["AA"]),),
            ),
            threading.Thread(
                target=manager._apply_rules,
                args=(_rules(blocked_countries=["BB"]),),
            ),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    assert len(observed) == 2
    assert observed == [[], []]
    assert config.blocked_countries in (frozenset({"AA"}), frozenset({"BB"}))


def test_rollback_restores_all_snapshot_fields() -> None:
    config = SecurityConfig(
        rate_limit=100,
        enable_ip_banning=True,
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler),
        blocked_countries=frozenset({"OLD"}),
    )
    manager = DynamicRuleManager(config)

    rules = _rules(
        blocked_countries=["NEW"],
        global_rate_limit=999,
        enable_ip_banning=False,
    )

    with patch.object(
        manager,
        "_apply_feature_toggles",
        MagicMock(side_effect=RuntimeError("fail")),
    ):
        with pytest.raises(RuntimeError):
            manager._apply_rules(rules)

    assert config.blocked_countries == frozenset({"OLD"})
    assert config.rate_limit == 100
    assert config.enable_ip_banning is True


def test_rollback_restores_auto_ban_overrides() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler),
        auto_ban_threshold=5,
        auto_ban_duration=3600,
        enable_rate_limit_auto_ban=False,
    )
    manager = DynamicRuleManager(config)

    rules = _rules(
        auto_ban_threshold=7,
        auto_ban_duration=1800,
        enable_rate_limit_auto_ban=True,
        emergency_mode=True,
    )

    with patch.object(
        manager,
        "_activate_emergency_mode",
        MagicMock(side_effect=RuntimeError("fail")),
    ):
        with pytest.raises(RuntimeError, match="fail"):
            manager._apply_rules(rules)

    assert config.auto_ban_threshold == 5
    assert config.auto_ban_duration == 3600
    assert config.enable_rate_limit_auto_ban is False


def test_rollback_restores_untouched_block_cloud_providers_to_none() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    assert config.block_cloud_providers is None
    manager = DynamicRuleManager(config)

    rules = _rules(auto_ban_threshold=7)

    with patch.object(
        manager,
        "_apply_feature_toggles",
        MagicMock(side_effect=RuntimeError("kaboom")),
    ):
        with pytest.raises(RuntimeError, match="kaboom"):
            manager._apply_rules(rules)

    assert config.block_cloud_providers is None


def test_check_rule_expiry_restores_untouched_block_cloud_providers_to_none() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    assert config.block_cloud_providers is None
    manager = DynamicRuleManager(config)

    rule = _rules(
        auto_ban_threshold=7,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    manager._apply_rules(rule)
    manager.current_rules = rule

    manager._check_rule_expiry()

    assert config.block_cloud_providers is None


def test_apply_rules_captures_base_snapshot_on_first_activation() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)

    rules = _rules(auto_ban_threshold=7)
    manager._apply_rules(rules)

    assert manager._active_base_snapshot is not None
    assert manager._active_base_snapshot["auto_ban_threshold"] == 5
    assert config.auto_ban_threshold == 7


def test_apply_rules_retains_base_snapshot_across_superseding_push() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)

    rule_a = _rules(rule_id="rule-a", auto_ban_threshold=7)
    manager._apply_rules(rule_a)
    manager.current_rules = rule_a
    base_snapshot = manager._active_base_snapshot
    assert base_snapshot is not None
    assert base_snapshot["auto_ban_threshold"] == 5

    rule_b = _rules(rule_id="rule-b", auto_ban_threshold=9)
    manager._apply_rules(rule_b)

    assert manager._active_base_snapshot is base_snapshot
    assert manager._active_base_snapshot["auto_ban_threshold"] == 5
    assert config.auto_ban_threshold == 9


def test_check_rule_expiry_reverts_expired_rule_and_clears_state() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)

    rule = _rules(
        auto_ban_threshold=7,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    manager._apply_rules(rule)
    active_rule: DynamicRules | None = rule
    manager.current_rules = active_rule
    assert config.auto_ban_threshold == 7

    manager._check_rule_expiry()

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None
    assert manager._active_base_snapshot is None


def test_check_rule_expiry_noop_for_future_expiry() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)

    rule = _rules(
        auto_ban_threshold=7,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    manager._apply_rules(rule)
    manager.current_rules = rule

    manager._check_rule_expiry()

    assert config.auto_ban_threshold == 7
    assert manager.current_rules == rule


def test_check_rule_expiry_noop_when_no_active_rule() -> None:
    config = SecurityConfig(geo_ip_handler=MagicMock(spec=SyncGeoIPHandler))
    manager = DynamicRuleManager(config)

    manager._check_rule_expiry()

    assert manager.current_rules is None


def test_check_rule_expiry_clears_expired_rule_without_snapshot() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)
    manager.current_rules = _rules(
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
    )

    manager._check_rule_expiry()

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None


def test_apply_rules_failed_first_apply_leaves_no_stale_base_snapshot() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)

    with patch.object(
        manager,
        "_apply_feature_toggles",
        MagicMock(side_effect=RuntimeError("kaboom")),
    ):
        with pytest.raises(RuntimeError, match="kaboom"):
            manager._apply_rules(_rules(auto_ban_threshold=7))

    snapshot_after_failure = manager._active_base_snapshot
    assert manager.current_rules is None
    assert snapshot_after_failure is None

    config.auto_ban_threshold = 6

    manager._apply_rules(_rules(rule_id="rule-2", auto_ban_threshold=9))

    base_snapshot = manager._active_base_snapshot
    assert base_snapshot is not None
    assert base_snapshot["auto_ban_threshold"] == 6
    assert config.auto_ban_threshold == 9


def test_rollback_restores_fields_on_smuggled_invalid_auto_ban_threshold() -> None:
    config = SecurityConfig(
        rate_limit=100,
        enable_ip_banning=True,
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler),
        blocked_countries=frozenset({"OLD_COUNTRY"}),
        auto_ban_threshold=5,
    )
    manager = DynamicRuleManager(config)

    rules = _rules(
        blocked_countries=["NEW_COUNTRY"],
        global_rate_limit=999,
        enable_ip_banning=False,
        auto_ban_threshold=7,
    )
    rules.auto_ban_threshold = 0

    with pytest.raises(ValueError, match="auto_ban_threshold must be >= 1"):
        manager._apply_rules(rules)

    assert config.blocked_countries == frozenset({"OLD_COUNTRY"})
    assert config.rate_limit == 100
    assert config.enable_ip_banning is True
    assert config.auto_ban_threshold == 5


def _full_snapshot_base_kwargs() -> dict[str, object]:
    return {
        "blocked_countries": frozenset({"BASE_BLOCK"}),
        "whitelist_countries": frozenset({"BASE_WHITE"}),
        "rate_limit": 100,
        "rate_limit_window": 60,
        "endpoint_rate_limits": {"/base": (5, 60)},
        "block_cloud_providers": frozenset({"AWS"}),
        "blocked_user_agents": ["base-bot"],
        "enable_penetration_detection": True,
        "enable_ip_banning": True,
        "enable_rate_limiting": True,
        "emergency_mode": False,
        "emergency_whitelist": ["10.0.0.1"],
        "auto_ban_threshold": 5,
        "auto_ban_duration": 600,
        "enable_rate_limit_auto_ban": False,
    }


def _full_mutation_rule(**extra: object) -> DynamicRules:
    return _rules(
        blocked_countries=["NEW_BLOCK"],
        whitelist_countries=["NEW_WHITE"],
        global_rate_limit=999,
        global_rate_window=120,
        endpoint_rate_limits={"/new": (10, 30)},
        blocked_cloud_providers={"GCP"},
        blocked_user_agents=["new-bot"],
        enable_penetration_detection=False,
        enable_ip_banning=False,
        enable_rate_limiting=False,
        enable_rate_limit_auto_ban=True,
        auto_ban_threshold=9,
        auto_ban_duration=1200,
        emergency_mode=True,
        emergency_whitelist=["10.0.0.2"],
        **extra,
    )


def _assert_config_matches_base_snapshot(config: SecurityConfig) -> None:
    base = _full_snapshot_base_kwargs()
    for field, value in base.items():
        assert getattr(config, field) == value, field


def test_rollback_restores_every_snapshot_field_after_full_mutation() -> None:
    with pytest.warns(UserWarning, match="blocked_countries is ignored"):
        config = SecurityConfig(
            geo_ip_handler=MagicMock(spec=SyncGeoIPHandler),
            **_full_snapshot_base_kwargs(),
        )
        manager = DynamicRuleManager(config)
        manager.agent_handler = MagicMock()

        rules = _full_mutation_rule()

        with patch.object(
            manager,
            "_send_emergency_event",
            MagicMock(side_effect=RuntimeError("boom")),
        ):
            with pytest.raises(RuntimeError, match="boom"):
                manager._apply_rules(rules)

    _assert_config_matches_base_snapshot(config)


def test_check_rule_expiry_restores_every_snapshot_field() -> None:
    with pytest.warns(UserWarning, match="blocked_countries is ignored"):
        config = SecurityConfig(
            geo_ip_handler=MagicMock(spec=SyncGeoIPHandler),
            **_full_snapshot_base_kwargs(),
        )
        manager = DynamicRuleManager(config)
        manager.agent_handler = MagicMock()

        rules = _full_mutation_rule(
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )

        manager._apply_rules(rules)
        manager.current_rules = rules

        manager._check_rule_expiry()

    _assert_config_matches_base_snapshot(config)
    assert manager._active_base_snapshot is None
    assert manager.current_rules is None


def test_check_rule_expiry_naive_past_expiry_reverts_without_typeerror() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)

    naive_past = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(tzinfo=None)
    rule = _rules(auto_ban_threshold=7, expires_at=naive_past)
    manager._apply_rules(rule)
    manager.current_rules = rule
    assert config.auto_ban_threshold == 7

    manager._check_rule_expiry()

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None
