from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler


def _rules(version: int = 1, rule_id: str = "r1", **kwargs: object) -> DynamicRules:
    base = {
        "rule_id": rule_id,
        "version": version,
        "timestamp": datetime.now(timezone.utc),
    }
    base.update(kwargs)
    return DynamicRules(**base)


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def _apply(manager: DynamicRuleManager, rules: DynamicRules) -> None:
    manager._apply_rules(rules)
    manager.current_rules = rules


def test_emergency_halving_does_not_compound_across_versions() -> None:
    config = SecurityConfig(auto_ban_threshold=16)
    manager = DynamicRuleManager(config)

    seen = []
    for version in (1, 2, 3):
        _apply(manager, _rules(version, emergency_mode=True, emergency_whitelist=[]))
        seen.append(config.auto_ban_threshold)

    assert seen == [8, 8, 8]
    assert manager._active_base_snapshot is not None
    assert manager._active_base_snapshot["auto_ban_threshold"] == 16


def test_collection_values_do_not_accumulate_across_versions() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler),
        blocked_user_agents=["base-bot"],
        block_cloud_providers=frozenset({"AWS"}),
    )
    manager = DynamicRuleManager(config)

    _apply(
        manager,
        _rules(
            1,
            blocked_user_agents=["bot-a"],
            blocked_cloud_providers={"GCP"},
            blocked_countries=["AA"],
            endpoint_rate_limits={"/a": (1, 60)},
        ),
    )
    _apply(
        manager,
        _rules(
            2,
            blocked_user_agents=["bot-b"],
            blocked_cloud_providers={"Azure"},
            blocked_countries=["BB"],
            endpoint_rate_limits={"/b": (2, 60)},
        ),
    )

    assert config.blocked_user_agents == ["bot-b"]
    assert config.block_cloud_providers == frozenset({"Azure"})
    assert config.blocked_countries == frozenset({"BB"})
    assert config.endpoint_rate_limits == {"/b": (2, 60)}


def test_new_version_drops_change_from_previous_version() -> None:
    config = SecurityConfig(
        rate_limit=100, enable_ip_banning=True, auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)

    _apply(
        manager,
        _rules(1, global_rate_limit=7, enable_ip_banning=False, auto_ban_threshold=2),
    )
    assert (config.rate_limit, config.enable_ip_banning) == (7, False)

    _apply(manager, _rules(2, global_rate_limit=9))

    assert config.rate_limit == 9
    assert config.enable_ip_banning is True
    assert config.auto_ban_threshold == 5


def test_different_rule_id_overlays_the_base() -> None:
    config = SecurityConfig(rate_limit=100, auto_ban_threshold=16)
    manager = DynamicRuleManager(config)

    _apply(manager, _rules(1, "r1", emergency_mode=True, emergency_whitelist=[]))
    _apply(manager, _rules(1, "r2", global_rate_limit=3))

    assert config.rate_limit == 3
    assert config.auto_ban_threshold == 16
    assert config.emergency_mode is False


def test_failed_apply_rolls_back_to_the_active_version() -> None:
    config = SecurityConfig(rate_limit=100, auto_ban_threshold=16)
    manager = DynamicRuleManager(config)
    _apply(manager, _rules(1, global_rate_limit=7, auto_ban_threshold=4))

    with patch.object(
        manager, "_apply_feature_toggles", MagicMock(side_effect=RuntimeError("boom"))
    ):
        with pytest.raises(RuntimeError, match="boom"):
            manager._apply_rules(_rules(2, global_rate_limit=9))

    assert config.rate_limit == 7
    assert config.auto_ban_threshold == 4
    assert manager._active_base_snapshot is not None
    assert manager._active_base_snapshot["rate_limit"] == 100


def test_expiry_restores_the_true_base_after_several_versions() -> None:
    config = SecurityConfig(auto_ban_threshold=16)
    manager = DynamicRuleManager(config)
    _apply(manager, _rules(1, emergency_mode=True, emergency_whitelist=[]))
    _apply(
        manager,
        _rules(
            2,
            emergency_mode=True,
            emergency_whitelist=[],
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        ),
    )
    assert config.auto_ban_threshold == 8

    manager._check_rule_expiry()

    assert config.auto_ban_threshold == 16
    assert config.emergency_mode is False
    assert manager.current_rules is None
    assert manager._active_base_snapshot is None


def test_new_version_after_hydration_overlays_the_base() -> None:
    config = SecurityConfig(
        enable_dynamic_rules=True,
        enable_agent=True,
        agent_api_key="key",
        auto_ban_threshold=16,
    )
    manager = DynamicRuleManager(config)
    hydrated = _rules(1, emergency_mode=True, emergency_whitelist=[])
    agent = MagicMock()
    agent.get_dynamic_rules.return_value = _rules(
        2, emergency_mode=True, emergency_whitelist=[]
    )
    with patch.object(
        manager, "_load_last_known_rules", MagicMock(return_value=hydrated)
    ):
        with patch.object(DynamicRuleManager, "_rule_update_loop"):
            manager.initialize_agent(agent)
    assert config.auto_ban_threshold == 8

    manager.update_rules()

    assert manager.current_rules is not None
    assert manager.current_rules.version == 2
    assert config.auto_ban_threshold == 8
    manager.stop()


def test_suspicious_patterns_are_not_duplicated_across_versions() -> None:
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    config = SecurityConfig()
    manager = DynamicRuleManager(config)
    pattern = "overlay-unique-marker-[0-9]{3}"
    sus_patterns_handler.patterns[:] = [
        p for p in sus_patterns_handler.patterns if p != pattern
    ]
    try:
        for version in (1, 2, 3):
            _apply(manager, _rules(version, suspicious_patterns=[pattern]))

        assert sus_patterns_handler.patterns.count(pattern) == 1
    finally:
        sus_patterns_handler.remove_pattern(pattern)
