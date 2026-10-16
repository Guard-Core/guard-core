from datetime import datetime, timezone
from typing import Any

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.handlers._dynamic_rule_validation import MalformedDynamicRules
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager


def _apply(manager: DynamicRuleManager, **fields: Any) -> None:
    rules = DynamicRules(
        rule_id="plan", version=1, timestamp=datetime.now(timezone.utc), **fields
    )
    manager._apply_rules(rules)


@pytest.fixture
def manager() -> DynamicRuleManager:
    config = SecurityConfig(enable_redis=False)
    return DynamicRuleManager(config)


def test_apply_cloud_provider_rules_rejects_a_rule_with_an_unknown_provider(
    manager: DynamicRuleManager,
) -> None:
    with pytest.raises(MalformedDynamicRules, match="Bogus"):
        _apply(manager, blocked_cloud_providers={"AWS", "Bogus", "GCP"})
    assert manager.config.block_cloud_providers is None


def test_apply_cloud_provider_rules_all_valid(
    manager: DynamicRuleManager,
) -> None:
    _apply(manager, blocked_cloud_providers={"AWS", "GCP", "Azure"})
    assert manager.config.block_cloud_providers == {"AWS", "GCP", "Azure"}


def test_apply_cloud_provider_rules_empty_set(
    manager: DynamicRuleManager,
) -> None:
    _apply(manager, blocked_cloud_providers=set())
    assert manager.config.block_cloud_providers is None


def test_apply_cloud_provider_rules_all_invalid(
    manager: DynamicRuleManager,
) -> None:
    with pytest.raises(MalformedDynamicRules):
        _apply(manager, blocked_cloud_providers={"Bogus1", "Bogus2"})
    assert manager.config.block_cloud_providers is None
