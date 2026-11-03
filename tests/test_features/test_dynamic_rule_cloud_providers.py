from datetime import datetime, timezone

import pytest

from guard_core.handlers._dynamic_rule_validation import MalformedDynamicRules
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.models import DynamicRules, SecurityConfig


async def _apply(manager: DynamicRuleManager, **fields: object) -> None:
    rules = DynamicRules(
        rule_id="plan", version=1, timestamp=datetime.now(timezone.utc), **fields
    )
    await manager._apply_rules(rules)


@pytest.fixture
def manager() -> DynamicRuleManager:
    config = SecurityConfig(enable_redis=False)
    return DynamicRuleManager(config)


@pytest.mark.asyncio
async def test_apply_cloud_provider_rules_rejects_a_rule_with_an_unknown_provider(
    manager: DynamicRuleManager,
) -> None:
    with pytest.raises(MalformedDynamicRules, match="Bogus"):
        await _apply(manager, blocked_cloud_providers={"AWS", "Bogus", "GCP"})
    assert manager.config.block_cloud_providers is None


@pytest.mark.asyncio
async def test_apply_cloud_provider_rules_all_valid(
    manager: DynamicRuleManager,
) -> None:
    await _apply(manager, blocked_cloud_providers={"AWS", "GCP", "Azure"})
    assert manager.config.block_cloud_providers == {"AWS", "GCP", "Azure"}


@pytest.mark.asyncio
async def test_apply_cloud_provider_rules_empty_set(
    manager: DynamicRuleManager,
) -> None:
    await _apply(manager, blocked_cloud_providers=set())
    assert manager.config.block_cloud_providers is None


@pytest.mark.asyncio
async def test_apply_cloud_provider_rules_all_invalid(
    manager: DynamicRuleManager,
) -> None:
    with pytest.raises(MalformedDynamicRules):
        await _apply(manager, blocked_cloud_providers={"Bogus1", "Bogus2"})
    assert manager.config.block_cloud_providers is None
