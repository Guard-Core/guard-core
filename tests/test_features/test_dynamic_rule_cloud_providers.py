import logging
from datetime import datetime, timezone
from typing import Any

import pytest

from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.models import DynamicRules, SecurityConfig


async def _apply(manager: DynamicRuleManager, **fields: Any) -> None:
    rules = DynamicRules(
        rule_id="plan", version=1, timestamp=datetime.now(timezone.utc), **fields
    )
    await manager._apply_rules(rules)


@pytest.fixture
def manager() -> DynamicRuleManager:
    config = SecurityConfig(enable_redis=False)
    return DynamicRuleManager(config)


@pytest.mark.asyncio
async def test_apply_cloud_provider_rules_filters_invalid_providers(
    manager: DynamicRuleManager, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    await _apply(manager, blocked_cloud_providers={"AWS", "Bogus", "GCP"})
    assert manager.config.block_cloud_providers == {"AWS", "GCP"}
    assert "ignored unknown cloud providers" in caplog.text
    assert "Bogus" in caplog.text


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
    manager: DynamicRuleManager, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    await _apply(manager, blocked_cloud_providers={"Bogus1", "Bogus2"})
    assert manager.config.block_cloud_providers is None
    assert "ignored unknown cloud providers" in caplog.text
