import logging
from datetime import datetime, timezone
from typing import Any

import pytest

from guard_core.models import DynamicRules, SecurityConfig
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


def test_apply_cloud_provider_rules_filters_invalid_providers(
    manager: DynamicRuleManager, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    _apply(manager, blocked_cloud_providers={"AWS", "Bogus", "GCP"})
    assert manager.config.block_cloud_providers == {"AWS", "GCP"}
    assert "ignored unknown cloud providers" in caplog.text
    assert "Bogus" in caplog.text


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
    manager: DynamicRuleManager, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    _apply(manager, blocked_cloud_providers={"Bogus1", "Bogus2"})
    assert manager.config.block_cloud_providers == set()
    assert "ignored unknown cloud providers" in caplog.text
