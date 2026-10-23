import logging
from collections.abc import Iterator
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core._dynamic_rules import dump_last_known_rules_snapshot
from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def _wire_rules(**overrides: Any) -> dict[str, Any]:
    wire: dict[str, Any] = {
        "rule_id": "default-proj",
        "version": 1,
        "timestamp": datetime.now(timezone.utc),
        "global_rate_limit": 100,
        "global_rate_window": 60,
        "enable_rate_limiting": True,
    }
    wire.update(overrides)
    return wire


def test_engine_model_tolerates_unknown_fields() -> None:
    rules = DynamicRules(
        **_wire_rules(brand_new_saas_field={"a": 1}, is_platform_default=True)
    )
    assert not hasattr(rules, "brand_new_saas_field")
    assert "brand_new_saas_field" not in rules.model_dump()
    assert dump_last_known_rules_snapshot(rules)


def _manager(
    **config_kwargs: Any,
) -> tuple[DynamicRuleManager, SyncSecurityConfig, Any]:
    config = SyncSecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-api-key",
        enable_dynamic_rules=True,
        rate_limit=600,
        enable_rate_limiting=False,
        **config_kwargs,
    )
    manager = DynamicRuleManager(config)
    agent = MagicMock()
    agent.send_event = MagicMock()
    manager.agent_handler = agent
    return manager, config, agent


def test_platform_default_rule_is_never_applied(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager, config, agent = _manager()
    rules: Any = SimpleNamespace(**_wire_rules(is_platform_default=True))
    agent.get_dynamic_rules = MagicMock(return_value=rules)

    with caplog.at_level(logging.INFO, logger="guard_core.sync.handlers.dynamic_rule"):
        for _ in range(3):
            manager.update_rules()

    assert config.rate_limit == 600
    assert config.enable_rate_limiting is False
    assert manager.current_rules is None
    agent.send_event.assert_not_called()
    skipped = [r for r in caplog.records if "platform default" in r.getMessage()]
    assert len(skipped) == 1


def test_platform_default_does_not_displace_an_active_rule() -> None:
    manager, config, agent = _manager()
    real = DynamicRules(
        **_wire_rules(
            rule_id="R", version=2, global_rate_limit=50, global_rate_window=60
        )
    )
    agent.get_dynamic_rules = MagicMock(return_value=real)
    manager.update_rules()
    assert config.rate_limit == 50

    agent.get_dynamic_rules = MagicMock(
        return_value=SimpleNamespace(**_wire_rules(is_platform_default=True, version=9))
    )
    manager.update_rules()

    assert config.rate_limit == 50
    assert manager.current_rules is not None
    assert manager.current_rules.rule_id == "R"


def test_agent_object_without_the_flag_is_still_applied() -> None:
    manager, config, agent = _manager()
    wire = _wire_rules(rule_id="legacy", global_rate_limit=77)
    agent.get_dynamic_rules = MagicMock(
        return_value=SimpleNamespace(
            **{
                k: v
                for k, v in DynamicRules(**wire).model_dump().items()
                if k != "is_platform_default"
            }
        )
    )
    manager.update_rules()
    assert config.rate_limit == 77
