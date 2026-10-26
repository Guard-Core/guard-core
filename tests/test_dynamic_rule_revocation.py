from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.models import DynamicRules, SecurityConfig
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
        "enable_rate_limiting": True,
    }
    base.update(overrides)
    return DynamicRules(**base)


def _manager(
    tmp_path: Path | None = None,
) -> tuple[DynamicRuleManager, SecurityConfig, AsyncMock]:
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-api-key",
        enable_dynamic_rules=True,
        rate_limit=600,
        rate_limit_window=60,
        enable_rate_limiting=False,
        dynamic_rules_cache_path=(tmp_path / "rules.json") if tmp_path else None,
    )
    manager = DynamicRuleManager(config)
    agent = MagicMock()
    agent.send_event = AsyncMock()
    agent.get_dynamic_rules = AsyncMock()
    manager.agent_handler = agent
    return manager, config, agent.get_dynamic_rules


async def _poll(manager: DynamicRuleManager, answer: Any) -> None:
    mock_agent(manager.agent_handler).get_dynamic_rules.return_value = answer
    await manager.update_rules()


@pytest.mark.asyncio
@pytest.mark.parametrize("rule_id", ["disabled-p", "expired-p", "none-p"])
async def test_explicit_version_zero_no_op_reverts_to_the_base_config(
    rule_id: str,
) -> None:
    manager, config, _ = _manager()
    await _poll(manager, _rules(version=3))
    assert config.rate_limit == 50

    await _poll(
        manager,
        DynamicRules(
            rule_id=rule_id,
            version=0,
            timestamp=datetime.now(timezone.utc),
            ttl=3600,
        ),
    )

    assert config.rate_limit == 600
    assert config.enable_rate_limiting is False
    assert manager.current_rules is None
    assert manager._active_base_snapshot is None


@pytest.mark.asyncio
async def test_version_zero_with_no_active_rule_changes_nothing() -> None:
    manager, config, _ = _manager()
    await _poll(
        manager,
        DynamicRules(rule_id="none-p", version=0, timestamp=datetime.now(timezone.utc)),
    )
    assert config.rate_limit == 600
    assert manager.current_rules is None


@pytest.mark.asyncio
async def test_errors_and_empty_answers_keep_the_last_known_rule() -> None:
    manager, config, getter = _manager()
    await _poll(manager, _rules(version=3))

    await _poll(manager, None)
    assert config.rate_limit == 50

    getter.side_effect = TimeoutError("agent timed out")
    await manager.update_rules()
    assert config.rate_limit == 50
    assert manager.current_rules is not None
    assert manager.current_rules.version == 3


@pytest.mark.asyncio
async def test_rollback_with_the_same_rule_id_is_applied() -> None:
    manager, config, _ = _manager()
    await _poll(manager, _rules(version=3))
    assert config.rate_limit == 50

    await _poll(manager, _rules(version=2, global_rate_limit=500))

    assert config.rate_limit == 500
    assert manager.current_rules is not None
    assert manager.current_rules.version == 2


@pytest.mark.asyncio
async def test_same_version_with_different_content_is_applied() -> None:
    manager, config, _ = _manager()
    await _poll(manager, _rules(version=3))
    await _poll(manager, _rules(version=3, global_rate_limit=70))
    assert config.rate_limit == 70


@pytest.mark.asyncio
async def test_an_identical_poll_is_not_reapplied() -> None:
    manager, config, _ = _manager()
    await _poll(manager, _rules(version=3))
    sent = mock_agent(manager.agent_handler).send_event.await_count
    await _poll(manager, _rules(version=3, ttl=999))
    assert mock_agent(manager.agent_handler).send_event.await_count == sent


@pytest.mark.asyncio
async def test_revocation_clears_the_persisted_last_known_rules(
    tmp_path: Path,
) -> None:
    manager, config, _ = _manager(tmp_path)
    await _poll(manager, _rules(version=3))
    assert (tmp_path / "rules.json").is_file()

    await _poll(
        manager,
        DynamicRules(rule_id="none-p", version=0, timestamp=datetime.now(timezone.utc)),
    )

    assert not (tmp_path / "rules.json").exists()
    DynamicRuleManager._instance = None
    again, again_config, _ = _manager(tmp_path)
    await again._hydrate_last_known_rules()
    assert again_config.rate_limit == 600
