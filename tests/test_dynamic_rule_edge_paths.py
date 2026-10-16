import logging
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import DynamicRules, SecurityConfig


@pytest.fixture(autouse=True)
async def _clean_dynamic_state() -> AsyncIterator[None]:
    DynamicRuleManager._instance = None
    yield
    ip_ban_manager.set_rule_exempt_ips(())
    DynamicRuleManager._instance = None


def _rules(**overrides: Any) -> DynamicRules:
    base: dict[str, Any] = {
        "rule_id": "R",
        "version": 1,
        "timestamp": datetime.now(timezone.utc),
    }
    base.update(overrides)
    return DynamicRules(**base)


def _manager(**config_kwargs: Any) -> DynamicRuleManager:
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-api-key",
        enable_dynamic_rules=True,
        **config_kwargs,
    )
    ip_ban_manager.config = config
    return DynamicRuleManager(config)


@pytest.mark.asyncio
async def test_revoking_logs_a_failing_unban_and_a_failing_pattern_removal(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    with (
        patch.object(
            ip_ban_manager, "unban_ip", AsyncMock(side_effect=RuntimeError("redis"))
        ),
        patch.object(
            sus_patterns_handler,
            "remove_pattern",
            AsyncMock(side_effect=RuntimeError("registry")),
        ),
        caplog.at_level(logging.ERROR),
    ):
        await manager._revoke_owned(["198.51.100.9"], [r"wp11edge\d+"])

    assert "Failed to revoke IP ban 198.51.100.9" in caplog.text
    assert "Failed to revoke suspicious pattern" in caplog.text


@pytest.mark.asyncio
async def test_rejected_event_is_skipped_without_an_agent_and_logs_a_send_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    rules = _rules(global_rate_limit=-1)
    manager.agent_handler = None
    await manager._send_rule_rejected_event(rules, ["problem"])

    agent = MagicMock()
    agent.send_event = AsyncMock(side_effect=RuntimeError("network"))
    manager.agent_handler = agent
    with caplog.at_level(logging.ERROR):
        await manager._send_rule_rejected_event(rules, ["problem"])
    assert "Failed to send rule rejected event: network" in caplog.text


@pytest.mark.asyncio
async def test_clearing_the_persisted_rules_reports_redis_and_file_failures(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    manager = _manager(dynamic_rules_cache_path=tmp_path / "rules.json")
    redis = MagicMock()
    redis.delete = AsyncMock(side_effect=RuntimeError("redis down"))
    manager.redis_handler = redis
    (tmp_path / "rules.json").write_text("{}", encoding="utf-8")

    with (
        patch.object(Path, "unlink", side_effect=OSError("denied")),
        caplog.at_level(logging.ERROR),
    ):
        await manager._clear_last_known_rules()

    assert "Failed to clear last-known dynamic rules in Redis" in caplog.text
    assert "Failed to clear dynamic rules cache file" in caplog.text


@pytest.mark.asyncio
async def test_clearing_the_persisted_rules_deletes_the_redis_key() -> None:
    manager = _manager()
    redis = MagicMock()
    redis.delete = AsyncMock()
    manager.redis_handler = redis
    await manager._clear_last_known_rules()
    redis.delete.assert_awaited_once_with("dynamic_rules", "last_known")


@pytest.mark.asyncio
async def test_unbanning_a_network_removes_the_redis_record() -> None:
    redis = MagicMock()
    redis.delete = AsyncMock()
    with patch.object(ip_ban_manager, "redis_handler", redis):
        await ip_ban_manager.unban_ip("203.0.113.0/24")
    redis.delete.assert_awaited_once_with("banned_networks", "203.0.113.0/24")


@pytest.mark.asyncio
async def test_a_non_ip_value_is_never_rule_exempt() -> None:
    ip_ban_manager.set_rule_exempt_ips(["198.51.100.0/24"])
    assert await ip_ban_manager.is_ip_banned("not-an-ip") is False


@pytest.mark.asyncio
async def test_an_invalid_ban_entry_next_to_a_whitelist_does_not_break_planning() -> (
    None
):
    manager = _manager()
    skipped = await manager._apply_rules(
        _rules(ip_blacklist=["not-an-ip"], ip_whitelist=["198.51.100.20"])
    )
    assert not any(item.startswith("ip_blacklist:") for item in skipped)
