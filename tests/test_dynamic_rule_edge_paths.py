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
    redis.write_atomically = AsyncMock()
    with patch.object(ip_ban_manager, "redis_handler", redis):
        await ip_ban_manager.unban_ip("203.0.113.0/24")
    redis.write_atomically.assert_awaited_once_with(
        sets=(),
        deletes=[
            ("banned_networks", "203.0.113.0/24"),
            ("banned_identities", "203.0.113.0/24"),
        ],
        increment=("ban_version", "counter"),
    )


@pytest.mark.asyncio
async def test_a_non_ip_value_is_never_rule_exempt() -> None:
    ip_ban_manager.set_rule_exempt_ips(["198.51.100.0/24"])
    assert await ip_ban_manager.is_ip_banned("not-an-ip") is False


def test_rule_exemption_mixin_defaults_to_no_networks_and_matches_by_family() -> None:
    from guard_core.handlers._ipban_rule_exempt import IpBanRuleExemptionMixin

    mixin = IpBanRuleExemptionMixin()
    assert mixin.rule_exempt_networks == ()
    assert mixin._is_rule_exempt_ip("198.51.100.5") is False

    mixin.set_rule_exempt_ips(["198.51.100.7/24"])
    assert mixin._is_rule_exempt_ip("198.51.100.5") is True
    assert mixin._is_rule_exempt_ip("198.51.101.5") is False
    assert mixin._is_rule_exempt_ip("2001:db8::1") is False
    assert mixin._is_rule_exempt_ip("not-an-ip") is False


@pytest.mark.asyncio
async def test_a_failing_range_unban_is_logged_and_does_not_stop_the_apply(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    with (
        patch.object(
            ip_ban_manager, "unban_inside", AsyncMock(side_effect=RuntimeError("boom"))
        ),
        caplog.at_level(logging.ERROR),
    ):
        await manager._apply_ip_whitelist(["198.51.100.0/24", "198.51.100.9"])

    assert "Failed to whitelist ranges ['198.51.100.0/24']: boom" in caplog.text


def test_a_validated_name_without_a_revalidator_is_passed_through() -> None:
    from guard_core._security_config_batch import prepare_config_batch

    config = SecurityConfig(enable_redis=False)
    prepared = prepare_config_batch(
        config,
        {"passive_mode": True, "rate_limit": 7},
        {"passive_mode", "rate_limit"},
    )
    assert prepared["passive_mode"] is True
    assert prepared["rate_limit"] == 7
