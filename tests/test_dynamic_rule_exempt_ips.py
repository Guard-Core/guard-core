from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.implementations.ip_security import _resolve_is_exempt
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.models import DynamicRules, SecurityConfig
from tests.fake_agent import mock_agent

EXEMPT_IP = "198.51.100.20"
STATIC_EXEMPT = "192.0.2.50"


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


def _manager() -> tuple[DynamicRuleManager, SecurityConfig, AsyncMock]:
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-api-key",
        enable_dynamic_rules=True,
        exempt_ips=[STATIC_EXEMPT],
    )
    ip_ban_manager.config = config
    manager = DynamicRuleManager(config)
    agent = MagicMock()
    agent.send_event = AsyncMock()
    agent.get_dynamic_rules = AsyncMock()
    manager.agent_handler = agent
    return manager, config, agent.send_event


async def _poll(manager: DynamicRuleManager, rules: DynamicRules) -> None:
    mock_agent(manager.agent_handler).get_dynamic_rules.return_value = rules
    await manager.update_rules()


@pytest.mark.asyncio
async def test_dynamic_ip_whitelist_entry_gets_exempt_ips_behaviour() -> None:
    manager, config, _ = _manager()
    assert _resolve_is_exempt(EXEMPT_IP, config, True, False) is False

    await _poll(manager, _rules(ip_whitelist=[EXEMPT_IP, "203.0.113.0/24"]))

    assert _resolve_is_exempt(EXEMPT_IP, config, True, False) is True
    assert _resolve_is_exempt("203.0.113.77", config, True, False) is True
    assert _resolve_is_exempt("203.0.114.1", config, True, False) is False
    assert _resolve_is_exempt(STATIC_EXEMPT, config, True, False) is True
    assert config.whitelist is None


@pytest.mark.asyncio
async def test_dynamic_whitelisted_ip_is_unbanned_and_never_banned() -> None:
    manager, _, _ = _manager()
    await ip_ban_manager.ban_ip(EXEMPT_IP, 3600, "threshold_exceeded")
    assert await ip_ban_manager.is_ip_banned(EXEMPT_IP)

    await _poll(manager, _rules(ip_whitelist=[EXEMPT_IP]))

    assert not await ip_ban_manager.is_ip_banned(EXEMPT_IP)
    assert await ip_ban_manager.ban_ip(EXEMPT_IP, 3600, "threshold_exceeded") is False
    assert not await ip_ban_manager.is_ip_banned(EXEMPT_IP)


@pytest.mark.asyncio
async def test_entry_in_both_lists_ends_exempt_and_is_reported() -> None:
    manager, _, send_event = _manager()
    await _poll(
        manager,
        _rules(ip_blacklist=[EXEMPT_IP, "198.51.100.30"], ip_whitelist=[EXEMPT_IP]),
    )

    assert not await ip_ban_manager.is_ip_banned(EXEMPT_IP)
    assert await ip_ban_manager.is_ip_banned("198.51.100.30")
    applied = [
        call.args[0]
        for call in send_event.call_args_list
        if call.args[0].event_type == "dynamic_rule_applied"
    ]
    assert any(
        f"ip_blacklist: {EXEMPT_IP} (overridden by ip_whitelist)"
        in event.metadata["skipped"]
        for event in applied
    )


@pytest.mark.asyncio
async def test_skipped_whitelist_entries_are_reported_in_the_applied_event() -> None:
    manager, config, send_event = _manager()
    await _poll(manager, _rules(ip_whitelist=["127.0.0.1", "::1", EXEMPT_IP]))

    applied = [
        call.args[0]
        for call in send_event.call_args_list
        if call.args[0].event_type == "dynamic_rule_applied"
    ]
    assert len(applied) == 1
    skipped = applied[0].metadata["skipped"]
    assert "ip_whitelist: 127.0.0.1 (loopback)" in skipped
    assert "ip_whitelist: ::1 (loopback)" in skipped
    assert _resolve_is_exempt(EXEMPT_IP, config, True, False) is True
    assert _resolve_is_exempt("127.0.0.1", config, True, False) is False


@pytest.mark.asyncio
async def test_revoking_the_rule_restores_static_exempt_ips_and_ban_eligibility() -> (
    None
):
    manager, config, _ = _manager()
    rules = _rules(
        ip_whitelist=[EXEMPT_IP],
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=30),
    )
    await _poll(manager, rules)
    assert isinstance(manager.current_rules, DynamicRules)
    manager.current_rules.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    await manager._check_rule_expiry()

    assert config.exempt_ips == (STATIC_EXEMPT,)
    assert await ip_ban_manager.ban_ip(EXEMPT_IP, 60, "threshold_exceeded") is True


@pytest.mark.asyncio
async def test_static_exempt_ips_stay_bannable() -> None:
    manager, _, _ = _manager()
    await _poll(manager, _rules(ip_whitelist=[EXEMPT_IP]))
    assert await ip_ban_manager.ban_ip(STATIC_EXEMPT, 60, "threshold_exceeded") is True


@pytest.mark.asyncio
async def test_whitelisting_a_cidr_unbans_every_ip_and_network_inside_it() -> None:
    manager, _, _ = _manager()
    await ip_ban_manager.ban_ip("198.51.100.7", 3600, "threshold_exceeded")
    await ip_ban_manager.ban_ip("198.51.100.128/25", 3600, "operator")
    await ip_ban_manager.ban_ip("203.0.113.9", 3600, "threshold_exceeded")

    await _poll(manager, _rules(ip_whitelist=["198.51.100.0/24"]))
    assert not await ip_ban_manager.is_ip_banned("198.51.100.7")
    assert not await ip_ban_manager.is_ip_banned("198.51.100.200")

    ip_ban_manager.set_rule_exempt_ips(())
    assert not await ip_ban_manager.is_ip_banned("198.51.100.7")
    assert not await ip_ban_manager.is_ip_banned("198.51.100.200")
    assert await ip_ban_manager.is_ip_banned("203.0.113.9")


@pytest.mark.asyncio
async def test_revoking_the_rule_does_not_bring_back_a_ban_inside_the_cidr() -> None:
    manager, _, _ = _manager()
    await ip_ban_manager.ban_ip("198.51.100.7", 3600, "threshold_exceeded")
    await _poll(manager, _rules(ip_whitelist=["198.51.100.0/24"]))
    await _poll(
        manager,
        DynamicRules(rule_id="none-p", version=0, timestamp=datetime.now(timezone.utc)),
    )
    assert manager.current_rules is None
    assert not await ip_ban_manager.is_ip_banned("198.51.100.7")
