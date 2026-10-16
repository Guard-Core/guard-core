import asyncio
from collections.abc import Awaitable, Iterator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import DynamicRules, SecurityConfig
from guard_core.protocols.geo_ip_protocol import GeoIPHandler


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
    }
    base.update(overrides)
    return DynamicRules(**base)


def _manager() -> tuple[DynamicRuleManager, SecurityConfig]:
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-api-key",
        enable_dynamic_rules=True,
        geo_ip_handler=MagicMock(spec=GeoIPHandler),
        rate_limit=600,
        rate_limit_window=60,
        enable_rate_limiting=False,
        blocked_countries=frozenset({"CN"}),
    )
    manager = DynamicRuleManager(config)
    manager.agent_handler = None
    return manager, config


async def _observe_while(
    config: SecurityConfig, work: Awaitable[Any]
) -> list[tuple[bool, int, bool, frozenset[str]]]:
    seen: list[tuple[bool, int, bool, frozenset[str]]] = []
    stop = asyncio.Event()

    async def sampler() -> None:
        while not stop.is_set():
            seen.append(
                (
                    config.emergency_mode,
                    config.rate_limit,
                    config.enable_rate_limiting,
                    config.blocked_countries,
                )
            )
            await asyncio.sleep(0)

    task = asyncio.create_task(sampler())
    await asyncio.sleep(0)
    await work
    await asyncio.sleep(0)
    stop.set()
    await task
    return seen


@pytest.mark.asyncio
async def test_reapplying_an_emergency_rule_never_exposes_the_base_config() -> None:
    manager, config = _manager()
    first = _rules(
        emergency_mode=True,
        emergency_whitelist=["10.9.9.9"],
        global_rate_limit=50,
        global_rate_window=60,
        enable_rate_limiting=True,
        blocked_countries=["RU"],
    )
    await manager._apply_rules(first)
    assert config.emergency_mode is True

    second = _rules(
        version=2,
        emergency_mode=True,
        emergency_whitelist=["10.9.9.9"],
        global_rate_limit=40,
        global_rate_window=60,
        enable_rate_limiting=True,
        blocked_countries=["RU"],
        suspicious_patterns=[r"wp11atomicA\d{2,5}", r"wp11atomicB[a-z]{2,6}"],
    )

    real_add = sus_patterns_handler.add_pattern

    async def slow_add(pattern: str, custom: bool = False) -> bool:
        await asyncio.sleep(0.02)
        return await real_add(pattern, custom)

    with patch.object(sus_patterns_handler, "add_pattern", slow_add):
        seen = await _observe_while(config, manager._apply_rules(second))

    assert len(seen) > 5
    assert all(emergency for emergency, _, _, _ in seen)
    assert all(rate in (50, 40) for _, rate, _, _ in seen)
    assert all(limiting for _, _, limiting, _ in seen)
    assert all("RU" in countries for _, _, _, countries in seen)
    assert config.rate_limit == 40
    await sus_patterns_handler.remove_pattern(r"wp11atomicA\d{2,5}")
    await sus_patterns_handler.remove_pattern(r"wp11atomicB[a-z]{2,6}")


@pytest.mark.asyncio
async def test_failed_apply_leaves_the_active_rule_untouched() -> None:
    manager, config = _manager()
    await manager._apply_rules(_rules(global_rate_limit=50, global_rate_window=60))
    assert config.rate_limit == 50

    with patch.object(
        sus_patterns_handler, "add_pattern", AsyncMock(side_effect=RuntimeError("boom"))
    ):
        with pytest.raises(RuntimeError, match="boom"):
            await manager._apply_rules(
                _rules(
                    version=2,
                    global_rate_limit=10,
                    global_rate_window=60,
                    suspicious_patterns=[r"wp11failQ\d+"],
                )
            )

    assert config.rate_limit == 50
    assert manager._active_base_snapshot is not None
    assert manager._active_base_snapshot["rate_limit"] == 600
