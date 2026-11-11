import asyncio
import threading
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest

from guard_core._utils.app_managers import release_app
from guard_core._utils.pending_rule_base import (
    record_pending_rule_base,
    revert_pending_rule_base,
)
from guard_core._utils.rule_attribution_shared import _APP_RULE_MANAGERS
from guard_core.core.initialization.handler_initializer import (
    HandlerInitializer,
    bind_app_managers,
)
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers import suspatterns_handler as patterns_module
from guard_core.handlers._dynamic_rule_intake import RunStopped
from guard_core.handlers._dynamic_rule_plan import DynamicRulePlan
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.models import DynamicRules, SecurityConfig
from guard_core.protocols.agent_protocol import AgentHandlerProtocol
from guard_core.protocols.redis_protocol import RedisHandlerProtocol

_IPS = ["203.0.113.131", "203.0.113.132"]
_PATTERNS = ["zzwp639firstzz", "zzwp639secondzz"]


@pytest.fixture(autouse=True)
def _defaults_unserved(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    managers = (
        ipban_module._APP_BAN_MANAGERS,
        patterns_module._APP_PATTERN_MANAGERS,
        _APP_RULE_MANAGERS,
    )
    for each in managers:
        each.forget_default()
    monkeypatch.setattr(DynamicRuleManager, "_instance", None)
    yield
    for each in managers:
        each.forget_default()
    ipban_module.ip_ban_manager.banned_ips.clear()


def _config(
    rate_limit: int = 100, cache: Path | None = None, rules: bool = False
) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_ip_banning=True,
        rate_limit=rate_limit,
        dynamic_rules_cache_path=cache,
        enable_agent=rules,
        agent_api_key="key" if rules else None,
        enable_dynamic_rules=rules,
    )


@dataclass
class _Run:
    done: asyncio.Event
    outcome: list[BaseException | None]
    task: asyncio.Task[None]


def _start(work: Callable[[], Awaitable[None]]) -> _Run:
    done = asyncio.Event()
    outcome: list[BaseException | None] = []

    async def run() -> None:
        try:
            await work()
            outcome.append(None)
        except BaseException as error:
            outcome.append(error)
        finally:
            done.set()

    task = asyncio.create_task(run())
    return _Run(done, outcome, task)


def _rules(full: bool = True) -> DynamicRules:
    return DynamicRules(
        rule_id="wp639",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=_IPS if full else [],
        suspicious_patterns=_PATTERNS if full else [],
        blocked_cloud_providers={"AWS"},
    )


class _Redis:
    def __init__(self, entered: asyncio.Event, gate: asyncio.Event) -> None:
        self.entered, self.gate = entered, gate
        self.keys: list[str] = []

    async def set_key(self, namespace: str, key: str, value: str) -> None:
        self.keys.append(key)
        self.entered.set()
        await self.gate.wait()


class _Agent:
    async def get_dynamic_rules(self) -> DynamicRules:
        return _rules()


def _park_second_pattern(
    config: SecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
    entered: asyncio.Event,
    gate: asyncio.Event,
) -> None:
    import inspect

    patterns_class = type(sus_patterns_manager_for(config))
    add_pattern = inspect.getattr_static(patterns_class, "add_pattern")._method

    async def second_pattern_waits(
        self: object, pattern: str, custom: bool = False
    ) -> bool:
        if pattern == _PATTERNS[1]:
            entered.set()
            await gate.wait()
        return bool(await add_pattern(self, pattern, custom))

    monkeypatch.setattr(patterns_class, "add_pattern", second_pattern_waits)


async def _nothing_remains_on_the_next_app(config_b: SecurityConfig) -> bool:
    bans = ip_ban_manager_for(config_b)
    banned = [await bans.is_ip_banned(ip, config=config_b) for ip in _IPS]
    held = {*_PATTERNS} & set(sus_patterns_manager_for(config_b).patterns)
    return not any(banned) and not held and not config_b.block_cloud_providers


async def test_a_release_from_another_thread_before_the_swap_rolls_the_apply_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    entered, gate = asyncio.Event(), asyncio.Event()
    _park_second_pattern(config, monkeypatch, entered, gate)

    async def apply() -> None:
        await manager._apply_rules(_rules())

    run = _start(apply)
    await entered.wait()
    releaser = threading.Thread(target=release_app, args=(config,))
    releaser.start()
    releaser.join()
    config_b = _config()
    HandlerInitializer(config_b)
    gate.set()
    await run.done.wait()
    assert type(run.outcome[0]).__name__ == "RunStopped"
    assert await _nothing_remains_on_the_next_app(config_b)
    assert not config.block_cloud_providers


async def test_force_update_across_a_release_behaves_like_the_loop_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(rules=True)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    manager.agent_handler = cast(AgentHandlerProtocol, _Agent())
    entered, gate = asyncio.Event(), asyncio.Event()
    _park_second_pattern(config, monkeypatch, entered, gate)

    async def update() -> None:
        await manager.force_update()

    run = _start(update)
    await entered.wait()
    release_app(config)
    config_b = _config()
    HandlerInitializer(config_b)
    gate.set()
    await run.done.wait()
    assert run.outcome == [None]
    assert await _nothing_remains_on_the_next_app(config_b)
    assert manager.current_rules is None


async def test_a_release_during_the_persist_await_writes_nothing_for_the_next_app(
    tmp_path: Path,
) -> None:
    config = _config()
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    entered, gate = asyncio.Event(), asyncio.Event()
    redis = _Redis(entered, gate)
    manager.redis_handler = cast(RedisHandlerProtocol, redis)

    async def apply() -> None:
        await manager._apply_rules(_rules(full=False))

    run = _start(apply)
    await entered.wait()
    release_app(config)
    config_b = _config(cache=tmp_path / "b.json")
    HandlerInitializer(config_b)
    assert DynamicRuleManager(config_b) is manager
    gate.set()
    await run.done.wait()
    assert type(run.outcome[0]).__name__ == "RunStopped"
    assert len(redis.keys) == 1
    assert list(tmp_path.iterdir()) == []


def _release_right_after_the_swap(
    monkeypatch: pytest.MonkeyPatch,
    manager: DynamicRuleManager,
    config: SecurityConfig,
    config_b: SecurityConfig,
) -> None:
    original = manager._swap_config

    def swapped_then_released(
        plan: DynamicRulePlan, target: SecurityConfig | None = None
    ) -> None:
        original(plan, target)
        release_app(config)
        HandlerInitializer(config_b)
        manager._keep_base_snapshot({"rate_limit": 22}, config_b)

    monkeypatch.setattr(manager, "_swap_config", swapped_then_released)


async def test_a_late_base_snapshot_after_a_release_does_not_take_the_next_apps_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, config_b = _config(11), _config(22)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    _release_right_after_the_swap(monkeypatch, manager, config, config_b)
    with pytest.raises(RunStopped):
        await manager._apply_rules(_rules(full=False))
    assert manager._active_base_owner is not None
    assert manager._active_base_owner() is config_b
    assert manager._active_base_snapshot == {"rate_limit": 22}


async def test_a_release_during_an_apply_reverts_that_config_at_its_next_initialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, config_b = _config(11), _config(22)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    _release_right_after_the_swap(monkeypatch, manager, config, config_b)
    with pytest.raises(RunStopped):
        await manager._apply_rules(_rules(full=False))
    assert config.block_cloud_providers
    HandlerInitializer(config)
    assert not config.block_cloud_providers
    assert config.rate_limit == 11
    assert not config_b.block_cloud_providers
    assert config_b.rate_limit == 22
    assert manager._active_base_snapshot == {"rate_limit": 22}


async def test_a_release_during_a_held_lock_keeps_the_base_for_the_next_init() -> None:
    config = _config(11)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    rules = _rules(full=False)
    await manager._apply_rules(rules)
    manager.current_rules = rules
    assert config.block_cloud_providers
    async with manager._lock:
        release_app(config)
    assert config.block_cloud_providers
    HandlerInitializer(config)
    assert not config.block_cloud_providers
    assert config.rate_limit == 11


def test_a_config_that_cannot_hold_a_record_has_no_pending_base() -> None:
    nowhere = object()
    record_pending_rule_base(nowhere, {"rate_limit": 1})
    revert_pending_rule_base(cast(SecurityConfig, nowhere))
