import asyncio
import gc
import threading
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

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
from guard_core.handlers._dynamic_rule_application import (
    RuleSideEffects,
    RuleTargets,
)
from guard_core.handlers._dynamic_rule_intake import RunStopped
from guard_core.handlers._dynamic_rule_plan import DynamicRulePlan
from guard_core.handlers.dynamic_rule_handler import _ENTRY_EPOCH, DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.models import DynamicRules, SecurityConfig
from guard_core.protocols.agent_protocol import (
    AgentHandlerProtocol,
    DynamicRulesProtocol,
)
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
    pre_rule_base = manager._snapshot_config()
    _release_right_after_the_swap(monkeypatch, manager, config, config_b)
    with pytest.raises(RunStopped):
        await manager._apply_rules(_rules(full=False))
    assert config.block_cloud_providers
    HandlerInitializer(config)
    assert {name: getattr(config, name) for name in pre_rule_base} == pre_rule_base
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


class _EventsAgent:
    def __init__(self, release_during_fetch: Callable[[], None]) -> None:
        self.release_during_fetch = release_during_fetch
        self.events: list[object] = []

    async def get_dynamic_rules(self) -> DynamicRules:
        gate = threading.Event()

        def release_then_open() -> None:
            self.release_during_fetch()
            gate.set()

        threading.Thread(target=release_then_open).start()
        assert gate.wait(10)
        return _rules()

    async def send_event(self, event: object) -> None:
        self.events.append(event)


def _rule_cycle_with_a_release_during_the_fetch(
    config: SecurityConfig, config_b: SecurityConfig
) -> tuple[DynamicRuleManager, _EventsAgent]:
    bind_app_managers(config)
    manager = DynamicRuleManager(config)

    def release_and_bind_next() -> None:
        release_app(config)
        HandlerInitializer(config_b)
        assert DynamicRuleManager(config_b) is manager

    agent = _EventsAgent(release_and_bind_next)
    manager.agent_handler = cast(AgentHandlerProtocol, agent)
    return manager, agent


async def test_a_release_during_the_fetch_of_the_loop_run_applies_nothing() -> None:
    config, config_b = _config(rules=True), _config(rules=True)
    manager, agent = _rule_cycle_with_a_release_during_the_fetch(config, config_b)
    with pytest.raises(RunStopped):
        await manager.update_rules()
    assert agent.events == []
    assert manager.current_rules is None
    assert await _nothing_remains_on_the_next_app(config_b)
    assert not config.block_cloud_providers


async def test_a_release_during_the_fetch_of_a_forced_update_applies_nothing() -> None:
    config, config_b = _config(rules=True), _config(rules=True)
    manager, agent = _rule_cycle_with_a_release_during_the_fetch(config, config_b)
    await manager.force_update()
    assert agent.events == []
    assert manager.current_rules is None
    assert await _nothing_remains_on_the_next_app(config_b)
    assert not config.block_cloud_providers


async def test_a_release_from_a_second_thread_during_the_side_effects_ends_the_apply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, config_b = _config(11), _config(22)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    side_effects = manager._apply_side_effects
    reached, gate = threading.Event(), threading.Event()

    async def gated(
        rules: DynamicRulesProtocol,
        effects: RuleSideEffects | None = None,
        exempt_ips: list[str] | None = None,
        targets: RuleTargets | None = None,
    ) -> None:
        reached.set()
        assert gate.wait(10)
        await side_effects(rules, effects, exempt_ips, targets)

    def release_then_open() -> None:
        assert reached.wait(10)
        release_app(config)
        HandlerInitializer(config_b)
        gate.set()

    monkeypatch.setattr(manager, "_apply_side_effects", gated)
    releaser = threading.Thread(target=release_then_open)
    releaser.start()
    with pytest.raises(RunStopped):
        await manager._apply_rules(_rules())
    releaser.join()
    assert await _nothing_remains_on_the_next_app(config_b)
    assert config_b.rate_limit == 22
    assert not config.block_cloud_providers


async def test_a_held_lock_release_leaves_no_rule_exempt_network_for_the_next_app() -> (
    None
):
    config = _config()
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    await manager._apply_rules(
        DynamicRules(
            rule_id="wp642",
            version=1,
            timestamp=datetime.now(timezone.utc),
            ip_whitelist=["198.51.100.0/24"],
        )
    )
    assert ip_ban_manager_for(config).rule_exempt_networks
    async with manager._lock:
        release_app(config)
    config_b = _config()
    HandlerInitializer(config_b)
    assert ip_ban_manager_for(config_b).rule_exempt_networks == ()


def _spawn_in_this_context(work: Callable[[], Awaitable[None]]) -> asyncio.Task[None]:
    async def run() -> None:
        await work()

    return asyncio.create_task(run())


async def _finished(spawned: asyncio.Task[None]) -> None:
    await spawned


def _owner_address() -> int:
    return id(asyncio.current_task())


async def _run_on_the_address_of_a_dead_owner(
    address: int, work: Callable[[], Awaitable[None]], bound: int
) -> bool:
    ran: list[bool] = []

    async def probe() -> None:
        if _owner_address() == address:
            ran.append(True)
            await work()

    for _ in range(bound):
        await _finished(_spawn_in_this_context(probe))
        if ran:
            return True
    return False


def _emergency_rules() -> DynamicRules:
    return DynamicRules(
        rule_id="wp644",
        version=1,
        timestamp=datetime.now(timezone.utc),
        emergency_mode=True,
        emergency_whitelist=["203.0.113.9"],
    )


class _SpawningAgent:
    """A host agent handler that makes a task while the apply announces its plan."""

    def __init__(self) -> None:
        self.rules = _emergency_rules()
        self.go = asyncio.Event()
        self.spawned: list[asyncio.Task[None]] = []
        self.child_work: Callable[[], Awaitable[None]] | None = None

    async def get_dynamic_rules(self) -> DynamicRules:
        return self.rules

    async def send_event(self, event: object) -> None:
        if self.child_work is None or self.spawned:
            return
        work = self.child_work

        async def child() -> None:
            await self.go.wait()
            await work()

        self.spawned.append(_spawn_in_this_context(child))


async def test_a_task_made_inside_a_cycle_runs_its_own_cycle_after_a_release() -> None:
    config, config_b = _config(rules=True), _config(rules=True)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    agent = _SpawningAgent()
    manager.agent_handler = cast(AgentHandlerProtocol, agent)
    agent.child_work = manager.force_update
    await manager._apply_rules(agent.rules)
    assert len(agent.spawned) == 1
    release_app(config)
    HandlerInitializer(config_b)
    assert DynamicRuleManager(config_b) is manager
    manager.agent_handler = cast(AgentHandlerProtocol, agent)
    agent.rules = _rules()
    agent.go.set()
    await _finished(agent.spawned[0])
    assert manager.current_rules is not None


async def test_a_task_made_in_one_managers_cycle_runs_its_own_on_another() -> None:
    config_a, config_b = _config(rules=True), _config(rules=True)
    bind_app_managers(config_a)
    manager_a = DynamicRuleManager(config_a)
    bind_app_managers(config_b)
    manager_b = DynamicRuleManager(config_b)
    assert manager_b is not manager_a
    agent_a, agent_b = _SpawningAgent(), _Agent()
    manager_a.agent_handler = cast(AgentHandlerProtocol, agent_a)
    manager_b.agent_handler = cast(AgentHandlerProtocol, agent_b)
    manager_b.mark_released()
    agent_a.child_work = manager_b.force_update
    await manager_a._apply_rules(agent_a.rules)
    manager_a.mark_released()
    agent_a.go.set()
    await _finished(agent_a.spawned[0])
    assert manager_b.current_rules is not None


class _ChildReleases:
    def __init__(self, manager: DynamicRuleManager, config: SecurityConfig) -> None:
        self.manager, self.config = manager, config
        self.child_saw_the_release: bool | None = None

    async def get_dynamic_rules(self) -> DynamicRules:
        async def child() -> None:
            release_app(self.config)
            self.child_saw_the_release = self.manager._released_since_entry()

        await _finished(_spawn_in_this_context(child))
        return _rules()


async def test_a_child_awaited_in_a_cycle_sees_a_release_and_the_cycle_stops() -> None:
    config = _config(rules=True)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    agent = _ChildReleases(manager, config)
    manager.agent_handler = cast(AgentHandlerProtocol, agent)
    with pytest.raises(RunStopped):
        await manager.update_rules()
    assert agent.child_saw_the_release is True
    assert manager.current_rules is None


class _AddressReuseAgent:
    """A host agent handler whose announce step makes a long-lived host task H."""

    def __init__(self, manager: DynamicRuleManager, config_b: SecurityConfig) -> None:
        self.manager, self.config_b = manager, config_b
        self.rules = _emergency_rules()
        self.go = asyncio.Event()
        self.cycle_address = 0
        self.host: list[asyncio.Task[None]] = []
        self.reused: bool | None = None

    async def get_dynamic_rules(self) -> DynamicRules:
        return self.rules

    async def send_event(self, event: object) -> None:
        if self.host:
            return
        self.cycle_address = _owner_address()
        self.host.append(_spawn_in_this_context(self._host))

    async def _host(self) -> None:
        await self.go.wait()
        self.reused = await _run_on_the_address_of_a_dead_owner(
            self.cycle_address, self._release_rebind_and_force, 1000
        )

    async def _release_rebind_and_force(self) -> None:
        release_app(self.manager.config)
        HandlerInitializer(self.config_b)
        assert DynamicRuleManager(self.config_b) is self.manager
        self.manager.agent_handler = cast(AgentHandlerProtocol, _Agent())
        await self.manager.force_update()


async def _one_attempt_at_a_task_on_the_address_of_the_dead_cycle_task() -> tuple[
    _AddressReuseAgent, DynamicRuleManager
]:
    config, config_b = _config(rules=True), _config(rules=True)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    agent = _AddressReuseAgent(manager, config_b)
    manager.agent_handler = cast(AgentHandlerProtocol, agent)

    async def the_cycle() -> None:
        await manager._apply_rules(agent.rules)

    await _finished(_spawn_in_this_context(the_cycle))
    await asyncio.sleep(0)
    gc.collect()
    agent.go.set()
    await _finished(agent.host[0])
    if not agent.reused:
        release_app(config)
    return agent, manager


async def test_a_task_on_the_address_of_the_dead_cycle_task_runs_its_own_cycle() -> (
    None
):
    # another object can take the freed address first, so a miss is retried afresh
    for _ in range(25):
        (
            agent,
            manager,
        ) = await _one_attempt_at_a_task_on_the_address_of_the_dead_cycle_task()
        if agent.reused:
            break
    assert agent.reused is True, (
        "CPython never reused the dead task's address in 25 attempts; "
        "allocator-dependent pin"
    )
    assert manager.current_rules is not None


async def test_a_dead_owner_leaves_the_entry_and_a_new_owner_takes_the_epoch() -> None:
    config = _config()
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    entries: list[Any] = []

    async def the_cycle() -> None:
        with manager._entry_epoch_scope():
            entries.append(_ENTRY_EPOCH.get())

    await _finished(_spawn_in_this_context(the_cycle))
    await asyncio.sleep(0)
    gc.collect()
    entry = entries[0]
    assert entry[1]() is None
    manager.mark_released()
    assert entry[2] != manager._release_epoch
    taken: list[int] = []

    async def a_new_owner() -> None:
        _ENTRY_EPOCH.set(entry)
        with manager._entry_epoch_scope():
            current = _ENTRY_EPOCH.get()
            assert current is not None
            taken.append(current[2])

    await _finished(_spawn_in_this_context(a_new_owner))
    assert taken == [manager._release_epoch]
