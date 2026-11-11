import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest

from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync._utils.app_managers import release_app
from guard_core.sync._utils.pending_rule_base import (
    record_pending_rule_base,
    revert_pending_rule_base,
)
from guard_core.sync._utils.rule_attribution_shared import _APP_RULE_MANAGERS
from guard_core.sync.core.initialization.handler_initializer import (
    HandlerInitializer,
    bind_app_managers,
)
from guard_core.sync.handlers import ipban_handler as ipban_module
from guard_core.sync.handlers import suspatterns_handler as patterns_module
from guard_core.sync.handlers._dynamic_rule_application import (
    RuleSideEffects,
    RuleTargets,
)
from guard_core.sync.handlers._dynamic_rule_intake import RunStopped
from guard_core.sync.handlers._dynamic_rule_plan import DynamicRulePlan
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.sync.protocols.agent_protocol import (
    DynamicRulesProtocol,
    SyncAgentHandlerProtocol,
)
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol

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
) -> SyncSecurityConfig:
    return SyncSecurityConfig(
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
    done: threading.Event
    outcome: list[BaseException | None]
    task: threading.Thread


def _start(work: Callable[[], None]) -> _Run:
    done = threading.Event()
    outcome: list[BaseException | None] = []

    def run() -> None:
        try:
            work()
            outcome.append(None)
        except BaseException as error:
            outcome.append(error)
        finally:
            done.set()

    task = threading.Thread(target=run, daemon=True)

    task.start()
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
    def __init__(self, entered: threading.Event, gate: threading.Event) -> None:
        self.entered, self.gate = entered, gate
        self.keys: list[str] = []

    def set_key(self, namespace: str, key: str, value: str) -> None:
        self.keys.append(key)
        self.entered.set()
        self.gate.wait()


class _Agent:
    def get_dynamic_rules(self) -> DynamicRules:
        return _rules()


def _park_second_pattern(
    config: SyncSecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
    entered: threading.Event,
    gate: threading.Event,
) -> None:
    import inspect

    patterns_class = type(sus_patterns_manager_for(config))
    add_pattern = inspect.getattr_static(patterns_class, "add_pattern")._method

    def second_pattern_waits(self: object, pattern: str, custom: bool = False) -> bool:
        if pattern == _PATTERNS[1]:
            entered.set()
            gate.wait()
        return bool(add_pattern(self, pattern, custom))

    monkeypatch.setattr(patterns_class, "add_pattern", second_pattern_waits)


def _nothing_remains_on_the_next_app(config_b: SyncSecurityConfig) -> bool:
    bans = ip_ban_manager_for(config_b)
    banned = [bans.is_ip_banned(ip, config=config_b) for ip in _IPS]
    held = {*_PATTERNS} & set(sus_patterns_manager_for(config_b).patterns)
    return not any(banned) and not held and not config_b.block_cloud_providers


def test_a_release_from_another_thread_before_the_swap_rolls_the_apply_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    entered, gate = threading.Event(), threading.Event()
    _park_second_pattern(config, monkeypatch, entered, gate)

    def apply() -> None:
        manager._apply_rules(_rules())

    run = _start(apply)
    entered.wait()
    releaser = threading.Thread(target=release_app, args=(config,))
    releaser.start()
    releaser.join()
    config_b = _config()
    HandlerInitializer(config_b)
    gate.set()
    run.done.wait()
    assert type(run.outcome[0]).__name__ == "RunStopped"
    assert _nothing_remains_on_the_next_app(config_b)
    assert not config.block_cloud_providers


def test_force_update_across_a_release_behaves_like_the_loop_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(rules=True)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    manager.agent_handler = cast(SyncAgentHandlerProtocol, _Agent())
    entered, gate = threading.Event(), threading.Event()
    _park_second_pattern(config, monkeypatch, entered, gate)

    def update() -> None:
        manager.force_update()

    run = _start(update)
    entered.wait()
    release_app(config)
    config_b = _config()
    HandlerInitializer(config_b)
    gate.set()
    run.done.wait()
    assert run.outcome == [None]
    assert _nothing_remains_on_the_next_app(config_b)
    assert manager.current_rules is None


def test_a_release_during_the_persist_await_writes_nothing_for_the_next_app(
    tmp_path: Path,
) -> None:
    config = _config()
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    entered, gate = threading.Event(), threading.Event()
    redis = _Redis(entered, gate)
    manager.redis_handler = cast(SyncRedisHandlerProtocol, redis)

    def apply() -> None:
        manager._apply_rules(_rules(full=False))

    run = _start(apply)
    entered.wait()
    release_app(config)
    config_b = _config(cache=tmp_path / "b.json")
    HandlerInitializer(config_b)
    assert DynamicRuleManager(config_b) is manager
    gate.set()
    run.done.wait()
    assert type(run.outcome[0]).__name__ == "RunStopped"
    assert len(redis.keys) == 1
    assert list(tmp_path.iterdir()) == []


def _release_right_after_the_swap(
    monkeypatch: pytest.MonkeyPatch,
    manager: DynamicRuleManager,
    config: SyncSecurityConfig,
    config_b: SyncSecurityConfig,
) -> None:
    original = manager._swap_config

    def swapped_then_released(
        plan: DynamicRulePlan, target: SyncSecurityConfig | None = None
    ) -> None:
        original(plan, target)
        release_app(config)
        HandlerInitializer(config_b)
        manager._keep_base_snapshot({"rate_limit": 22}, config_b)

    monkeypatch.setattr(manager, "_swap_config", swapped_then_released)


def test_a_late_base_snapshot_after_a_release_does_not_take_the_next_apps_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, config_b = _config(11), _config(22)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    _release_right_after_the_swap(monkeypatch, manager, config, config_b)
    with pytest.raises(RunStopped):
        manager._apply_rules(_rules(full=False))
    assert manager._active_base_owner is not None
    assert manager._active_base_owner() is config_b
    assert manager._active_base_snapshot == {"rate_limit": 22}


def test_a_release_during_an_apply_reverts_that_config_at_its_next_initialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, config_b = _config(11), _config(22)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    pre_rule_base = manager._snapshot_config()
    _release_right_after_the_swap(monkeypatch, manager, config, config_b)
    with pytest.raises(RunStopped):
        manager._apply_rules(_rules(full=False))
    assert config.block_cloud_providers
    HandlerInitializer(config)
    assert {name: getattr(config, name) for name in pre_rule_base} == pre_rule_base
    assert not config.block_cloud_providers
    assert config.rate_limit == 11
    assert not config_b.block_cloud_providers
    assert config_b.rate_limit == 22
    assert manager._active_base_snapshot == {"rate_limit": 22}


def test_a_release_during_a_held_lock_keeps_the_base_for_the_next_init() -> None:
    config = _config(11)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    rules = _rules(full=False)
    manager._apply_rules(rules)
    manager.current_rules = rules
    assert config.block_cloud_providers
    with manager._lock:
        release_app(config)
    assert config.block_cloud_providers
    HandlerInitializer(config)
    assert not config.block_cloud_providers
    assert config.rate_limit == 11


def test_a_config_that_cannot_hold_a_record_has_no_pending_base() -> None:
    nowhere = object()
    record_pending_rule_base(nowhere, {"rate_limit": 1})
    revert_pending_rule_base(cast(SyncSecurityConfig, nowhere))


class _EventsAgent:
    def __init__(self, release_during_fetch: Callable[[], None]) -> None:
        self.release_during_fetch = release_during_fetch
        self.events: list[object] = []

    def get_dynamic_rules(self) -> DynamicRules:
        gate = threading.Event()

        def release_then_open() -> None:
            self.release_during_fetch()
            gate.set()

        threading.Thread(target=release_then_open).start()
        assert gate.wait(10)
        return _rules()

    def send_event(self, event: object) -> None:
        self.events.append(event)


def _rule_cycle_with_a_release_during_the_fetch(
    config: SyncSecurityConfig, config_b: SyncSecurityConfig
) -> tuple[DynamicRuleManager, _EventsAgent]:
    bind_app_managers(config)
    manager = DynamicRuleManager(config)

    def release_and_bind_next() -> None:
        release_app(config)
        HandlerInitializer(config_b)
        assert DynamicRuleManager(config_b) is manager

    agent = _EventsAgent(release_and_bind_next)
    manager.agent_handler = cast(SyncAgentHandlerProtocol, agent)
    return manager, agent


def test_a_release_during_the_fetch_of_the_loop_run_applies_nothing() -> None:
    config, config_b = _config(rules=True), _config(rules=True)
    manager, agent = _rule_cycle_with_a_release_during_the_fetch(config, config_b)
    with pytest.raises(RunStopped):
        manager.update_rules()
    assert agent.events == []
    assert manager.current_rules is None
    assert _nothing_remains_on_the_next_app(config_b)
    assert not config.block_cloud_providers


def test_a_release_during_the_fetch_of_a_forced_update_applies_nothing() -> None:
    config, config_b = _config(rules=True), _config(rules=True)
    manager, agent = _rule_cycle_with_a_release_during_the_fetch(config, config_b)
    manager.force_update()
    assert agent.events == []
    assert manager.current_rules is None
    assert _nothing_remains_on_the_next_app(config_b)
    assert not config.block_cloud_providers


def test_a_release_from_a_second_thread_during_the_side_effects_ends_the_apply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, config_b = _config(11), _config(22)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    side_effects = manager._apply_side_effects
    reached, gate = threading.Event(), threading.Event()

    def gated(
        rules: DynamicRulesProtocol,
        effects: RuleSideEffects | None = None,
        exempt_ips: list[str] | None = None,
        targets: RuleTargets | None = None,
    ) -> None:
        reached.set()
        assert gate.wait(10)
        side_effects(rules, effects, exempt_ips, targets)

    def release_then_open() -> None:
        assert reached.wait(10)
        release_app(config)
        HandlerInitializer(config_b)
        gate.set()

    monkeypatch.setattr(manager, "_apply_side_effects", gated)
    releaser = threading.Thread(target=release_then_open)
    releaser.start()
    with pytest.raises(RunStopped):
        manager._apply_rules(_rules())
    releaser.join()
    assert _nothing_remains_on_the_next_app(config_b)
    assert config_b.rate_limit == 22
    assert not config.block_cloud_providers


def test_a_held_lock_release_leaves_no_rule_exempt_network_for_the_next_app() -> None:
    config = _config()
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    manager._apply_rules(
        DynamicRules(
            rule_id="wp642",
            version=1,
            timestamp=datetime.now(timezone.utc),
            ip_whitelist=["198.51.100.0/24"],
        )
    )
    assert ip_ban_manager_for(config).rule_exempt_networks
    with manager._lock:
        release_app(config)
    config_b = _config()
    HandlerInitializer(config_b)
    assert ip_ban_manager_for(config_b).rule_exempt_networks == ()


def _spawn_in_this_context(work: Callable[[], None]) -> threading.Thread:
    # a pool that copies the context makes the thread inherit it, as a task does
    import contextvars

    spawned = threading.Thread(
        target=contextvars.copy_context().run, args=(work,), daemon=True
    )
    spawned.start()
    return spawned


def _finished(spawned: threading.Thread) -> None:
    spawned.join()


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
        self.go = threading.Event()
        self.spawned: list[threading.Thread] = []
        self.child_work: Callable[[], None] | None = None

    def get_dynamic_rules(self) -> DynamicRules:
        return self.rules

    def send_event(self, event: object) -> None:
        if self.child_work is None or self.spawned:
            return
        work = self.child_work

        def child() -> None:
            self.go.wait()
            work()

        self.spawned.append(_spawn_in_this_context(child))


def test_a_task_made_inside_a_cycle_runs_its_own_cycle_after_a_release() -> None:
    config, config_b = _config(rules=True), _config(rules=True)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    agent = _SpawningAgent()
    manager.agent_handler = cast(SyncAgentHandlerProtocol, agent)
    agent.child_work = manager.force_update
    manager._apply_rules(agent.rules)
    assert len(agent.spawned) == 1
    release_app(config)
    HandlerInitializer(config_b)
    assert DynamicRuleManager(config_b) is manager
    manager.agent_handler = cast(SyncAgentHandlerProtocol, agent)
    agent.rules = _rules()
    agent.go.set()
    _finished(agent.spawned[0])
    assert manager.current_rules is not None


def test_a_task_made_in_one_managers_cycle_runs_its_own_on_another() -> None:
    config_a, config_b = _config(rules=True), _config(rules=True)
    bind_app_managers(config_a)
    manager_a = DynamicRuleManager(config_a)
    bind_app_managers(config_b)
    manager_b = DynamicRuleManager(config_b)
    assert manager_b is not manager_a
    agent_a, agent_b = _SpawningAgent(), _Agent()
    manager_a.agent_handler = cast(SyncAgentHandlerProtocol, agent_a)
    manager_b.agent_handler = cast(SyncAgentHandlerProtocol, agent_b)
    manager_b.mark_released()
    agent_a.child_work = manager_b.force_update
    manager_a._apply_rules(agent_a.rules)
    manager_a.mark_released()
    agent_a.go.set()
    _finished(agent_a.spawned[0])
    assert manager_b.current_rules is not None


class _ChildReleases:
    def __init__(self, manager: DynamicRuleManager, config: SyncSecurityConfig) -> None:
        self.manager, self.config = manager, config
        self.child_saw_the_release: bool | None = None

    def get_dynamic_rules(self) -> DynamicRules:
        def child() -> None:
            release_app(self.config)
            self.child_saw_the_release = self.manager._released_since_entry()

        _finished(_spawn_in_this_context(child))
        return _rules()


def test_a_child_awaited_in_a_cycle_sees_a_release_and_the_cycle_stops() -> None:
    config = _config(rules=True)
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    agent = _ChildReleases(manager, config)
    manager.agent_handler = cast(SyncAgentHandlerProtocol, agent)
    with pytest.raises(RunStopped):
        manager.update_rules()
    assert agent.child_saw_the_release is True
    assert manager.current_rules is None
