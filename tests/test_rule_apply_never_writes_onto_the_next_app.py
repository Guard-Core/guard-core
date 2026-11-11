import asyncio
import inspect
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from guard_core._utils.app_managers import release_app
from guard_core._utils.rule_attribution_shared import _APP_RULE_MANAGERS
from guard_core.core.initialization.handler_initializer import (
    HandlerInitializer,
    bind_app_managers,
)
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers import suspatterns_handler as patterns_module
from guard_core.handlers.dynamic_rule_handler import _RUN_STOP, DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.models import DynamicRules, SecurityConfig

_IPS = ["203.0.113.121", "203.0.113.122"]


_PATTERNS = ["zzwp638firstzz", "zzwp638secondzz"]


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
    default = patterns_module.SusPatternsManager._instance
    if default is not None:
        # An apply on an app no one bound writes before the first bind records the
        # startup rows, so the record would restore its patterns for every later test.
        default.__dict__.pop("_rows_before_the_first_app", None)
        default.patterns[:] = [p for p in default.patterns if p not in _PATTERNS]
    for each in managers:
        each.forget_default()
    ipban_module.ip_ban_manager.banned_ips.clear()


def _config(rate_limit: int = 100) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False, enable_ip_banning=True, rate_limit=rate_limit
    )


def _rules(
    providers: set[str] | None = None,
    version: int = 1,
    full: bool = True,
    patterns: list[str] | None = None,
) -> DynamicRules:
    return DynamicRules(
        rule_id="wp638",
        version=version,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=_IPS if full else [],
        suspicious_patterns=(patterns or []) if full else [],
        blocked_cloud_providers=providers or {"AWS"},
    )


@dataclass
class _Flight:
    config: SecurityConfig
    rules: DynamicRuleManager
    gate: asyncio.Event
    entered: asyncio.Event
    done: asyncio.Event
    outcome: list[BaseException | None]
    task: asyncio.Task[None]


def _start_the_apply(
    config: SecurityConfig,
    rules: DynamicRules,
    monkeypatch: pytest.MonkeyPatch,
    park_in: str,
    patterns: list[str],
) -> _Flight:
    manager = DynamicRuleManager(config)
    gate, entered, done = asyncio.Event(), asyncio.Event(), asyncio.Event()
    outcome: list[BaseException | None] = []
    if park_in == "side_effect":
        patterns_class = type(sus_patterns_manager_for(config))
        add_pattern = inspect.getattr_static(patterns_class, "add_pattern")._method

        async def second_pattern_waits(
            self: object, pattern: str, custom: bool = False
        ) -> bool:
            if pattern == patterns[1]:
                entered.set()
                await gate.wait()
            return bool(await add_pattern(self, pattern, custom))

        monkeypatch.setattr(patterns_class, "add_pattern", second_pattern_waits)
    else:

        async def persist_waits(_rules: object) -> None:
            entered.set()
            await gate.wait()

        monkeypatch.setattr(manager, "_persist_last_known_rules", persist_waits)

    async def run() -> None:
        _RUN_STOP.set(manager._stop_event)
        try:
            await manager._apply_rules(rules)
            outcome.append(None)
        except BaseException as error:
            outcome.append(error)
        finally:
            done.set()

    async def loop_stand_in() -> None:
        await asyncio.sleep(1)

    manager.update_task = asyncio.create_task(loop_stand_in())
    task = asyncio.create_task(run())
    return _Flight(config, manager, gate, entered, done, outcome, task)


async def _parked_then_released(
    monkeypatch: pytest.MonkeyPatch,
    park_in: str,
    config: SecurityConfig,
    patterns: list[str],
) -> _Flight:
    flight = _start_the_apply(
        config, _rules(patterns=patterns), monkeypatch, park_in, patterns
    )
    await flight.entered.wait()
    release_app(config)
    return flight


async def test_an_apply_released_mid_flight_writes_nothing_onto_the_next_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flight = await _parked_then_released(
        monkeypatch, "side_effect", _config(), _PATTERNS
    )
    config_b = _config()
    assert DynamicRuleManager(config_b) is flight.rules
    HandlerInitializer(config_b)
    flight.gate.set()
    await flight.done.wait()
    assert type(flight.outcome[0]).__name__ == "RunStopped"
    assert not config_b.block_cloud_providers
    assert not {*_PATTERNS} & set(sus_patterns_manager_for(config_b).patterns)
    bans = ip_ban_manager_for(config_b)
    assert not any([await bans.is_ip_banned(ip, config=config_b) for ip in _IPS])


async def test_no_pattern_of_a_released_apply_remains_on_its_manager_or_the_next(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    patterns = _PATTERNS
    bind_app_managers(config)
    manager_a = sus_patterns_manager_for(config)
    flight = await _parked_then_released(monkeypatch, "side_effect", config, patterns)
    config_b = _config()
    HandlerInitializer(config_b)
    flight.gate.set()
    await flight.done.wait()
    assert not {*patterns} & set(manager_a.patterns)
    assert not {*patterns} & set(sus_patterns_manager_for(config_b).patterns)


async def test_a_stopped_apply_undoes_the_writes_it_made_before_the_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flight = await _parked_then_released(
        monkeypatch, "side_effect", _config(), _PATTERNS
    )
    config_b = _config()
    assert DynamicRuleManager(config_b) is flight.rules
    HandlerInitializer(config_b)
    bans = ip_ban_manager_for(config_b)
    assert all([await bans.is_ip_banned(ip, config=config_b) for ip in _IPS])
    assert _PATTERNS[0] in sus_patterns_manager_for(config_b).patterns
    flight.gate.set()
    await flight.done.wait()
    assert _PATTERNS[0] not in sus_patterns_manager_for(config_b).patterns
    assert not any([await bans.is_ip_banned(ip, config=config_b) for ip in _IPS])


async def test_a_cancel_in_the_side_effects_undoes_them(  # async-only
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    flight = _start_the_apply(
        config,
        _rules(patterns=_PATTERNS),
        monkeypatch,
        "side_effect",
        _PATTERNS,
    )
    await flight.entered.wait()
    flight.task.cancel()
    await flight.done.wait()
    assert isinstance(flight.outcome[0], asyncio.CancelledError)
    assert not config.block_cloud_providers
    assert _PATTERNS[0] not in sus_patterns_manager_for(config).patterns
    assert not await ip_ban_manager_for(config).is_ip_banned(_IPS[0], config=config)
    assert not ip_ban_manager_for(config).rule_exempt_networks


async def test_a_default_reused_after_a_release_past_the_swap_takes_its_own_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flight = await _parked_then_released(monkeypatch, "after_swap", _config(11), [])
    config_b = _config(22)
    rules_b = DynamicRuleManager(config_b)
    assert rules_b is flight.rules
    flight.gate.set()
    await flight.done.wait()
    await rules_b._apply_rules(_rules({"AZURE"}, version=2, full=False))
    assert config_b.rate_limit == 22
    assert config_b.block_cloud_providers == frozenset({"Azure"})


async def test_the_same_app_reinitialized_after_a_release_applies_over_its_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    await DynamicRuleManager(config)._apply_rules(_rules({"AWS"}, full=False))
    flight = await _parked_then_released(monkeypatch, "after_swap", config, [])
    assert DynamicRuleManager(config) is flight.rules
    flight.gate.set()
    await flight.done.wait()
    await flight.rules._apply_rules(_rules({"AZURE"}, version=3, full=False))
    assert config.block_cloud_providers == frozenset({"Azure"})


async def test_a_default_reused_on_a_second_loop_keeps_lock() -> None:  # async-only
    import threading

    manager = DynamicRuleManager(_config())
    errors: list[BaseException] = []

    async def contend() -> None:
        async with manager._lock:
            waiter = asyncio.create_task(waits_for_the_lock())
            await asyncio.sleep(0.05)
        await waiter

    async def waits_for_the_lock() -> None:
        async with manager._lock:
            return

    def on_a_new_loop() -> None:
        try:
            asyncio.run(contend())
        except BaseException as error:
            errors.append(error)

    for _ in range(2):
        thread = threading.Thread(target=on_a_new_loop)
        thread.start()
        thread.join()
    assert errors == []
