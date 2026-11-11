import inspect
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync._utils.app_managers import release_app
from guard_core.sync._utils.rule_attribution_shared import _APP_RULE_MANAGERS
from guard_core.sync.core.initialization.handler_initializer import (
    HandlerInitializer,
    bind_app_managers,
)
from guard_core.sync.handlers import ipban_handler as ipban_module
from guard_core.sync.handlers import suspatterns_handler as patterns_module
from guard_core.sync.handlers.dynamic_rule_handler import _RUN_STOP, DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_manager_for

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


def _config(rate_limit: int = 100) -> SyncSecurityConfig:
    return SyncSecurityConfig(
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
    config: SyncSecurityConfig
    rules: DynamicRuleManager
    gate: threading.Event
    entered: threading.Event
    done: threading.Event
    outcome: list[BaseException | None]
    task: threading.Thread


def _start_the_apply(
    config: SyncSecurityConfig,
    rules: DynamicRules,
    monkeypatch: pytest.MonkeyPatch,
    park_in: str,
    patterns: list[str],
) -> _Flight:
    manager = DynamicRuleManager(config)
    gate, entered, done = threading.Event(), threading.Event(), threading.Event()
    outcome: list[BaseException | None] = []
    if park_in == "side_effect":
        patterns_class = type(sus_patterns_manager_for(config))
        add_pattern = inspect.getattr_static(patterns_class, "add_pattern")._method

        def second_pattern_waits(
            self: object, pattern: str, custom: bool = False
        ) -> bool:
            if pattern == patterns[1]:
                entered.set()
                gate.wait()
            return bool(add_pattern(self, pattern, custom))

        monkeypatch.setattr(patterns_class, "add_pattern", second_pattern_waits)
    else:

        def persist_waits(_rules: object) -> None:
            entered.set()
            gate.wait()

        monkeypatch.setattr(manager, "_persist_last_known_rules", persist_waits)

    def run() -> None:
        _RUN_STOP.set(manager._stop_event)
        try:
            manager._apply_rules(rules)
            outcome.append(None)
        except BaseException as error:
            outcome.append(error)
        finally:
            done.set()

    def loop_stand_in() -> None:
        time.sleep(1)

    manager.update_task = threading.Thread(target=loop_stand_in, daemon=True)

    manager.update_task.start()
    task = threading.Thread(target=run, daemon=True)

    task.start()
    return _Flight(config, manager, gate, entered, done, outcome, task)


def _parked_then_released(
    monkeypatch: pytest.MonkeyPatch,
    park_in: str,
    config: SyncSecurityConfig,
    patterns: list[str],
) -> _Flight:
    flight = _start_the_apply(
        config, _rules(patterns=patterns), monkeypatch, park_in, patterns
    )
    flight.entered.wait()
    release_app(config)
    return flight


def test_an_apply_released_mid_flight_writes_nothing_onto_the_next_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flight = _parked_then_released(monkeypatch, "side_effect", _config(), _PATTERNS)
    config_b = _config()
    assert DynamicRuleManager(config_b) is flight.rules
    HandlerInitializer(config_b)
    flight.gate.set()
    flight.done.wait()
    assert type(flight.outcome[0]).__name__ == "RunStopped"
    assert not config_b.block_cloud_providers
    assert not {*_PATTERNS} & set(sus_patterns_manager_for(config_b).patterns)
    bans = ip_ban_manager_for(config_b)
    assert not any([bans.is_ip_banned(ip, config=config_b) for ip in _IPS])


def test_no_pattern_of_a_released_apply_remains_on_its_manager_or_the_next(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    patterns = _PATTERNS
    bind_app_managers(config)
    manager_a = sus_patterns_manager_for(config)
    flight = _parked_then_released(monkeypatch, "side_effect", config, patterns)
    config_b = _config()
    HandlerInitializer(config_b)
    flight.gate.set()
    flight.done.wait()
    assert not {*patterns} & set(manager_a.patterns)
    assert not {*patterns} & set(sus_patterns_manager_for(config_b).patterns)


def test_a_stopped_apply_undoes_the_writes_it_made_before_the_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flight = _parked_then_released(monkeypatch, "side_effect", _config(), _PATTERNS)
    config_b = _config()
    assert DynamicRuleManager(config_b) is flight.rules
    HandlerInitializer(config_b)
    bans = ip_ban_manager_for(config_b)
    assert all([bans.is_ip_banned(ip, config=config_b) for ip in _IPS])
    assert _PATTERNS[0] in sus_patterns_manager_for(config_b).patterns
    flight.gate.set()
    flight.done.wait()
    assert _PATTERNS[0] not in sus_patterns_manager_for(config_b).patterns
    assert not any([bans.is_ip_banned(ip, config=config_b) for ip in _IPS])


def test_a_default_reused_after_a_release_past_the_swap_takes_its_own_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flight = _parked_then_released(monkeypatch, "after_swap", _config(11), [])
    config_b = _config(22)
    rules_b = DynamicRuleManager(config_b)
    assert rules_b is flight.rules
    flight.gate.set()
    flight.done.wait()
    rules_b._apply_rules(_rules({"AZURE"}, version=2, full=False))
    assert config_b.rate_limit == 22
    assert config_b.block_cloud_providers == frozenset({"Azure"})


def test_the_same_app_reinitialized_after_a_release_applies_over_its_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    DynamicRuleManager(config)._apply_rules(_rules({"AWS"}, full=False))
    flight = _parked_then_released(monkeypatch, "after_swap", config, [])
    assert DynamicRuleManager(config) is flight.rules
    flight.gate.set()
    flight.done.wait()
    flight.rules._apply_rules(_rules({"AZURE"}, version=3, full=False))
    assert config.block_cloud_providers == frozenset({"Azure"})
