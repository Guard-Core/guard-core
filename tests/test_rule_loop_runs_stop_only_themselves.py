import asyncio
from collections.abc import Iterator
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core._utils.app_managers import release_app
from guard_core._utils.rule_attribution_shared import _APP_RULE_MANAGERS
from guard_core.handlers._background_stop import background_task_is_live
from guard_core.handlers._dynamic_rule_intake import RunStopped
from guard_core.handlers.dynamic_rule_handler import _RUN_STOP, DynamicRuleManager
from guard_core.models import DynamicRules, SecurityConfig


@pytest.fixture(autouse=True)
def _rule_default_unserved(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    _APP_RULE_MANAGERS.forget_default()
    monkeypatch.setattr(DynamicRuleManager, "_instance", None)
    yield
    _APP_RULE_MANAGERS.forget_default()


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="k" * 10,
        enable_dynamic_rules=True,
        dynamic_rule_interval=3600,
    )


def _rules() -> DynamicRules:
    return DynamicRules(
        rule_id="r6", version=1, timestamp=datetime.now(timezone.utc), ip_blacklist=[]
    )


def _manager_with_quiet_updates(
    config: SecurityConfig, monkeypatch: pytest.MonkeyPatch
) -> DynamicRuleManager:
    manager = DynamicRuleManager(config)
    monkeypatch.setattr(manager, "_hydrate_last_known_rules", AsyncMock())
    monkeypatch.setattr(manager, "update_rules", AsyncMock())
    return manager


async def test_release_then_an_immediate_initialize_keeps_one_live_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    gate = asyncio.Event()
    entered = asyncio.Event()
    manager = DynamicRuleManager(config)
    monkeypatch.setattr(manager, "_hydrate_last_known_rules", AsyncMock())

    async def update_that_waits_for_the_gate() -> None:
        entered.set()
        await gate.wait()

    monkeypatch.setattr(manager, "update_rules", update_that_waits_for_the_gate)
    await manager.initialize_agent(Mock())
    await entered.wait()
    first = manager.update_task
    release_app(config)
    second_config = _config()
    again = DynamicRuleManager(second_config)
    assert again is manager
    await again.initialize_agent(Mock())
    gate.set()
    await asyncio.sleep(0.3)
    assert background_task_is_live(again.update_task)
    assert again.update_task is not first
    assert not background_task_is_live(first)
    assert not again._stop_event.is_set()


async def test_a_run_that_ended_on_its_own_is_started_again_by_initialize(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    manager = _manager_with_quiet_updates(config, monkeypatch)
    await manager.initialize_agent(Mock())
    await asyncio.sleep(0.05)
    ended = manager.update_task
    manager._stop_event.set()
    await asyncio.sleep(0.2)
    assert not background_task_is_live(ended)
    await manager.initialize_agent(Mock())
    await asyncio.sleep(0.05)
    assert manager.update_task is not ended
    assert background_task_is_live(manager.update_task)


async def test_an_update_in_flight_at_release_applies_nothing_and_ends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    gate = asyncio.Event()
    entered = asyncio.Event()
    manager = DynamicRuleManager(config)
    apply_rules = AsyncMock(return_value=[])
    monkeypatch.setattr(manager, "_hydrate_last_known_rules", AsyncMock())
    monkeypatch.setattr(manager, "_apply_rules", apply_rules)
    agent = Mock()

    async def slow_fetch() -> DynamicRules:
        entered.set()
        await gate.wait()
        return _rules()

    agent.get_dynamic_rules = slow_fetch
    await manager.initialize_agent(agent)
    await entered.wait()
    run = manager.update_task
    release_app(config)
    gate.set()
    await asyncio.sleep(0.3)
    apply_rules.assert_not_called()
    assert manager.current_rules is None
    assert not background_task_is_live(run)


async def test_a_stopped_run_does_not_enter_the_apply() -> None:
    manager = DynamicRuleManager(_config())
    stop_event = asyncio.Event()
    stop_event.set()
    token = _RUN_STOP.set(stop_event)
    try:
        with pytest.raises(RunStopped):
            await manager._apply_rules(_rules())
    finally:
        _RUN_STOP.reset(token)


async def test_a_run_ends_when_its_update_reports_it_was_stopped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    manager = DynamicRuleManager(config)
    monkeypatch.setattr(manager, "_hydrate_last_known_rules", AsyncMock())
    monkeypatch.setattr(manager, "update_rules", AsyncMock(side_effect=RunStopped))
    await manager.initialize_agent(Mock())
    await asyncio.sleep(0.2)
    assert not background_task_is_live(manager.update_task)


async def test_a_stopped_run_does_not_ask_for_a_rule_update() -> None:
    manager = DynamicRuleManager(_config())
    stop_event = asyncio.Event()
    stop_event.set()
    token = _RUN_STOP.set(stop_event)
    try:
        assert manager._should_update_rules(_rules()) is False
    finally:
        _RUN_STOP.reset(token)


async def test_a_run_stopped_during_its_update_does_not_sleep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = DynamicRuleManager(_config())
    stop_event = asyncio.Event()

    async def update_that_stops_the_run() -> None:
        stop_event.set()

    sleep = AsyncMock()
    monkeypatch.setattr(manager, "update_rules", update_that_stops_the_run)
    monkeypatch.setattr(manager, "_interruptible_sleep", sleep)
    await manager._rule_update_loop(stop_event)
    sleep.assert_not_called()


async def test_a_failed_update_backs_off_before_the_next_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = DynamicRuleManager(_config())
    stop_event = asyncio.Event()
    sleeps: list[float] = []

    async def back_off_then_stop(timeout: float, event: asyncio.Event) -> None:
        sleeps.append(timeout)
        event.set()

    monkeypatch.setattr(
        manager, "update_rules", AsyncMock(side_effect=RuntimeError("boom"))
    )
    monkeypatch.setattr(manager, "_interruptible_sleep", back_off_then_stop)
    await manager._rule_update_loop(stop_event)
    assert sleeps == [60]


async def test_a_run_stopped_during_a_failed_update_ends_without_backing_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = DynamicRuleManager(_config())
    stop_event = asyncio.Event()

    async def update_that_stops_the_run_then_fails() -> None:
        stop_event.set()
        raise RuntimeError("boom")

    sleep = AsyncMock()
    monkeypatch.setattr(manager, "update_rules", update_that_stops_the_run_then_fails)
    monkeypatch.setattr(manager, "_interruptible_sleep", sleep)
    await manager._rule_update_loop(stop_event)
    sleep.assert_not_called()


async def test_initializing_the_agent_again_keeps_the_live_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _manager_with_quiet_updates(_config(), monkeypatch)
    await manager.initialize_agent(Mock())
    live = manager.update_task
    await manager.initialize_agent(Mock())
    assert manager.update_task is live
    assert background_task_is_live(live)
    release_app(manager.config)
