import asyncio
import threading
from collections.abc import Iterator
from unittest.mock import Mock

import pytest

from guard_core._utils.app_managers import AppManagers, release_app
from guard_core._utils.rule_attribution_shared import _APP_RULE_MANAGERS
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.decorators import SecurityDecorator
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers._background_stop import stop_task_from_another_thread
from guard_core.handlers.behavior_handler import BehaviorRule
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.models import SecurityConfig
from tests.protocol_only_redis import REDIS_URL

_IP = "203.0.113.80"


@pytest.fixture(autouse=True)
def _defaults_unserved(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    _APP_RULE_MANAGERS.forget_default()
    ipban_module._APP_BAN_MANAGERS.forget_default()
    monkeypatch.setattr(DynamicRuleManager, "_instance", None)
    yield
    _APP_RULE_MANAGERS.forget_default()
    ipban_module._APP_BAN_MANAGERS.forget_default()
    ipban_module.ip_ban_manager.banned_ips.clear()


def _loop_task_of(manager: DynamicRuleManager) -> asyncio.Task[None] | None:
    return manager.update_task


def _state_of(
    manager: DynamicRuleManager,
) -> tuple[object, object, bool, list[str], list[str], float]:
    return (
        manager.update_task,
        manager.current_rules,
        manager._hydrated_last_known_rules,
        manager._owned_bans,
        manager._owned_patterns,
        manager.last_update,
    )


def _config(prefix: str | None = None) -> SecurityConfig:
    if prefix is None:
        return SecurityConfig(enable_redis=False, enable_ip_banning=True)
    return SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_ip_banning=True,
    )


async def test_release_stops_the_loop_of_a_default_held_alone_and_resets_state() -> (
    None
):
    config = _config()
    manager = DynamicRuleManager(config)
    task = asyncio.get_running_loop().create_task(asyncio.sleep(3600))
    manager.update_task = task
    manager.current_rules = Mock()
    manager._hydrated_last_known_rules = True
    manager._owned_bans = ["203.0.113.81"]
    manager._owned_patterns = ["zz"]
    manager.last_update = 123
    release_app(config)
    await asyncio.sleep(0.05)
    assert task.cancelled()
    assert _state_of(manager) == (None, None, False, [], [], 0)
    second = _config()
    assert DynamicRuleManager(second) is manager
    assert manager.config is second


def test_a_sharing_app_keeps_the_default_so_release_does_not_forget_its_state() -> None:
    forgotten: list[str] = []

    class _Default:
        def forget_state_of_the_gone_app(self) -> None:
            forgotten.append("forgot")

    managers: AppManagers[_Default] = AppManagers("pin_shared_default")
    default = _Default()
    first, second = _config("wp616:r4-share:"), _config("wp616:r4-share:")
    managers.bind(first, default, _Default)
    managers.bind(second, default, _Default)
    release_app(first)
    assert forgotten == []
    release_app(second)
    assert forgotten == ["forgot"]


def test_release_from_another_thread_with_the_loop_closed_raises_nothing() -> None:
    config = _config()
    manager = DynamicRuleManager(config)
    loop = asyncio.new_event_loop()
    loop.close()
    task = Mock(spec=asyncio.Task)
    task.done.return_value = False
    task.get_loop.return_value = loop
    manager.update_task = task
    errors: list[str] = []

    def release_elsewhere() -> None:
        try:
            release_app(config)
        except Exception as error:
            errors.append(repr(error))

    thread = threading.Thread(target=release_elsewhere)
    thread.start()
    thread.join()
    assert errors == []
    assert _loop_task_of(manager) is None
    task.cancel.assert_not_called()


async def test_release_from_another_thread_cancels_a_loop_running_here() -> None:
    config = _config()
    manager = DynamicRuleManager(config)
    task = asyncio.get_running_loop().create_task(asyncio.sleep(3600))
    manager.update_task = task
    thread = threading.Thread(target=release_app, args=(config,))
    thread.start()
    thread.join()
    await asyncio.sleep(0.05)
    assert task.cancelled()


async def test_a_decorators_tracker_bans_on_the_manager_its_app_was_bound_to() -> None:
    first = _config("wp616:r4-a:")
    second = _config("wp616:r4-b:")
    HandlerInitializer(first)
    decorator = SecurityDecorator(second)
    tracker = decorator.behavior_tracker
    HandlerInitializer(second, guard_decorator=decorator)
    own = ip_ban_manager_for(second)
    assert own is not ipban_module.ip_ban_manager
    release_app(second)
    assert ip_ban_manager_for(second) is ipban_module.ip_ban_manager
    rule = BehaviorRule("usage", 1, window=60, action="ban", ban_duration=60)
    assert await tracker._execute_ban_action(_IP, "pin", rule) == "ban"
    assert await own.is_ip_banned(_IP, config=second)
    assert not await ipban_module.ip_ban_manager.is_ip_banned(_IP)


async def test_a_rule_ban_lands_on_the_manager_of_the_app_that_took_the_default() -> (
    None
):
    first, second, third = (
        _config("wp616:r4-c:"),
        _config("wp616:r4-d:"),
        _config("wp616:r4-e:"),
    )
    HandlerInitializer(first)
    DynamicRuleManager(second)
    HandlerInitializer(second)
    release_app(second)
    initializer = HandlerInitializer(third)
    adopted = initializer.dynamic_rule_manager_of_this_app()
    own = ip_ban_manager_for(third)
    assert own is not ipban_module.ip_ban_manager
    assert adopted.ban_manager_of_the_app() is own
    await adopted._apply_ip_bans([_IP], 60, [])
    assert await own.is_ip_banned(_IP, config=third)
    assert not await ipban_module.ip_ban_manager.is_ip_banned(_IP)


def test_a_loop_that_closes_between_the_check_and_the_cancel_raises_nothing() -> None:
    loop = Mock()
    loop.is_closed.return_value = False
    loop.is_running.return_value = True
    loop.call_soon_threadsafe.side_effect = RuntimeError("Event loop is closed")
    task = Mock(spec=asyncio.Task)
    task.done.return_value = False
    task.get_loop.return_value = loop
    stop_task_from_another_thread(task, asyncio.Event())


def test_a_failed_withdrawal_is_logged_and_release_goes_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    manager = DynamicRuleManager(config)
    manager.current_rules = Mock()
    monkeypatch.setattr(
        manager, "_revert_to_base_config", Mock(side_effect=RuntimeError("boom"))
    )
    release_app(config)
    assert _state_of(manager)[1] is None
