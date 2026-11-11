import threading
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync._utils.app_managers import release_app
from guard_core.sync._utils.rule_attribution_shared import _APP_RULE_MANAGERS
from guard_core.sync.handlers._background_stop import background_task_is_live
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager


@pytest.fixture(autouse=True)
def _rule_default_unserved(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    _APP_RULE_MANAGERS.forget_default()
    monkeypatch.setattr(DynamicRuleManager, "_instance", None)
    yield
    _APP_RULE_MANAGERS.forget_default()


def _config() -> SyncSecurityConfig:
    return SyncSecurityConfig(
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
    config: SyncSecurityConfig, monkeypatch: pytest.MonkeyPatch
) -> DynamicRuleManager:
    manager = DynamicRuleManager(config)
    monkeypatch.setattr(manager, "_hydrate_last_known_rules", MagicMock())
    monkeypatch.setattr(manager, "update_rules", MagicMock())
    return manager


def test_release_then_an_immediate_initialize_keeps_one_live_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    gate = threading.Event()
    entered = threading.Event()
    manager = DynamicRuleManager(config)
    monkeypatch.setattr(manager, "_hydrate_last_known_rules", MagicMock())

    def update_that_waits_for_the_gate() -> None:
        entered.set()
        gate.wait()

    monkeypatch.setattr(manager, "update_rules", update_that_waits_for_the_gate)
    manager.initialize_agent(Mock())
    entered.wait()
    first = manager.update_task
    release_app(config)
    second_config = _config()
    again = DynamicRuleManager(second_config)
    assert again is manager
    again.initialize_agent(Mock())
    gate.set()
    time.sleep(0.3)
    assert background_task_is_live(again.update_task)
    assert again.update_task is not first
    assert not background_task_is_live(first)
    assert not again._stop_event.is_set()


def test_a_run_that_ended_on_its_own_is_started_again_by_initialize(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    manager = _manager_with_quiet_updates(config, monkeypatch)
    manager.initialize_agent(Mock())
    time.sleep(0.05)
    ended = manager.update_task
    manager._stop_event.set()
    time.sleep(0.2)
    assert not background_task_is_live(ended)
    manager.initialize_agent(Mock())
    time.sleep(0.05)
    assert manager.update_task is not ended
    assert background_task_is_live(manager.update_task)


def test_an_update_in_flight_at_release_applies_nothing_and_ends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    gate = threading.Event()
    entered = threading.Event()
    manager = DynamicRuleManager(config)
    apply_rules = MagicMock(return_value=[])
    monkeypatch.setattr(manager, "_hydrate_last_known_rules", MagicMock())
    monkeypatch.setattr(manager, "_apply_rules", apply_rules)
    agent = Mock()

    def slow_fetch() -> DynamicRules:
        entered.set()
        gate.wait()
        return _rules()

    agent.get_dynamic_rules = slow_fetch
    manager.initialize_agent(agent)
    entered.wait()
    run = manager.update_task
    release_app(config)
    gate.set()
    time.sleep(0.3)
    apply_rules.assert_not_called()
    assert manager.current_rules is None
    assert not background_task_is_live(run)
