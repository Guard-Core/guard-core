import _thread
import contextvars
import sys
import threading
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from typing import cast

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
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol


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


def _config() -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_ip_banning=True,
        enable_agent=True,
        agent_api_key="key",
        enable_dynamic_rules=True,
    )


def _rules() -> DynamicRules:
    return DynamicRules(
        rule_id="wp646",
        version=1,
        timestamp=datetime.now(timezone.utc),
        emergency_mode=True,
        emergency_whitelist=["203.0.113.9"],
    )


class _ContextCopyingAgent:
    """Copies the context of the thread running the cycle, from inside the cycle."""

    def __init__(self) -> None:
        self.copied: contextvars.Context | None = None

    def get_dynamic_rules(self) -> DynamicRules:
        return _rules()

    def send_event(self, event: object) -> None:
        if self.copied is None:
            self.copied = contextvars.copy_context()


def _run_on_a_foreign_thread(work: Callable[[], object]) -> int:
    # _thread.start_new_thread leaves the threading module unaware of the thread,
    # as a C extension, mod_wsgi, uWSGI or Granian does
    done = _thread.allocate_lock()
    done.acquire()
    failure: list[BaseException] = []
    ident: list[int] = []

    def run() -> None:
        ident.append(threading.get_ident())
        try:
            work()
        except BaseException as error:
            failure.append(error)
        finally:
            done.release()

    _thread.start_new_thread(run, ())
    done.acquire()
    while ident[0] in sys._current_frames():  # the thread has not yet ended
        time.sleep(0.001)
    time.sleep(
        0.01
    )  # lets the OS release the thread's slot, so the next thread takes it
    if failure:
        raise failure[0]
    return ident[0]


def test_a_foreign_thread_on_a_dead_foreign_threads_ident_runs_its_own_cycle() -> None:
    config, config_b = _config(), _config()
    bind_app_managers(config)
    manager = DynamicRuleManager(config)
    agent = _ContextCopyingAgent()
    manager.agent_handler = cast(SyncAgentHandlerProtocol, agent)
    first = _run_on_a_foreign_thread(lambda: manager._apply_rules(_rules()))
    copied = agent.copied
    assert copied is not None

    def release_rebind_and_force() -> None:
        release_app(config)
        HandlerInitializer(config_b)
        assert DynamicRuleManager(config_b) is manager
        manager.agent_handler = cast(SyncAgentHandlerProtocol, _ContextCopyingAgent())
        manager.force_update()

    second = _run_on_a_foreign_thread(lambda: copied.run(release_rebind_and_force))
    assert second == first, "the ident of the dead thread was not reused"
    assert manager.current_rules is not None
