import threading
import time

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.app_scope import app_scope_of
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.decorators.base import BaseSecurityDecorator


def test_two_threads_completing_a_sync_adoption_run_the_steps_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig()
    initializer = HandlerInitializer(config)
    monkeypatch.setattr(app_scope_of(config), "redis_handler", object())
    adopted = BaseSecurityDecorator(SyncSecurityConfig())
    calls: list[int] = []

    def slow(redis_handler: object = None) -> None:
        calls.append(1)
        time.sleep(0.05)

    monkeypatch.setattr(adopted, "initialize_behavior_tracking", slow)
    initializer.adopt_decorator(adopted)

    threads = [
        threading.Thread(target=initializer.complete_decorator_adoption)
        for _ in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(calls) == 1
