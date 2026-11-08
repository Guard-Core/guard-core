"""LEDGER 6.645 for the sync tree: the attempt thread, its app scope, and a fork while
an attempt is in flight."""

import contextlib
import itertools
import os
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager

import pytest
from redis import Redis

from guard_core.exceptions import GuardRedisError
from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.app_scope import _current_app_scope, app_scope_of
from guard_core.sync.handlers import redis_handler as redis_handler_module
from guard_core.sync.handlers._redis_attempt import RedisAttemptSlot
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL, suite_redis_prefix

_URLS = itertools.count(100)
TIMEOUT = 0.6
BAR = 0.5
CHILD_DEADLINE = 6.0
EXIT_OK = 0
EXIT_BLOCKED = 3
EXIT_NOT_RECOVERED = 4
EXIT_CRASHED = 5


class FakeClient:
    def __init__(self, rig: "Rig") -> None:
        self.rig = rig
        self.closed = False

    def ping(self) -> bool:
        if self.rig.mode == "slowfail":
            time.sleep(0.3)
            raise redis_handler_module.RedisConnectionError("down")
        if self.rig.mode == "fail":
            raise redis_handler_module.RedisConnectionError("down")
        self.rig.started.set()
        deadline = time.monotonic() + 5
        while (
            self.rig.mode == "block"
            and not self.rig.release.is_set()
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        return True

    def close(self) -> None:
        self.closed = True

    def aclose(self) -> None:
        self.closed = True


class Rig:
    def __init__(self) -> None:
        self.mode = "fail"
        self.release = threading.Event()
        self.started = threading.Event()
        self.clients: list[FakeClient] = []

    def build(self, *args: object, **kwargs: object) -> FakeClient:
        client = FakeClient(self)
        self.clients.append(client)
        return client


@pytest.fixture
def rig(monkeypatch: pytest.MonkeyPatch) -> Iterator[Rig]:
    made = Rig()
    monkeypatch.setattr(redis_handler_module, "_build_redis_client", made.build)
    yield made
    made.release.set()


def manager_for(tag: str, url: str | None = None) -> RedisManager:
    config = SyncSecurityConfig(
        enable_redis=True,
        redis_url=url or f"redis://127.0.0.1:1/{next(_URLS)}",
        redis_prefix=suite_redis_prefix(tag),
        redis_socket_connect_timeout=TIMEOUT,
        redis_socket_timeout=TIMEOUT,
        redis_retries=0,
    )
    return RedisManager(config)


def get_ignoring_503(manager: RedisManager) -> str:
    try:
        manager.get_key("outage", "k")
    except GuardRedisError:
        return "503"
    return "ok"


def wait_for(check: Callable[[], bool], seconds: float = 3.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.02)
    return check()


def test_the_attempt_thread_runs_inside_the_app_scope_of_its_manager(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = manager_for("scope")
    seen: list[object] = []
    real_open = RedisManager._open_connection

    def recording_open(self: RedisManager, url: str) -> None:
        seen.append(_current_app_scope.get())
        real_open(self, url)

    assert get_ignoring_503(manager) == "503"
    rig.mode = "ok"
    monkeypatch.setattr(RedisManager, "_open_connection", recording_open)
    time.sleep(0.3)
    assert get_ignoring_503(manager) == "503"
    assert wait_for(manager.is_connected)
    assert seen == [app_scope_of(manager.config)]
    manager.close()


def test_threads_at_a_cold_start_wait_for_one_attempt_and_use_its_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builds: list[int] = []
    real_build = redis_handler_module._build_redis_client

    def counting(url: str, size: int, pool_timeout: float, **kwargs: object) -> Redis:
        builds.append(1)
        return real_build(url, size, pool_timeout, **kwargs)

    real_open = RedisManager._open_connection

    def slow_open(self: RedisManager, url: str) -> None:
        time.sleep(0.3)
        real_open(self, url)

    monkeypatch.setattr(redis_handler_module, "_build_redis_client", counting)
    monkeypatch.setattr(RedisManager, "_open_connection", slow_open)
    manager = manager_for("coldthreads", REDIS_URL)
    answers: list[str] = []
    threads = [
        threading.Thread(target=lambda: answers.append(get_ignoring_503(manager)))
        for _ in range(6)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert answers == ["ok"] * 6
    assert len(builds) == 1
    manager.close()


def test_threads_waiting_for_a_failed_first_attempt_are_refused_without_another(
    rig: Rig,
) -> None:
    rig.mode = "slowfail"
    manager = manager_for("failthreads")
    answers: list[str] = []
    threads = [
        threading.Thread(target=lambda: answers.append(get_ignoring_503(manager)))
        for _ in range(5)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert answers == ["503"] * 5
    assert len(rig.clients) == 1
    manager.close()


def _fork_warning() -> AbstractContextManager[object]:
    if sys.version_info >= (3, 12):
        return pytest.warns(DeprecationWarning, match="multi-threaded")
    return contextlib.nullcontext()


def _run_in_forked_child(body: Callable[[], int]) -> int:
    with _fork_warning():
        pid = os.fork()
        if pid == 0:
            try:
                status = body()
            except BaseException:
                status = EXIT_CRASHED
            os._exit(status)
    deadline = time.monotonic() + CHILD_DEADLINE
    while time.monotonic() < deadline:
        finished, status = os.waitpid(pid, os.WNOHANG)
        if finished:
            return os.waitstatus_to_exitcode(status)
        time.sleep(0.02)
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    pytest.fail(f"the forked child hung past {CHILD_DEADLINE} s, killed its pid {pid}")


def test_a_child_forked_during_an_attempt_neither_blocks_nor_stays_degraded(
    rig: Rig,
) -> None:
    manager = manager_for("fork")
    assert get_ignoring_503(manager) == "503"
    rig.mode = "block"
    time.sleep(0.3)
    assert get_ignoring_503(manager) == "503"
    assert rig.started.wait(3)

    def first_request_in_the_child() -> int:
        rig.mode = "ok"
        started = time.monotonic()
        outcome = get_ignoring_503(manager)
        if outcome != "503" or time.monotonic() - started > BAR:
            return EXIT_BLOCKED
        return EXIT_OK if wait_for(manager.is_connected) else EXIT_NOT_RECOVERED

    assert _run_in_forked_child(first_request_in_the_child) == EXIT_OK
    rig.release.set()
    assert wait_for(manager.is_connected)
    manager.close()


def test_stopping_a_slot_that_never_spawned_does_nothing() -> None:
    RedisAttemptSlot().stop()


def test_forgetting_the_parents_attempts_leaves_a_manager_without_a_gate_alone() -> (
    None
):
    manager = manager_for("nogate")
    manager._forget_the_parents_attempts()
    assert "_reconnect_gate_of_this_manager" not in vars(manager)


def test_a_waiter_past_the_window_gets_503_and_builds_nothing(rig: Rig) -> None:
    rig.mode = "ok"
    manager = manager_for("waiter")
    outcomes: list[str] = []
    waiter = threading.Thread(
        target=lambda: outcomes.append(get_ignoring_503(manager)), daemon=True
    )
    with manager._connection_lock_here():
        waiter.start()
        time.sleep(0.1)
        assert outcomes == []
        manager._degraded = True
        manager._reconnect_gate()._not_before = time.monotonic() - 1.0
    waiter.join(5)
    assert outcomes == ["503"]
    assert rig.clients == []
