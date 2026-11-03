import contextlib
import os
import sys
import threading
import time
from collections.abc import Callable, Generator
from contextlib import AbstractContextManager

import pytest
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from guard_core.sync.handlers.redis_handler import _build_redis_client
from tests.test_sync.conftest import REDIS_URL

TIMEOUT = 0.5
MARGIN = 0.5
CHILD_DEADLINE = TIMEOUT + MARGIN + 1.5
EXIT_OK = 0
EXIT_WRONG_OUTCOME = 3
EXIT_SLOW = 4
EXIT_CRASHED = 5


@pytest.fixture
def client() -> Generator[Redis, None]:
    built = _build_redis_client(REDIS_URL, 1, TIMEOUT)
    yield built
    built.close()


def _fork_warning() -> AbstractContextManager[object]:
    if sys.version_info >= (3, 12):
        return pytest.warns(DeprecationWarning, match="multi-threaded")
    return contextlib.nullcontext()


def _child_status(body: Callable[[], int]) -> int:
    try:
        return body()
    except BaseException:
        return EXIT_CRASHED


def _run_in_forked_child(body: Callable[[], int]) -> int:
    with _fork_warning():
        pid = os.fork()
        if pid == 0:
            os._exit(_child_status(body))
    deadline = time.monotonic() + CHILD_DEADLINE
    while time.monotonic() < deadline:
        finished, status = os.waitpid(pid, os.WNOHANG)
        if finished:
            return os.waitstatus_to_exitcode(status)
        time.sleep(0.02)
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    pytest.fail(
        f"the forked child hung past {CHILD_DEADLINE:.1f} s "
        f"(pool timeout {TIMEOUT} s), killed its pid {pid}"
    )


@contextlib.contextmanager
def _thread_holding(
    lock: AbstractContextManager[object],
) -> Generator[None, None, None]:
    held, done = threading.Event(), threading.Event()

    def hold() -> None:
        with lock:
            held.set()
            done.wait(10)

    thread = threading.Thread(target=hold, daemon=True)
    thread.start()
    held.wait(5)
    try:
        yield
    finally:
        done.set()
        thread.join(5)


def test_a_child_forked_while_a_thread_holds_the_condition_still_times_out(
    client: Redis,
) -> None:
    pool = client.connection_pool
    pool.release(pool.get_connection())

    def exhaust_then_ask_again() -> int:
        pool.get_connection()
        started = time.monotonic()
        try:
            pool.get_connection()
        except RedisConnectionError as error:
            wrong = str(error) != "No connection available."
            slow = time.monotonic() - started > TIMEOUT + MARGIN
            return EXIT_WRONG_OUTCOME if wrong else EXIT_SLOW if slow else EXIT_OK
        return EXIT_WRONG_OUTCOME

    with _thread_holding(pool._condition):
        assert _run_in_forked_child(exhaust_then_ask_again) == EXIT_OK


def test_a_child_forked_while_a_thread_waits_starts_without_waiters(
    client: Redis,
) -> None:
    pool = client.connection_pool
    held = pool.get_connection()
    waiting = threading.Thread(target=lambda: pool.get_connection(), daemon=True)
    waiting.start()
    while not pool._waiters:
        time.sleep(0.01)

    def release_with_no_inherited_waiter() -> int:
        connection = pool.get_connection()
        started = time.monotonic()
        pool.release(connection)
        quick = time.monotonic() - started < MARGIN
        return EXIT_OK if quick and pool._waiters == 0 else EXIT_WRONG_OUTCOME

    try:
        assert _run_in_forked_child(release_with_no_inherited_waiter) == EXIT_OK
    finally:
        pool.release(held)
        waiting.join(5)
