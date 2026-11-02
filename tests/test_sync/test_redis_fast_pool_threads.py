import threading
import time
import warnings
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from redis import ConnectionPool, Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from guard_core.sync.handlers import _redis_fast_pool
from guard_core.sync.handlers.redis_handler import _build_redis_client
from tests import redis_py_internals as internals
from tests.test_sync.conftest import REDIS_URL

POOL_SIZE = 3
TIMEOUT = 0.4
MARGIN = 0.5


@pytest.fixture
def client() -> Generator[Redis, None]:
    built = _build_redis_client(REDIS_URL, POOL_SIZE, TIMEOUT)
    yield built
    built.close()


def _hold_all(pool: Any) -> list[Any]:
    return [pool.get_connection() for _ in range(POOL_SIZE)]


def _timed_acquire(pool: Any) -> tuple[Any, float]:
    started = time.monotonic()
    try:
        outcome: Any = pool.get_connection()
    except RedisConnectionError as error:
        outcome = error
    return outcome, time.monotonic() - started


class _ForbiddenCondition:
    def __enter__(self) -> None:
        raise AssertionError("the fast path must not touch the condition")

    def __exit__(self, *exc_info: Any) -> None:
        return None


def test_a_free_connection_is_taken_without_the_condition(client: Redis) -> None:
    pool = client.connection_pool
    pool._condition = _ForbiddenCondition()

    connection = pool.get_connection()
    pool.release(connection)

    assert pool._waiters == 0


def test_the_fast_path_records_no_wait_sample_and_the_slow_path_one(
    client: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    samples: list[float] = []

    def record(**sample: Any) -> None:
        assert sample["pool_name"] == "test-pool"
        samples.append(sample["duration_seconds"])

    monkeypatch.setattr(
        _redis_fast_pool, "_WAIT_RECORDER", (record, lambda pool: "test-pool")
    )
    pool = client.connection_pool
    first = pool.get_connection()
    pool.release(first)
    assert samples == []

    held = _hold_all(pool)
    with ThreadPoolExecutor(max_workers=1) as executor:
        waiter = executor.submit(pool.get_connection)
        time.sleep(0.05)
        pool.release(held[0])
        connection = waiter.result()
    for each in [connection, *held[1:]]:
        pool.release(each)

    assert len(samples) == 1
    assert 0.04 <= samples[0] < TIMEOUT


def test_n_plus_k_concurrent_acquires_each_get_a_connection_or_the_error(
    client: Redis,
) -> None:
    pool = client.connection_pool

    def one(_: int) -> tuple[Any, float]:
        outcome, elapsed = _timed_acquire(pool)
        if not isinstance(outcome, Exception):
            time.sleep(0.2)
            pool.release(outcome)
        return outcome, elapsed

    with ThreadPoolExecutor(max_workers=POOL_SIZE + 9) as executor:
        results = list(executor.map(one, range(POOL_SIZE + 9)))

    for outcome, elapsed in results:
        assert elapsed < TIMEOUT + MARGIN
        if isinstance(outcome, Exception):
            assert str(outcome) == "No connection available."


def test_sustained_exhaustion_fails_every_waiter_inside_the_deadline(
    client: Redis,
) -> None:
    pool = client.connection_pool
    held = _hold_all(pool)
    try:
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: _timed_acquire(pool), range(8)))
    finally:
        for connection in held:
            pool.release(connection)

    for outcome, elapsed in results:
        assert isinstance(outcome, RedisConnectionError)
        assert str(outcome) == "No connection available."
        assert TIMEOUT - 0.05 <= elapsed < TIMEOUT + MARGIN
    assert pool._waiters == 0


def test_churn_never_leaves_a_waiter_past_its_deadline(client: Redis) -> None:
    pool = client.connection_pool
    stop = time.monotonic() + 1.5
    worst: list[float] = []

    def worker(_: int) -> None:
        local = 0.0
        while time.monotonic() < stop:
            outcome, elapsed = _timed_acquire(pool)
            local = max(local, elapsed)
            if not isinstance(outcome, Exception):
                time.sleep(0.03)
                pool.release(outcome)
        worst.append(local)

    with ThreadPoolExecutor(max_workers=POOL_SIZE * 4) as executor:
        list(executor.map(worker, range(POOL_SIZE * 4)))

    assert max(worst) < TIMEOUT + MARGIN
    assert pool._waiters == 0


def test_a_release_between_the_exhaustion_and_the_wait_is_not_lost(
    client: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    pool = client.connection_pool
    held = _hold_all(pool)
    original = pool._wait_until_a_connection_is_free
    released = threading.Event()

    def release_before_the_first_check(
        deadline: float, *, register: bool = False
    ) -> bool:
        if register and not released.is_set():
            released.set()
            pool.release(held[0])
        return bool(original(deadline, register=register))

    monkeypatch.setattr(
        pool, "_wait_until_a_connection_is_free", release_before_the_first_check
    )

    connection, elapsed = _timed_acquire(pool)

    assert not isinstance(connection, Exception)
    assert elapsed < TIMEOUT / 2
    for each in [connection, *held[1:]]:
        pool.release(each)


def test_a_connection_failure_is_raised_at_once_not_waited_out() -> None:
    dead = _build_redis_client("redis://127.0.0.1:1", POOL_SIZE, 5.0)
    started = time.monotonic()
    try:
        with pytest.raises(RedisConnectionError):
            dead.connection_pool.get_connection()
    finally:
        dead.close()

    assert time.monotonic() - started < 2.0


def test_a_waiter_that_loses_the_connection_to_a_newcomer_keeps_its_deadline(
    client: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    pool = client.connection_pool
    held = _hold_all(pool)
    claimed = iter([True])
    monkeypatch.setattr(pool, "_has_free_connection", lambda: next(claimed, False))

    outcome, elapsed = _timed_acquire(pool)

    for each in held:
        pool.release(each)
    assert isinstance(outcome, RedisConnectionError)
    assert str(outcome) == "No connection available."
    assert TIMEOUT - 0.05 <= elapsed < TIMEOUT + MARGIN


def test_a_failure_after_the_wake_is_raised_not_retried(
    client: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    pool = client.connection_pool
    held = _hold_all(pool)
    with ThreadPoolExecutor(max_workers=1) as executor:
        waiter = executor.submit(_timed_acquire, pool)
        time.sleep(0.05)

        def refuse(*_args: Any, **_kwargs: Any) -> None:
            raise RedisConnectionError("refused")

        monkeypatch.setattr(ConnectionPool, "get_connection", refuse)
        pool.release(held[0])
        outcome, elapsed = waiter.result()

    assert str(outcome) == "refused"
    assert elapsed < TIMEOUT
    for each in held[1:]:
        pool.release(each)


def test_a_redis_without_a_wait_recorder_still_waits_and_acquires(
    client: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_redis_fast_pool, "_WAIT_RECORDER", None)
    pool = client.connection_pool
    held = _hold_all(pool)
    with ThreadPoolExecutor(max_workers=1) as executor:
        waiter = executor.submit(pool.get_connection)
        time.sleep(0.05)
        pool.release(held[0])
        connection = waiter.result()
    for each in [connection, *held[1:]]:
        pool.release(each)


def test_the_wait_recorder_is_absent_when_redis_py_has_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(name: str) -> Any:
        raise ImportError(name)

    assert (
        _redis_fast_pool._load_wait_recorder() is not None
    ) is internals.WAIT_RECORDER_EXISTS
    monkeypatch.setattr(_redis_fast_pool.importlib, "import_module", refuse)

    assert _redis_fast_pool._load_wait_recorder() is None


def _checkout_needing_the_name(
    self: ConnectionPool, command_name: str, *keys: Any, **options: Any
) -> str | None:
    return command_name


def _checkout_with_an_optional_name(
    self: ConnectionPool, command_name: str | None = None, *keys: Any, **options: Any
) -> str | None:
    return command_name


def test_the_command_name_is_required_where_the_plain_pool_requires_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ConnectionPool, "get_connection", _checkout_needing_the_name)
    assert _redis_fast_pool._command_name_is_required() is True

    monkeypatch.setattr(
        ConnectionPool, "get_connection", _checkout_with_an_optional_name
    )
    assert _redis_fast_pool._command_name_is_required() is False


def test_a_plain_checkout_takes_the_name_only_where_the_signature_needs_it(
    client: Redis,
) -> None:
    pool = client.connection_pool

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        connection = pool.get_connection()
        pool.release(connection)
        assert client.ping() is True
