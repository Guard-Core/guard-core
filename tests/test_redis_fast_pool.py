import asyncio
import importlib
import importlib.util
import time
import warnings
from collections.abc import AsyncGenerator
from types import ModuleType
from typing import Any

import pytest
import redis.asyncio.connection as redis_connection_module
from redis.asyncio import ConnectionPool, Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from guard_core.handlers import _redis_fast_pool
from guard_core.handlers.redis_handler import _build_redis_client, close_redis_client
from tests import redis_py_internals as internals
from tests.conftest import REDIS_URL

POOL_SIZE = 3
TIMEOUT = 0.4
MARGIN = 0.5


@pytest.fixture
async def client() -> AsyncGenerator[Redis, None]:
    built = _build_redis_client(REDIS_URL, POOL_SIZE, TIMEOUT)
    yield built
    await close_redis_client(built)


async def _hold_all(pool: Any) -> list[Any]:
    return [await pool.get_connection() for _ in range(POOL_SIZE)]


async def _timed_acquire(pool: Any) -> tuple[Any, float]:
    started = time.monotonic()
    try:
        outcome: Any = await pool.get_connection()
    except RedisConnectionError as error:
        outcome = error
    return outcome, time.monotonic() - started


class _ForbiddenCondition:
    async def __aenter__(self) -> None:
        raise AssertionError("the fast path must not touch the condition")

    async def __aexit__(self, *exc_info: Any) -> None:
        return None


async def test_a_free_connection_is_taken_without_the_condition(
    client: Redis,
) -> None:
    pool = client.connection_pool
    pool._condition = _ForbiddenCondition()

    connection = await pool.get_connection()
    await pool.release(connection)

    assert pool._waiters == 0


async def test_the_fast_path_records_no_wait_sample_and_the_slow_path_one(
    client: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    samples: list[float] = []

    async def record(**sample: Any) -> None:
        assert sample["pool_name"] == "test-pool"
        samples.append(sample["duration_seconds"])

    monkeypatch.setattr(
        _redis_fast_pool, "_WAIT_RECORDER", (record, lambda pool: "test-pool")
    )
    pool = client.connection_pool
    first = await pool.get_connection()
    await pool.release(first)
    assert samples == []

    held = await _hold_all(pool)
    waiter = asyncio.create_task(pool.get_connection())
    await asyncio.sleep(0.05)
    await pool.release(held[0])
    connection = await waiter
    for each in [connection, *held[1:]]:
        await pool.release(each)

    assert len(samples) == 1
    assert 0.04 <= samples[0] < TIMEOUT


async def test_n_plus_k_concurrent_acquires_each_get_a_connection_or_the_error(
    client: Redis,
) -> None:
    pool = client.connection_pool

    async def one() -> tuple[Any, float]:
        outcome, elapsed = await _timed_acquire(pool)
        if not isinstance(outcome, Exception):
            await asyncio.sleep(0.2)
            await pool.release(outcome)
        return outcome, elapsed

    results = await asyncio.gather(*(one() for _ in range(POOL_SIZE + 9)))

    for outcome, elapsed in results:
        assert elapsed < TIMEOUT + MARGIN
        if isinstance(outcome, Exception):
            assert str(outcome) == "No connection available."


async def test_sustained_exhaustion_fails_every_waiter_inside_the_deadline(
    client: Redis,
) -> None:
    pool = client.connection_pool
    held = await _hold_all(pool)
    try:
        results = await asyncio.gather(*(_timed_acquire(pool) for _ in range(8)))
    finally:
        for connection in held:
            await pool.release(connection)

    for outcome, elapsed in results:
        assert isinstance(outcome, RedisConnectionError)
        assert str(outcome) == "No connection available."
        assert TIMEOUT - 0.05 <= elapsed < TIMEOUT + MARGIN
    assert pool._waiters == 0


async def test_churn_never_leaves_a_waiter_past_its_deadline(client: Redis) -> None:
    pool = client.connection_pool
    stop = time.monotonic() + 1.5
    worst = 0.0

    async def worker() -> None:
        nonlocal worst
        while time.monotonic() < stop:
            outcome, elapsed = await _timed_acquire(pool)
            worst = max(worst, elapsed)
            if not isinstance(outcome, Exception):
                await asyncio.sleep(0.03)
                await pool.release(outcome)

    await asyncio.gather(*(worker() for _ in range(POOL_SIZE * 4)))

    assert worst < TIMEOUT + MARGIN
    assert pool._waiters == 0


async def test_a_release_between_the_exhaustion_and_the_wait_is_not_lost(
    client: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    pool = client.connection_pool
    held = await _hold_all(pool)
    original = pool._wait_on_the_condition

    async def release_in_the_window() -> None:
        assert pool._waiters == 1
        await pool.release(held[0])
        await original()

    monkeypatch.setattr(pool, "_wait_on_the_condition", release_in_the_window)

    connection, elapsed = await _timed_acquire(pool)

    assert not isinstance(connection, Exception)
    assert elapsed < TIMEOUT / 2
    for each in [connection, *held[1:]]:
        await pool.release(each)


async def test_a_connection_failure_is_raised_at_once_not_waited_out() -> None:
    dead = _build_redis_client("redis://127.0.0.1:1", POOL_SIZE, 5.0)
    started = time.monotonic()
    try:
        with pytest.raises(RedisConnectionError):
            await dead.connection_pool.get_connection()
    finally:
        await close_redis_client(dead)

    assert time.monotonic() - started < 2.0


async def test_a_waiter_that_loses_the_connection_to_a_newcomer_keeps_its_deadline(
    client: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    pool = client.connection_pool
    held = await _hold_all(pool)
    claimed = iter([True])
    monkeypatch.setattr(pool, "_has_free_connection", lambda: next(claimed, False))

    outcome, elapsed = await _timed_acquire(pool)

    for each in held:
        await pool.release(each)
    assert isinstance(outcome, RedisConnectionError)
    assert str(outcome) == "No connection available."
    assert TIMEOUT - 0.05 <= elapsed < TIMEOUT + MARGIN


async def test_a_failure_after_the_wake_is_raised_not_retried(
    client: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    pool = client.connection_pool
    held = await _hold_all(pool)
    waiter = asyncio.create_task(_timed_acquire(pool))
    await asyncio.sleep(0.05)

    async def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise RedisConnectionError("refused")

    monkeypatch.setattr(ConnectionPool, "get_connection", refuse)
    await pool.release(held[0])
    outcome, elapsed = await waiter

    assert str(outcome) == "refused"
    assert elapsed < TIMEOUT
    for each in held[1:]:
        await pool.release(each)


async def test_a_redis_without_a_wait_recorder_still_waits_and_acquires(
    client: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_redis_fast_pool, "_WAIT_RECORDER", None)
    pool = client.connection_pool
    held = await _hold_all(pool)
    waiter = asyncio.create_task(pool.get_connection())
    await asyncio.sleep(0.05)
    await pool.release(held[0])
    connection = await waiter
    for each in [connection, *held[1:]]:
        await pool.release(each)


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


def _fresh_copy_of_the_fast_pool_module() -> ModuleType:
    path = _redis_fast_pool.__file__
    assert path is not None
    spec = importlib.util.spec_from_file_location("fast_pool_fresh_copy", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_module_loads_afresh_on_this_redis_py() -> None:
    module = _fresh_copy_of_the_fast_pool_module()

    assert issubclass(module.FastPathConnectionPool, ConnectionPool)


def test_the_module_needs_no_abstract_connection_class_to_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(redis_connection_module, "AbstractConnection", raising=False)

    module = _fresh_copy_of_the_fast_pool_module()

    assert issubclass(module.FastPathConnectionPool, ConnectionPool)


def test_a_redis_py_whose_recorder_lacks_the_count_function_has_no_count_recorder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def an_observability_module_with_nothing_in_it(name: str) -> ModuleType:
        return ModuleType(name)

    monkeypatch.setattr(
        _redis_fast_pool.importlib,
        "import_module",
        an_observability_module_with_nothing_in_it,
    )

    assert _redis_fast_pool._load_count_recorder() is None


async def _checkout_needing_the_name(
    self: ConnectionPool, command_name: str, *keys: object, **options: object
) -> str | None:
    return command_name


async def _checkout_with_an_optional_name(
    self: ConnectionPool,
    command_name: str | None = None,
    *keys: object,
    **options: object,
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


async def test_a_plain_checkout_takes_the_name_only_where_the_signature_needs_it(
    client: Redis,
) -> None:
    pool = client.connection_pool

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        connection = await pool.get_connection()
        await pool.release(connection)
        assert await client.ping() is True
