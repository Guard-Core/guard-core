"""LEDGER 6.645 and 6.698: one connect per manager across event loops, an attempt that
outlives or is cut off by its loop, and a hung app that costs a healthy one nothing."""

import asyncio
import threading
from collections.abc import Awaitable, Callable, Coroutine, Iterator
from time import monotonic
from types import SimpleNamespace
from typing import TypeVar
from unittest.mock import MagicMock

import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from guard_core.exceptions import GuardRedisError
from guard_core.handlers import redis_handler as redis_handler_module
from guard_core.handlers._redis_attempt import RedisAttemptSlot
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix
from tests.redis_outage_standins import HungListener

T = TypeVar("T")
TIMEOUT = 0.6


def config_for(url: str, tag: str, timeout: float = 5.0) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=url,
        redis_prefix=suite_redis_prefix(tag),
        redis_socket_connect_timeout=timeout,
        redis_socket_timeout=timeout,
        redis_retries=0,
    )


def on_a_new_loop(make: Callable[[], Coroutine[object, object, T]]) -> Awaitable[T]:
    return asyncio.to_thread(lambda: asyncio.run(make()))


class LoopThread:
    """An event loop that keeps running on its own thread."""

    def __enter__(self) -> "LoopThread":
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self._thread.start()
        return self

    def run(self, work: Coroutine[object, object, T]) -> T:
        return asyncio.run_coroutine_threadsafe(work, self.loop).result(10)

    def __exit__(self, *exc_info: object) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(5)
        self.loop.close()


class ThreadSafeClient:
    """A PING that polls a threading.Event, so it can wait on any loop."""

    def __init__(self, rig: "ThreadSafeRig") -> None:
        self.rig = rig
        self.closed = False
        self.connection_pool = SimpleNamespace(
            _available_connections=[], _in_use_connections=[]
        )

    async def ping(self) -> bool:
        if self.rig.mode == "fail":
            raise RedisConnectionError("down")
        self.rig.started.set()
        deadline = monotonic() + 3.0
        while (
            self.rig.mode == "block"
            and not self.rig.release.is_set()
            and monotonic() < deadline
        ):
            await asyncio.sleep(0.01)
        return True

    async def close(self) -> None:
        self.closed = True

    async def aclose(self) -> None:
        self.closed = True


class ThreadSafeRig:
    def __init__(self) -> None:
        self.mode = "fail"
        self.release = threading.Event()
        self.started = threading.Event()
        self.clients: list[ThreadSafeClient] = []

    def build(self, *args: object, **kwargs: object) -> ThreadSafeClient:
        client = ThreadSafeClient(self)
        self.clients.append(client)
        return client


@pytest.fixture
def rig(monkeypatch: pytest.MonkeyPatch) -> Iterator[ThreadSafeRig]:
    made = ThreadSafeRig()
    monkeypatch.setattr(redis_handler_module, "_build_redis_client", made.build)
    yield made
    made.release.set()


async def get_ignoring_503(manager: RedisManager) -> object:
    try:
        return await manager.get_key("outage", "k")
    except GuardRedisError:
        return "503"


def counting_builder(builds: list[int]) -> Callable[..., Redis]:
    real_build = redis_handler_module._build_redis_client

    def counting(url: str, size: int, pool_timeout: float, **kwargs: object) -> Redis:
        builds.append(1)
        return real_build(url, size, pool_timeout, **kwargs)

    return counting


def slow_open(delay: float) -> Callable[[RedisManager, str], Awaitable[None]]:
    real_open = RedisManager._open_connection

    async def slow(self: RedisManager, url: str) -> None:
        await asyncio.sleep(delay)
        await real_open(self, url)

    return slow


async def test_concurrent_requests_on_a_new_loop_reconnect_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builds: list[int] = []
    monkeypatch.setattr(
        redis_handler_module, "_build_redis_client", counting_builder(builds)
    )
    manager = RedisManager(config_for(REDIS_URL, "mismatch"))
    await manager.initialize()
    assert len(builds) == 1

    async def twenty_at_once() -> list[object]:
        return list(
            await asyncio.gather(*(get_ignoring_503(manager) for _ in range(20)))
        )

    answers = await on_a_new_loop(twenty_at_once)
    assert answers == [None] * 20
    assert len(builds) == 2
    await manager.close()


async def test_a_lock_contended_on_two_loops_raises_no_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(RedisManager, "_open_connection", slow_open(0.2))
    manager = RedisManager(config_for(REDIS_URL, "twoloops"))

    async def three_at_once() -> list[object]:
        return list(
            await asyncio.gather(*(get_ignoring_503(manager) for _ in range(3)))
        )

    assert await on_a_new_loop(three_at_once) == [None] * 3
    assert await on_a_new_loop(three_at_once) == [None] * 3
    await manager.close()


async def test_a_hung_app_costs_a_healthy_app_nothing() -> None:
    with HungListener() as hung:
        stuck = RedisManager(config_for(hung.url, "stuck", TIMEOUT))
        healthy = RedisManager(config_for(REDIS_URL, "healthy"))

        async def timed(manager: RedisManager) -> float:
            started = monotonic()
            await get_ignoring_503(manager)
            return monotonic() - started

        stuck_wait, healthy_wait = await asyncio.gather(timed(stuck), timed(healthy))
        assert stuck_wait >= TIMEOUT * 0.5
        assert healthy_wait < 0.3
        await stuck.close()
        await healthy.close()


async def test_the_spawning_loop_ending_mid_attempt_leaves_a_manager_that_recovers(
    rig: ThreadSafeRig,
) -> None:
    manager = RedisManager(config_for("redis://127.0.0.1:1/0", "loopends", TIMEOUT))

    async def fail_then_start_a_blocked_attempt() -> None:
        assert await get_ignoring_503(manager) == "503"
        rig.mode = "block"
        await asyncio.sleep(0.3)
        assert await get_ignoring_503(manager) == "503"
        await asyncio.sleep(0.1)
        assert rig.started.is_set()

    await on_a_new_loop(fail_then_start_a_blocked_attempt)
    assert not manager.is_connected()
    assert all(client.closed for client in rig.clients if client.rig.mode == "block")
    rig.mode = "ok"

    async def recover() -> bool:
        await asyncio.sleep(1.3)
        await get_ignoring_503(manager)
        for _ in range(100):
            if manager.is_connected():
                return True
            await asyncio.sleep(0.02)
        return False

    assert await on_a_new_loop(recover)
    await manager.close()


async def test_close_from_another_loop_cancels_an_attempt_on_a_live_loop(
    rig: ThreadSafeRig,
) -> None:
    manager = RedisManager(config_for("redis://127.0.0.1:1/0", "foreignclose", TIMEOUT))
    with LoopThread() as spawning:

        async def fail_then_block() -> None:
            await get_ignoring_503(manager)
            rig.mode = "block"
            await asyncio.sleep(0.3)
            await get_ignoring_503(manager)
            await asyncio.sleep(0.1)

        spawning.run(fail_then_block())
        assert rig.started.is_set()
        started = monotonic()
        await manager.close()
        assert monotonic() - started < 1.0
        for _ in range(100):
            if rig.clients[-1].closed:
                break
            await asyncio.sleep(0.02)
    assert rig.clients[-1].closed
    assert not manager.is_connected()


async def test_stopping_an_attempt_whose_loop_is_closed_cancels_nothing() -> None:
    gone = asyncio.new_event_loop()
    gone.close()
    task = MagicMock()
    task.done.return_value = False
    task.get_loop.return_value = gone
    slot = RedisAttemptSlot()
    slot._task = task
    await slot.stop()
    task.cancel.assert_not_called()


async def test_a_cancel_during_the_ping_closes_the_client_and_frees_the_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    made: list[ThreadSafeClient] = []
    rig = ThreadSafeRig()
    rig.mode = "block"

    def build(*args: object, **kwargs: object) -> ThreadSafeClient:
        client = rig.build()
        made.append(client)
        return client

    monkeypatch.setattr(redis_handler_module, "_build_redis_client", build)
    manager = RedisManager(config_for("redis://127.0.0.1:1/0", "cancel", TIMEOUT))
    task = asyncio.create_task(manager.initialize())
    while not rig.started.is_set():
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert made[0].closed
    gate = manager._reconnect_gate()
    assert gate._failures == 1
    assert not gate._claim.locked()
    rig.release.set()


async def test_alternating_loops_make_a_bounded_number_of_reconnects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builds: list[int] = []
    monkeypatch.setattr(
        redis_handler_module, "_build_redis_client", counting_builder(builds)
    )
    manager = RedisManager(config_for(REDIS_URL, "alternate"))
    rounds = 6
    with LoopThread() as first, LoopThread() as second:
        for turn in range(rounds):
            loop = first if turn % 2 == 0 else second
            assert loop.run(get_ignoring_503(manager)) is None
        first.run(manager.close())
    assert len(builds) <= rounds + 1
