"""LEDGER 6.645 and 6.698: one connect per manager across event loops, an attempt that
outlives or is cut off by its loop, and a hung app that costs a healthy one nothing."""

import asyncio
import itertools
import threading
import time
from collections.abc import Awaitable, Callable, Coroutine, Iterator
from time import monotonic
from typing import TypeVar
from unittest.mock import MagicMock

import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from guard_core.exceptions import GuardRedisError
from guard_core.handlers import _redis_outage
from guard_core.handlers import redis_handler as redis_handler_module
from guard_core.handlers._redis_attempt import RedisAttemptSlot
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix
from tests.redis_outage_standins import HungListener

T = TypeVar("T")
TIMEOUT = 0.6


_URLS = itertools.count(300)


def fake_url() -> str:
    return f"redis://127.0.0.1:1/{next(_URLS)}"


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

    @staticmethod
    async def _let_scheduled_work_finish() -> None:
        for _ in range(3):
            await asyncio.sleep(0)

    def __exit__(self, *exc_info: object) -> None:
        # A client dropped on this loop closes its transports one iteration later:
        # stopping first leaves them unclosed (LEDGER 6.779, seen as ResourceWarning).
        self.run(self._let_scheduled_work_finish())
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(5)
        self.loop.close()


class ThreadSafeClient:
    """A PING that polls a threading.Event, so it can wait on any loop."""

    def __init__(self, rig: "ThreadSafeRig") -> None:
        self.rig = rig
        self.closed = False
        self.dropped = False
        self.connection_pool = self

    @property
    def _available_connections(self) -> list[object]:
        # read by abandon_client when the client's loop is not the caller's
        self.dropped = True
        return []

    @property
    def _in_use_connections(self) -> list[object]:
        return []

    async def ping(self) -> bool:
        if self.rig.mode == "slowfail":
            await asyncio.sleep(0.1)
            raise RedisConnectionError("down")
        if self.rig.mode == "fail":
            raise RedisConnectionError("down")
        trap = self.rig.trap
        if trap is not None and threading.current_thread() is trap.thread:
            trap.armed = True
        if self.rig.mode == "slow":
            await asyncio.sleep(0.3)
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


class ReadTrap:
    """Pauses one thread right after it read the manager's client, so another thread
    can run a whole bind before the first one writes (the interleaving of two loops on
    two OS threads between a check and an assignment)."""

    def __init__(self) -> None:
        self.thread: threading.Thread | None = None
        self.armed = False
        self.read = threading.Event()
        self.other_done = threading.Event()

    def pause_if_trapped(self) -> None:
        if self.armed and threading.current_thread() is self.thread:
            self.armed = False
            self.read.set()
            self.other_done.wait(0.5)


class TrappedClientSlot:
    def __init__(self, trap: ReadTrap) -> None:
        self.trap = trap

    def __get__(self, owner: object, *_unused: object) -> object:
        if owner is None:
            return None
        value = vars(owner).get("_raw_redis")
        self.trap.pause_if_trapped()
        return value

    def __set__(self, owner: object, value: object) -> None:
        vars(owner)["_raw_redis"] = value


class ThreadSafeRig:
    def __init__(self) -> None:
        self.mode = "fail"
        self.release = threading.Event()
        self.started = threading.Event()
        self.clients: list[ThreadSafeClient] = []
        self.trap: ReadTrap | None = None

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


@pytest.fixture
def late_abandon(monkeypatch: pytest.MonkeyPatch) -> None:
    """abandon_client only schedules the drop on the client's own loop. Stall that
    loop first so the drop lands late, as it does on a loaded machine (LEDGER 6.779)."""
    real_abandon = _redis_outage.abandon_client

    def stalled(client: Redis, client_loop: asyncio.AbstractEventLoop) -> None:
        client_loop.call_soon_threadsafe(time.sleep, 0.3)
        real_abandon(client, client_loop)

    monkeypatch.setattr(_redis_outage, "abandon_client", stalled)


def unreleased_clients(
    rig: ThreadSafeRig, manager: RedisManager, *loops: LoopThread
) -> list[ThreadSafeClient]:
    # A drop is queued on its client's loop: wait for each loop to run what it holds.
    for loop in loops:
        loop.run(asyncio.sleep(0))
    # A client of a loop that is still alive is parked, not released.
    live = [manager._redis, *(held[0] for held in manager._parked_clients().values())]
    return [
        client
        for client in rig.clients
        if all(client is not kept for kept in live)
        and not (client.closed or client.dropped)
    ]


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


@pytest.mark.usefixtures("late_abandon")
async def test_two_loops_reconnecting_at_once_leave_no_client_unreleased(
    rig: ThreadSafeRig,
) -> None:
    rig.mode = "ok"
    manager = RedisManager(config_for(fake_url(), "leak", TIMEOUT))

    async def use() -> None:
        async with manager.get_connection():
            pass

    with LoopThread() as bound, LoopThread() as first, LoopThread() as second:
        bound.run(use())
        assert len(rig.clients) == 1
        rig.mode = "slow"
        racers = [
            asyncio.run_coroutine_threadsafe(use(), loop.loop)
            for loop in (first, second)
        ]
        for racer in racers:
            racer.result(10)
        leaked = unreleased_clients(rig, manager, bound, first, second)
        assert leaked == []
        assert manager._redis is not None
        bound.run(manager.close())


@pytest.mark.usefixtures("late_abandon")
async def test_two_threads_binding_between_a_check_and_a_write_release_the_first(
    rig: ThreadSafeRig, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig.mode = "ok"
    manager = RedisManager(config_for(fake_url(), "interleave", TIMEOUT))

    async def use() -> None:
        async with manager.get_connection():
            pass

    with LoopThread() as bound, LoopThread() as first, LoopThread() as second:
        bound.run(use())
        trap = ReadTrap()
        trap.thread = first._thread
        rig.trap = trap
        monkeypatch.setattr(RedisManager, "_redis", TrappedClientSlot(trap))
        vars(manager)["_raw_redis"] = vars(manager).pop("_redis", None)
        racer = asyncio.run_coroutine_threadsafe(use(), first.loop)
        assert trap.read.wait(5)
        other = asyncio.run_coroutine_threadsafe(use(), second.loop)
        other.result(10)
        trap.other_done.set()
        racer.result(10)
        leaked = unreleased_clients(rig, manager, bound, first, second)
        assert leaked == []
        assert manager._redis is not None
        bound.run(manager.close())


async def test_requests_on_another_loop_after_the_connects_fail_make_one_attempt(
    rig: ThreadSafeRig,
) -> None:
    rig.mode = "ok"
    manager = RedisManager(config_for(fake_url(), "loopbfails", TIMEOUT))

    async def bind_here() -> None:
        await manager.initialize()

    await on_a_new_loop(bind_here)
    assert len(rig.clients) == 1
    rig.mode = "slowfail"

    async def timed(one: RedisManager) -> tuple[float, object]:
        started = monotonic()
        answer = await get_ignoring_503(one)
        return monotonic() - started, answer

    answers = await asyncio.gather(*(timed(manager) for _ in range(8)))
    assert len(rig.clients) == 2
    assert {answer for _, answer in answers} == {"503"}
    assert max(wait for wait, _ in answers) < 0.5
    await manager.close()
