"""LEDGER 6.645, 6.696, 6.697 (engine part), 6.698: during a Redis outage no request
that starts after the first failed attempt waits for a connect, whether the outage
began before the first connect or while the client was live."""

import asyncio
import itertools
import logging
from collections.abc import Callable, Iterator
from time import monotonic
from unittest.mock import MagicMock, patch

import pytest
from redis.exceptions import AuthenticationError, BusyLoadingError, MaxConnectionsError
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.exceptions import GuardRedisError
from guard_core.handlers import redis_handler as redis_handler_module
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, MockGuardResponse, suite_redis_prefix
from tests.redis_outage_standins import HangableProxy, HungListener

BAR = 0.5
BLOCK_LIMIT = 3.0
TIMEOUT = 0.6
CLIENT_IP = "198.51.100.77"


_URLS = itertools.count()


def fake_url() -> str:
    # One database number per call: a client published for one URL is shared by the
    # next manager on the same URL, and these tests count the clients they build.
    return f"redis://127.0.0.1:1/{next(_URLS)}"


def config_for(
    url: str,
    tag: str,
    *,
    redis_fail_open: bool = True,
    redis_max_connections: int | None = None,
    redis_pool_timeout: float = 1.0,
    timeout: float = TIMEOUT,
    prefix: str | None = None,
) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=url,
        redis_prefix=prefix or suite_redis_prefix(tag),
        redis_socket_connect_timeout=timeout,
        redis_socket_timeout=timeout,
        redis_retries=0,
        redis_fail_open=redis_fail_open,
        redis_max_connections=redis_max_connections,
        redis_pool_timeout=redis_pool_timeout,
    )


async def timed_get(manager: RedisManager) -> tuple[float, str]:
    started = monotonic()
    try:
        await manager.get_key("outage", "k")
    except GuardRedisError as refused:
        return monotonic() - started, f"{refused.status_code}"
    return monotonic() - started, "ok"


async def requests_for(manager: RedisManager, seconds: float) -> list[float]:
    waits: list[float] = []
    end = monotonic() + seconds
    while monotonic() < end:
        waits.append((await timed_get(manager))[0])
        await asyncio.sleep(0.05)
    return waits


class StopTheProcess(BaseException):
    """What a cancel or a KeyboardInterrupt is to the code: not an Exception."""


class FakeClient:
    """A client whose PING the test controls; closes are recorded."""

    def __init__(self, rig: "Rig") -> None:
        self.rig = rig
        self.closed = False

    async def ping(self) -> bool:
        self.rig.pings += 1
        if self.rig.mode == "fail":
            raise RedisConnectionError("down")
        if self.rig.mode == "stop":
            raise StopTheProcess
        if self.rig.mode == "steal":
            # Another loop's reconnect binds its own client while this one pings.
            assert self.rig.manager is not None
            self.rig.manager._redis = self.rig.stolen
        self.rig.started.set()
        deadline = monotonic() + BLOCK_LIMIT
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


class Rig:
    def __init__(self) -> None:
        self.mode = "fail"
        self.pings = 0
        self.release = asyncio.Event()
        self.started = asyncio.Event()
        self.clients: list[FakeClient] = []
        self.manager: RedisManager | None = None
        self.stolen = FakeClient(self)

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


async def wait_until(check: Callable[[], bool], seconds: float = 3.0) -> bool:
    end = monotonic() + seconds
    while monotonic() < end:
        if check():
            return True
        await asyncio.sleep(0.02)
    return check()


async def wait_connected(manager: RedisManager) -> bool:
    return await wait_until(manager.is_connected)


async def test_a_hung_redis_costs_only_the_first_attempt_a_wait() -> None:
    with HungListener() as hung:
        manager = RedisManager(config_for(hung.url, "hung"))
        first, outcome = await timed_get(manager)
        assert outcome == "503"
        assert first >= TIMEOUT * 0.5
        waits = await requests_for(manager, 3.5)
        await manager.close()
    assert len(waits) > 20
    assert max(waits) < BAR


async def test_an_outage_that_starts_with_a_live_client_stops_costing_waits() -> None:
    with HangableProxy() as proxy:
        manager = RedisManager(config_for(proxy.url, "midlife"))
        await manager.initialize()
        await manager.set_key("outage", "k", "v", ttl=30)
        assert (await timed_get(manager))[1] == "ok"
        proxy.hang()
        first = (await timed_get(manager))[0]
        assert first >= TIMEOUT * 0.5
        waits = await requests_for(manager, 3.5)
        await manager.close()
    assert len(waits) > 20
    assert max(waits) < BAR


async def test_fail_closed_answers_503_at_once_while_degraded_and_recovers() -> None:
    with HangableProxy() as proxy:
        config = config_for(proxy.url, "closed", redis_fail_open=False)
        manager = RedisManager(config)
        limiter = RateLimitManager(config)
        await manager.initialize()
        await limiter.initialize_redis(manager)

        async def respond(status: int, message: str) -> MockGuardResponse:
            return MockGuardResponse(message, status)

        async def one() -> tuple[float, str]:
            started = monotonic()
            try:
                answer = await limiter.check_rate_limit(
                    MagicMock(), CLIENT_IP, respond, rate_limit=1000
                )
            except GuardRedisError as refused:
                return monotonic() - started, f"{refused.status_code}"
            return monotonic() - started, "ok" if answer is None else "blocked"

        assert (await one())[1] == "ok"
        proxy.hang()
        await one()
        degraded = [await one() for _ in range(10)]
        assert {outcome for _, outcome in degraded} == {"503"}
        assert max(wait for wait, _ in degraded) < BAR
        proxy.release()
        end = monotonic() + 8
        outcome = "503"
        while outcome != "ok" and monotonic() < end:
            outcome = (await one())[1]
            await asyncio.sleep(0.1)
        await manager.close()
    assert outcome == "ok"


async def test_the_request_ends_while_the_attempt_is_still_blocked(rig: Rig) -> None:
    manager = RedisManager(config_for(fake_url(), "blocked"))
    assert (await timed_get(manager))[1] == "503"
    rig.mode = "block"
    await asyncio.sleep(0.3)
    waits = [(await timed_get(manager))[0] for _ in range(5)]
    assert max(waits) < BAR
    assert await wait_until(rig.started.is_set)
    assert not manager.is_connected()
    rig.release.set()
    assert await wait_connected(manager)
    await manager.close()


async def test_a_recovered_redis_serves_again_after_the_spawned_attempt(
    rig: Rig,
) -> None:
    manager = RedisManager(config_for(fake_url(), "recovers"))
    await timed_get(manager)
    rig.mode = "ok"
    await asyncio.sleep(0.3)
    await timed_get(manager)
    assert await wait_connected(manager)
    await manager.close()


@pytest.mark.parametrize("error", [RedisConnectionError, RedisTimeoutError])
async def test_a_connection_or_timeout_error_marks_the_manager_degraded(
    rig: Rig, error: type[Exception]
) -> None:
    rig.mode = "ok"
    manager = RedisManager(config_for(fake_url(), "marks"))
    await manager.initialize()
    assert manager.is_connected()
    expected = GuardRedisError if error is RedisConnectionError else error
    with pytest.raises(expected):
        async with manager.get_connection():
            raise error("down")
    assert not manager.is_connected()
    assert rig.clients[0].closed
    gate = manager._reconnect_gate()
    assert gate._failures == 1
    assert gate.enter() is False
    await manager.close()


@pytest.mark.parametrize(
    "error",
    [
        AuthenticationError,
        BusyLoadingError,
        MaxConnectionsError,
        TimeoutError,
    ],
)
async def test_other_errors_leave_the_client_and_the_gate_alone(
    rig: Rig, error: type[Exception]
) -> None:
    rig.mode = "ok"
    manager = RedisManager(config_for(fake_url(), "others"))
    await manager.initialize()
    with pytest.raises((error, GuardRedisError)):
        async with manager.get_connection():
            raise error("not an outage")
    assert manager.is_connected()
    assert not rig.clients[0].closed
    assert manager._reconnect_gate()._failures == 0
    await manager.close()


class SwappingLock:
    """A lock whose acquisition lets another caller replace the client first."""

    def __init__(self, manager: RedisManager, replacement: MagicMock) -> None:
        self.manager = manager
        self.replacement = replacement

    async def __aenter__(self) -> None:
        self.manager._redis = self.replacement

    async def __aexit__(self, *exc_info: object) -> None:
        return None


async def test_a_client_replaced_while_the_mark_waits_for_the_lock_is_kept(
    rig: Rig,
) -> None:
    rig.mode = "ok"
    manager = RedisManager(config_for(fake_url(), "swapped"))
    await manager.initialize()
    replacement = MagicMock()
    swapping = SwappingLock(manager, replacement)
    with patch.object(manager, "_connection_lock_here", return_value=swapping):
        with pytest.raises(GuardRedisError):
            async with manager.get_connection():
                raise RedisConnectionError("late error of the old client")
    assert manager._redis is replacement
    assert not rig.clients[0].closed
    manager._redis = None


async def test_an_outage_error_while_an_attempt_holds_the_claim_records_nothing(
    rig: Rig,
) -> None:
    rig.mode = "ok"
    manager = RedisManager(config_for(fake_url(), "claimheld"))
    await manager.initialize()
    gate = manager._reconnect_gate()
    assert gate.enter()
    with pytest.raises(GuardRedisError):
        async with manager.get_connection():
            raise RedisConnectionError("down")
    assert not manager.is_connected()
    assert gate._failures == 0
    gate.leave(True)


async def test_an_interrupt_during_the_ping_closes_the_client_and_stays_degraded(
    rig: Rig,
) -> None:
    rig.mode = "stop"
    manager = RedisManager(config_for(fake_url(), "interrupt"))
    with pytest.raises(StopTheProcess):
        await manager.initialize()
    assert rig.clients[0].closed
    assert not manager.is_connected()
    assert manager._reconnect_gate()._failures == 1
    assert not manager._reconnect_gate()._claim.locked()


class BrokenHandler(RedisManager):
    async def initialize(self) -> None:
        raise RuntimeError("custom initialize broke")


async def test_a_custom_initialize_that_raises_is_logged_and_frees_the_gate(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = config_for(fake_url(), "broken")
    handler = BrokenHandler(config)
    initializer = HandlerInitializer(config, redis_handler=handler)
    initializer.bind_redis_recovery_pipeline(MagicMock(), MagicMock())
    gate = initializer._recovery_own_gate
    assert gate is not None
    assert gate.enter()
    with caplog.at_level(logging.WARNING):
        await initializer._attempt_custom_initialize(handler, gate)
    assert "Redis recovery after a cold start failed" in caplog.text
    assert not gate._claim.locked()


async def test_recovery_of_a_manager_that_is_not_degraded_connects_inline(
    rig: Rig,
) -> None:
    rig.mode = "ok"
    config = config_for(fake_url(), "plainrecover")
    manager = RedisManager(config)
    initializer = HandlerInitializer(config, redis_handler=manager)
    initializer.bind_redis_recovery_pipeline(MagicMock(), MagicMock())
    await initializer._initialize_redis_handler(manager)
    assert manager.is_connected()
    await manager.close()


async def test_a_custom_handler_spawn_that_fails_frees_the_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = config_for(fake_url(), "nospawncustom")
    handler = BrokenHandler(config)
    initializer = HandlerInitializer(config, redis_handler=handler)
    initializer.bind_redis_recovery_pipeline(MagicMock(), MagicMock())
    attempts = initializer._recovery_attempts
    assert attempts is not None

    def broken(work: Callable[[], object]) -> None:
        raise RuntimeError("cannot start")

    monkeypatch.setattr(attempts, "spawn", broken)
    with pytest.raises(RuntimeError):
        await initializer._initialize_redis_handler(handler)
    gate = initializer._recovery_own_gate
    assert gate is not None
    assert not gate._claim.locked()


async def test_a_client_bound_while_another_connect_pings_is_released(
    rig: Rig,
) -> None:
    manager = RedisManager(config_for(fake_url(), "steal"))
    rig.manager = manager
    rig.mode = "steal"
    await manager.initialize()
    assert rig.stolen.closed
    assert manager._redis is rig.clients[0]
    rig.mode = "ok"
    await manager.close()


async def test_a_spawn_that_fails_frees_the_window(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = RedisManager(config_for(fake_url(), "nospawn"))
    assert (await timed_get(manager))[1] == "503"
    await asyncio.sleep(0.3)

    def broken(work: Callable[[], object]) -> None:
        raise RuntimeError("cannot start")

    monkeypatch.setattr(manager._attempts(), "spawn", broken)
    assert (await timed_get(manager))[1] == "503"
    assert not manager._reconnect_gate()._claim.locked()


async def test_the_fork_hook_gives_every_manager_a_free_claim(rig: Rig) -> None:
    manager = RedisManager(config_for(fake_url(), "forkhook"))
    assert (await timed_get(manager))[1] == "503"
    gate = manager._reconnect_gate()
    held = gate._claim
    held.acquire()
    redis_handler_module._forget_the_parents_attempts()
    assert gate._claim is not held
    assert not gate._claim.locked()
    assert held.locked()
    assert gate._not_before == 0.0
    held.release()
    untouched = RedisManager(config_for(fake_url(), "nogate"))
    untouched._forget_the_parents_attempts()
    assert "_reconnect_gate_of_this_manager" not in vars(untouched)


async def test_a_second_error_on_a_replaced_client_does_not_discard_the_new_one(
    rig: Rig,
) -> None:
    rig.mode = "ok"
    manager = RedisManager(config_for(fake_url(), "replaced"))
    await manager.initialize()
    old = manager._redis
    with pytest.raises(GuardRedisError):
        async with manager.get_connection():
            await manager.initialize()
            assert manager._redis is not old
            raise RedisConnectionError("late error of the old client")
    assert manager.is_connected()
    await manager.close()


async def test_pool_exhaustion_with_redis_up_is_no_outage() -> None:
    config = config_for(
        REDIS_URL, "pool", redis_max_connections=1, redis_pool_timeout=0.05
    )
    manager = RedisManager(config)
    await manager.initialize()
    async with manager.get_connection() as client:
        pool = client.connection_pool
        taken = await pool.get_connection()
        refused, outcome = await timed_get(manager)
        assert outcome == "503"
        await pool.release(taken)
    assert manager.is_connected()
    assert manager._reconnect_gate()._failures == 0
    assert (await timed_get(manager))[1] == "ok"
    await manager.close()


async def ban_then_start_cold(delay: float, monkeypatch: pytest.MonkeyPatch) -> bool:
    prefix = suite_redis_prefix("ban")
    config = config_for(REDIS_URL, "ban", timeout=5.0, prefix=prefix)
    writer = RedisManager(config)
    await writer.initialize()
    banner = IPBanManager()
    banner.redis_handler = None
    await banner.reset()
    banner.config = config
    await banner.initialize_redis(writer)
    await banner.ban_ip(CLIENT_IP, 60, "outage test")
    await writer.close()

    real_open = RedisManager._open_connection

    async def slow_open(self: RedisManager, url: str) -> None:
        await asyncio.sleep(delay)
        await real_open(self, url)

    monkeypatch.setattr(RedisManager, "_open_connection", slow_open)
    fresh_config = config_for(REDIS_URL, "ban", timeout=5.0, prefix=prefix)
    reader = RedisManager(fresh_config)
    cold = IPBanManager()
    cold.redis_handler = None
    await cold.reset()
    cold.config = fresh_config
    await cold.initialize_redis(reader)
    banned = await cold.is_ip_banned(CLIENT_IP)
    await cold.unban_ip(CLIENT_IP)
    await cold.reset()
    await reader.close()
    return banned


async def test_a_ban_held_in_redis_answers_the_first_request_after_a_cold_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert await ban_then_start_cold(0.0, monkeypatch)


async def test_a_slow_healthy_connect_still_answers_the_ban_on_the_first_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert await ban_then_start_cold(0.4, monkeypatch)


async def test_close_in_the_middle_of_an_attempt_returns_and_leaves_no_client(
    rig: Rig,
) -> None:
    manager = RedisManager(config_for(fake_url(), "closing"))
    await timed_get(manager)
    rig.mode = "block"
    await asyncio.sleep(0.3)
    await timed_get(manager)
    assert await wait_until(rig.started.is_set)
    started = monotonic()
    await manager.close()
    assert monotonic() - started < 1.0
    rig.release.set()
    assert await wait_until(lambda: all(client.closed for client in rig.clients))
    assert not manager.is_connected()


async def test_two_managers_on_one_hung_url_attempt_at_most_once_per_window(
    rig: Rig,
) -> None:
    first = RedisManager(config_for(fake_url(), "twin-a"))
    second = RedisManager(config_for(fake_url(), "twin-b"))
    for manager in (first, second):
        assert (await timed_get(manager))[1] == "503"
    before = rig.pings
    end = monotonic() + 2.0
    while monotonic() < end:
        for manager in (first, second):
            assert (await timed_get(manager))[0] < BAR
        await asyncio.sleep(0.05)
    assert rig.pings - before <= 2 * 4
    for manager in (first, second):
        await manager.close()


async def test_a_manager_closed_while_its_attempt_connects_drops_the_client(
    rig: Rig,
) -> None:
    manager = RedisManager(config_for(fake_url(), "closedmid"))
    await timed_get(manager)
    rig.mode = "block"
    await asyncio.sleep(0.3)
    await timed_get(manager)
    assert await wait_until(rig.started.is_set)
    manager._closed = True
    rig.release.set()
    assert await wait_until(lambda: rig.clients[-1].closed)
    assert not manager.is_connected()
