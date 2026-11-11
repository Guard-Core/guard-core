import asyncio
import gc
import logging
import socket
import threading
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from time import monotonic
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

import pytest
import redis as redis_sync
from redis.asyncio import Redis
from redis.exceptions import RedisError

from guard_core.core.checks import factory as checks_factory
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.factory import build_default_pipeline
from guard_core.core.checks.pipeline import (
    REDIS_OUTAGE_RETRY_AFTER,
    SecurityCheckPipeline,
)
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.exceptions import GuardRedisError
from guard_core.handlers._redis_reconnect_gate import RedisReconnectGate
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.redis_handler import (
    RedisHandlerBase,
    RedisManager,
    close_redis_client,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol
from tests.async_is_connected import async_false
from tests.conftest import REDIS_URL, suite_redis_prefix

RECOVERY_CHECK = "redis_cold_start_recovery"
BANNED_IP = "203.0.113.9"


STAND_IN_PORTS: set[int] = set()


class RedisForwarder:
    """A local port that forwards to the real Redis only while it is on. Off, nothing
    listens on it, so a client gets connection refused like a Redis that is down."""

    def __init__(self) -> None:
        target = urlparse(REDIS_URL)
        self._target = (target.hostname or "127.0.0.1", target.port or 6379)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = int(probe.getsockname()[1])
        STAND_IN_PORTS.add(self.port)
        self._listener: socket.socket | None = None
        self._open: list[socket.socket] = []
        self._lock = threading.Lock()

    @property
    def url(self) -> str:
        return urlparse(REDIS_URL)._replace(netloc=f"127.0.0.1:{self.port}").geturl()

    def on(self) -> None:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self.port))
        listener.listen()
        self._listener = listener
        threading.Thread(target=self._accept, args=(listener,), daemon=True).start()

    def off(self) -> None:
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        with self._lock:
            sockets, self._open = self._open, []
        for sock in sockets:
            self._close(sock)

    def _accept(self, listener: socket.socket) -> None:
        while True:
            try:
                client, _ = listener.accept()
            except OSError:
                return
            upstream = socket.create_connection(self._target)
            with self._lock:
                self._open.extend((client, upstream))
            for source, sink in ((client, upstream), (upstream, client)):
                threading.Thread(
                    target=self._pipe, args=(source, sink), daemon=True
                ).start()

    @staticmethod
    def _close(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

    def _pipe(self, source: socket.socket, sink: socket.socket) -> None:
        try:
            while data := source.recv(65536):
                sink.sendall(data)
        except OSError:
            pass
        finally:
            self._close(source)
            self._close(sink)


class SilentServer:
    """A loopback port whose connections complete in the kernel backlog and are never
    answered: a Redis behind a partition, where the connect works and the read hangs."""

    def __init__(self) -> None:
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(128)
        self.port = int(self._listener.getsockname()[1])
        STAND_IN_PORTS.add(self.port)

    @property
    def url(self) -> str:
        return urlparse(REDIS_URL)._replace(netloc=f"127.0.0.1:{self.port}").geturl()

    def close(self) -> None:
        self._listener.close()


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Events:
    def __init__(self) -> None:
        self.actions: list[str] = []

    async def send_event(self, event: object) -> None:
        self.actions.append(str(getattr(event, "action_taken", "")))

    def count(self, action: str) -> int:
        return self.actions.count(action)


class Parked(SecurityCheck):
    """A check that records every request it sees and parks until released."""

    def __init__(
        self, middleware: GuardMiddlewareProtocol, name: str, gate: threading.Event
    ) -> None:
        super().__init__(middleware)
        self._name = name
        self._gate = gate
        self.seen: list[object] = []

    @property
    def check_name(self) -> str:
        return self._name

    async def check(self, request: object) -> None:
        self.seen.append(request)
        while not self._gate.is_set():
            await asyncio.sleep(0.01)


class Blocker(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "blocker"

    async def check(self, request: object) -> MagicMock:
        return MagicMock()


def open_sockets_to_a_stand_in() -> list[socket.socket]:
    return [
        found
        for found in gc.get_objects()
        if type(found) is socket.socket
        and found.family == socket.AF_INET
        and found.fileno() != -1
        and _peer_port(found) in STAND_IN_PORTS
    ]


def _peer_port(sock: socket.socket) -> int | None:
    try:
        return int(sock.getpeername()[1])
    except OSError:
        return None


@pytest.fixture(autouse=True)
async def no_app_leaves_a_connection_open() -> AsyncIterator[None]:
    """A manager nobody closes keeps its connection to the stand-in until the
    garbage collector finds it, and a collector that runs in a later test reports
    the open socket there as a ResourceWarning (LEDGER 6.715)."""
    yield
    while APPS:
        app = APPS.pop()
        if app.redis is not None:
            await app.redis.close()
    assert open_sockets_to_a_stand_in() == []


@pytest.fixture
def forwarder() -> Iterator[RedisForwarder]:
    forward = RedisForwarder()
    yield forward
    forward.off()


@pytest.fixture
def silent() -> Iterator[SilentServer]:
    server = SilentServer()
    yield server
    server.close()


@pytest.fixture
def clock() -> Iterator[Clock]:
    from guard_core.handlers import _redis_reconnect_gate

    fake = Clock()
    with patch.object(_redis_reconnect_gate, "monotonic", fake):
        yield fake


@pytest.fixture
def prefix() -> Iterator[str]:
    own = suite_redis_prefix("wp450")
    yield own
    client = redis_sync.Redis.from_url(REDIS_URL)
    for key in client.scan_iter(f"{own}*"):
        client.delete(key)
    client.close()


def request_of(**state: object) -> MagicMock:
    request = MagicMock()
    request.state = SimpleNamespace(**state)
    return request


def keys_under(prefix: str) -> int:
    client = redis_sync.Redis.from_url(REDIS_URL)
    count = sum(1 for _ in client.scan_iter(f"{prefix}*"))
    client.close()
    return count


def config_for(
    url: str, prefix: str, *, fail_open: bool = True, enable_redis: bool = True
) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=enable_redis,
        redis_url=url,
        redis_prefix=prefix,
        redis_fail_open=fail_open,
        enable_rate_limiting=False,
        redis_socket_connect_timeout=0.5,
        redis_socket_timeout=0.5,
        redis_retries=0,
    )


async def settle_gates(*gates: RedisReconnectGate | None) -> None:
    # A reconnect runs off the request path: the request that won the window is
    # answered at once and the attempt it started ends here, before the next call.
    end = monotonic() + 5
    while monotonic() < end and any(
        gate is not None and gate._claim.locked() for gate in gates
    ):
        await asyncio.sleep(0.01)


async def settle(manager: RedisManager) -> None:
    await settle_gates(manager._reconnect_gate())


async def serve(
    pipeline: SecurityCheckPipeline,
    initializer: HandlerInitializer,
    handler: object = None,
) -> object:
    answer = await pipeline.execute(request_of())
    manager_gate = (
        handler._reconnect_gate() if isinstance(handler, RedisManager) else None
    )
    await settle_gates(initializer._recovery_own_gate, manager_gate)
    return answer


APPS: list["App"] = []


class App:
    def __init__(self, config: SecurityConfig, with_handler: bool = True) -> None:
        APPS.append(self)
        self.config = config
        self.redis = RedisManager(config) if with_handler else None
        self.initializer = HandlerInitializer(config, redis_handler=self.redis)
        self.middleware = MagicMock()
        self.middleware.config = config
        self.middleware.logger = logging.getLogger("wp450")
        self.middleware.handler_initializer = self.initializer
        with patch.object(checks_factory, "DEFAULT_CHECK_CLASSES", ()):
            self.pipeline = build_default_pipeline(self.middleware)

    async def start(self) -> None:
        await self.initializer.initialize_redis_handlers()

    async def request(self, **state: object) -> object:
        answer = await self.pipeline.execute(request_of(**state))
        await self.settle()
        return answer

    async def settle(self) -> None:
        manager_gate = self.redis._reconnect_gate() if self.redis is not None else None
        await settle_gates(self.initializer._recovery_own_gate, manager_gate)

    async def ban(self) -> None:
        manager = ip_ban_manager_for(self.config)
        await manager.ban_ip(BANNED_IP, 60, config=self.config)

    def names(self) -> list[str]:
        return self.pipeline.get_check_names()

    def connects(self) -> MagicMock:
        assert self.redis is not None
        return MagicMock(wraps=self.redis._open_connection)


async def test_redis_is_used_after_the_retry_interval_when_it_comes_back(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    assert await app.request() is None
    await app.ban()
    assert keys_under(prefix) == 0

    forwarder.on()
    await asyncio.sleep(REDIS_OUTAGE_RETRY_AFTER + 0.3)
    assert await app.request() is None
    assert await app.request() is None

    await app.ban()
    assert keys_under(prefix) > 0
    assert app.names() == []


async def test_the_retry_interval_is_the_503_retry_after() -> None:
    from guard_core.core.initialization import _redis_cold_start_recovery
    from guard_core.handlers import _redis_reconnect_gate

    interval = _redis_cold_start_recovery.REDIS_COLD_START_RETRY_INTERVAL
    assert interval == REDIS_OUTAGE_RETRY_AFTER == 5
    assert _redis_reconnect_gate.REDIS_RECONNECT_WINDOW_SECONDS == 5


async def test_a_healthy_start_never_inserts_the_recovery_check(
    forwarder: RedisForwarder, prefix: str
) -> None:
    forwarder.on()
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    assert app.names() == []
    for _ in range(3):
        assert await app.request() is None
        assert app.names() == []
    await app.ban()
    assert keys_under(prefix) > 0


@pytest.mark.parametrize("enable_redis", [False, True])
async def test_an_app_with_redis_off_on_purpose_never_retries(
    forwarder: RedisForwarder, prefix: str, enable_redis: bool, clock: Clock
) -> None:
    config = config_for(forwarder.url, prefix, enable_redis=enable_redis)
    app = App(config, with_handler=False)
    await app.start()
    forwarder.on()
    clock.now += REDIS_OUTAGE_RETRY_AFTER * 10
    assert await app.request() is None
    assert app.names() == []
    await app.ban()
    assert keys_under(prefix) == 0


async def test_fail_closed_start_raises_and_inserts_nothing(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix, fail_open=False))
    with pytest.raises(GuardRedisError):
        await app.start()
    assert app.names() == []


async def test_a_second_failure_keeps_failing_open_and_retries_next_window(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    assert app.redis is not None
    attempts = app.connects()
    with patch.object(app.redis, "_open_connection", attempts):
        await app.start()
        assert attempts.call_count == 1
        assert app.names() == [RECOVERY_CHECK]

        assert await app.request() is None
        clock.now += 0.1
        assert await app.request() is None
        assert attempts.call_count == 1

        clock.now += 0.2
        assert await app.request() is None
        assert attempts.call_count == 2
        assert app.names() == [RECOVERY_CHECK]

        clock.now += 0.3
        assert await app.request() is None
        assert attempts.call_count == 2

        clock.now += REDIS_OUTAGE_RETRY_AFTER
        assert await app.request() is None
        assert attempts.call_count == 3
        assert app.names() == [RECOVERY_CHECK]

        forwarder.on()
        clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
        assert await app.request() is None
        assert attempts.call_count == 4
        assert await app.request() is None
        assert app.names() == []

        clock.now += REDIS_OUTAGE_RETRY_AFTER * 3
        assert await app.request() is None
        assert attempts.call_count == 4


async def test_a_held_claim_makes_the_retry_return_without_connecting(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    forwarder.on()
    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    assert app.redis is not None
    with patch.object(app.redis, "_open_connection") as connect:
        claim = app.initializer._recovery_claim
        assert claim is not None
        assert claim.acquire(blocking=False)
        assert await app.request() is None
        claim.release()
        connect.assert_not_called()


async def test_the_armed_check_is_repeated_once_the_claim_is_held(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    forwarder.on()
    with (
        patch.object(
            app.initializer, "_redis_recovery_armed", side_effect=[True, False]
        ),
        patch.object(app.initializer, "_bind_recovered_redis") as bind,
    ):
        assert await app.request() is None
    bind.assert_not_called()
    assert app.names() == [RECOVERY_CHECK]


async def test_a_disarmed_recovery_returns_before_taking_the_claim(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    forwarder.on()
    with (
        patch.object(app.initializer, "_redis_recovery_armed", return_value=False),
        patch.object(app.initializer, "_bind_recovered_redis") as bind,
    ):
        assert await app.request() is None
    bind.assert_not_called()


async def test_a_manager_another_caller_reconnected_is_bound_without_a_connect(
    forwarder: RedisForwarder,
    prefix: str,
    clock: Clock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = App(config_for(forwarder.url, prefix))
    assert app.redis is not None
    await app.start()
    forwarder.on()
    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    with (
        patch.object(
            app.initializer,
            "_initialize_connected_redis_handlers",
            side_effect=RuntimeError("setup broke"),
        ),
        caplog.at_level(logging.WARNING),
    ):
        assert await app.request() is None
        assert await app.request() is None
    assert "Redis recovery after a cold start failed" in caplog.text
    assert app.names() == [RECOVERY_CHECK]

    attempts = app.connects()
    with patch.object(app.redis, "_open_connection", attempts):
        assert await app.request() is None
        assert await app.request() is None
    attempts.assert_not_called()
    assert app.names() == []
    await app.ban()
    assert keys_under(prefix) > 0


async def test_an_unbound_initializer_arms_nothing(
    forwarder: RedisForwarder, prefix: str
) -> None:
    config = config_for(forwarder.url, prefix)
    initializer = HandlerInitializer(config, redis_handler=RedisManager(config))
    await initializer.initialize_redis_handlers()
    assert initializer._recovery_check is None


async def test_arming_twice_inserts_one_check(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    app.initializer._arm_redis_cold_start_recovery()
    assert app.names() == [RECOVERY_CHECK]


async def test_a_new_start_with_redis_back_removes_the_check(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    assert app.names() == [RECOVERY_CHECK]
    forwarder.on()
    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    await app.start()
    await app.settle()
    await app.start()
    assert app.names() == []


async def test_concurrent_requests_bind_the_handlers_once(  # async-only
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    forwarder.on()
    binds: list[int] = []
    real_setup = app.initializer._initialize_connected_redis_handlers

    async def slow_setup() -> None:
        binds.append(1)
        await asyncio.sleep(0.2)
        await real_setup()

    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    assert await app.request() is None
    with patch.object(
        app.initializer, "_initialize_connected_redis_handlers", slow_setup
    ):
        results = await asyncio.gather(*(app.request() for _ in range(20)))
    assert results == [None] * 20
    assert len(binds) == 1
    assert app.names() == []


async def test_removing_the_check_never_skips_or_repeats_one_in_flight(  # async-only
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    gate = threading.Event()
    first = Parked(app.middleware, "first", threading.Event())
    first._gate.set()
    middle = Parked(app.middleware, "middle", gate)
    app.pipeline.add_check(first)
    app.pipeline.add_check(middle)
    assert app.names() == [RECOVERY_CHECK, "first", "middle"]

    waiting = [asyncio.ensure_future(app.request()) for _ in range(10)]
    await asyncio.sleep(0.1)
    assert len(middle.seen) == 10
    app.initializer._disarm_redis_cold_start_recovery()
    assert app.names() == ["first", "middle"]
    gate.set()
    assert await asyncio.gather(*waiting) == [None] * 10
    assert len(first.seen) == 10
    assert len(set(map(id, first.seen))) == 10
    assert len(middle.seen) == 10


async def test_the_factory_binds_the_pipeline_without_adding_a_check(
    prefix: str,
) -> None:
    config = config_for("redis://127.0.0.1:1", prefix)
    initializer = HandlerInitializer(config, redis_handler=RedisManager(config))
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("wp450")
    middleware.handler_initializer = initializer
    pipeline = build_default_pipeline(middleware)
    assert RECOVERY_CHECK not in pipeline.get_check_names()
    assert isinstance(pipeline, SecurityCheckPipeline)
    assert initializer._recovery_pipeline is pipeline


async def test_a_middleware_without_an_initializer_builds_a_pipeline(
    prefix: str,
) -> None:
    config = config_for("redis://127.0.0.1:1", prefix)
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("wp450")
    middleware.handler_initializer = None
    pipeline = build_default_pipeline(middleware)
    assert RECOVERY_CHECK not in pipeline.get_check_names()


async def test_a_pipeline_rebuild_keeps_the_check_until_redis_recovers(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    with patch.object(checks_factory, "DEFAULT_CHECK_CLASSES", ()):
        app.config.rate_limit = 7
        assert await app.request() is None
        assert app.names() == [RECOVERY_CHECK]

        forwarder.on()
        clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
        assert await app.request() is None
        assert await app.request() is None
        assert app.names() == []

        app.config.rate_limit = 8
        assert await app.request() is None
        assert app.names() == []


async def test_an_arming_between_the_build_and_the_assign_of_a_rebuild_survives(
    forwarder: RedisForwarder, prefix: str
) -> None:
    forwarder.on()
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    assert app.names() == []

    def build_while_arming() -> list[SecurityCheck]:
        app.initializer._arm_redis_cold_start_recovery()
        return []

    app.config.rate_limit = 9
    with patch.object(app.pipeline, "_rebuild_checks", build_while_arming):
        app.pipeline._rebuild_if_stale()
    assert app.names() == [RECOVERY_CHECK]


async def test_a_blocked_request_alone_brings_redis_back(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    app.pipeline.add_check(Blocker(app.middleware))
    forwarder.on()
    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    assert await app.request() is not None
    assert await app.request() is not None
    assert app.names() == ["blocker"]
    await app.ban()
    assert keys_under(prefix) > 0


async def test_an_excluded_path_probe_alone_brings_redis_back(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    gate = threading.Event()
    gate.set()
    enforced_nowhere = Parked(app.middleware, "ordinary", gate)
    app.pipeline.add_check(enforced_nowhere)
    forwarder.on()
    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    assert await app.request(guard_exclusion_scoped=True) is None
    assert await app.request(guard_exclusion_scoped=True) is None
    assert enforced_nowhere.seen == []
    assert app.names() == ["ordinary"]
    await app.ban()
    assert keys_under(prefix) > 0


async def test_a_pending_ban_error_names_the_first_real_check_while_armed(
    forwarder: RedisForwarder, prefix: str, caplog: pytest.LogCaptureFixture
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    gate = threading.Event()
    gate.set()
    real = Parked(app.middleware, "first_real", gate)
    app.pipeline.add_check(real)
    assert app.pipeline.checks[0].middleware is real.middleware
    assert app.pipeline._first_real_check() is real
    app.middleware.create_error_response = AsyncMock(return_value=MagicMock())
    with (
        patch.object(
            app.pipeline, "_resolve_pending_ban", side_effect=RuntimeError("boom")
        ),
        caplog.at_level(logging.ERROR),
    ):
        assert await app.request() is not None
    assert "Error in security check first_real" in caplog.text
    assert RECOVERY_CHECK not in caplog.text


async def test_the_first_real_check_falls_back_to_the_only_check(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    assert app.pipeline._first_real_check().check_name == RECOVERY_CHECK


async def test_removing_a_check_that_is_not_there_changes_nothing(
    forwarder: RedisForwarder, prefix: str
) -> None:
    forwarder.on()
    app = App(config_for(forwarder.url, prefix))
    assert app.pipeline.remove_check("nothing") is False


async def test_a_black_hole_that_hangs_for_seconds_is_tried_once_per_5_s(
    silent: SilentServer, prefix: str, clock: Clock
) -> None:
    manager = RedisManager(config_for(silent.url, prefix))
    events = Events()
    manager.agent_handler = events
    real_open = manager._open_connection
    attempts: list[int] = []

    async def hangs_like_the_defaults(url: str) -> None:
        attempts.append(1)
        try:
            await real_open(url)
        finally:
            clock.now += 4.0

    async def call() -> None:
        with pytest.raises(GuardRedisError):
            async with manager.get_connection():
                pass
        await settle(manager)

    with patch.object(manager, "_open_connection", hangs_like_the_defaults):
        await call()
        assert (len(attempts), events.count("connection_failed")) == (1, 1)
        for step in (1.0, 1.0, 2.5):
            clock.now += step
            await call()
        assert len(attempts) == 1
        clock.now += 1.0
        await call()
        assert (len(attempts), events.count("connection_failed")) == (2, 2)
        clock.now += 1.0
        await call()
        assert (len(attempts), events.count("connection_failed")) == (2, 2)
        clock.now += 9.0
        await call()
        assert (len(attempts), events.count("connection_failed")) == (3, 3)


async def test_fail_closed_gets_its_503_fast_during_an_outage(
    silent: SilentServer, prefix: str, clock: Clock
) -> None:
    app = App(config_for(silent.url, prefix, fail_open=False))
    assert app.redis is not None
    attempts = app.connects()
    with patch.object(app.redis, "_open_connection", attempts):
        with pytest.raises(GuardRedisError):
            await app.start()
        began = monotonic()
        with pytest.raises(GuardRedisError):
            async with app.redis.get_connection():
                pass
        assert monotonic() - began < 0.1
        assert attempts.call_count == 1
        clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
        with pytest.raises(GuardRedisError):
            async with app.redis.get_connection():
                pass
        await settle(app.redis)
        assert attempts.call_count == 2


async def test_a_connected_manager_is_never_gated(
    forwarder: RedisForwarder, prefix: str
) -> None:
    forwarder.on()
    manager = RedisManager(config_for(forwarder.url, prefix))
    await manager.initialize()
    await manager.initialize()
    async with manager.get_connection() as connection:
        assert await connection.ping()
    await manager.close()


async def test_the_gate_lets_one_caller_in_and_waits_out_a_failure(
    clock: Clock,
) -> None:
    from guard_core.handlers._redis_reconnect_gate import RedisReconnectGate

    gate = RedisReconnectGate()
    assert gate.enter() is True
    assert gate.enter() is False
    gate.leave(connected=False)
    assert gate.enter() is False
    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    assert gate.enter() is True
    gate.leave(connected=True)
    assert gate.enter() is True
    gate.leave(connected=True)


async def test_the_gate_admits_exactly_one_thread() -> None:
    from guard_core.handlers._redis_reconnect_gate import RedisReconnectGate

    gate = RedisReconnectGate()
    admitted: list[bool] = []
    start = threading.Barrier(8)

    def contend() -> None:
        start.wait()
        admitted.append(gate.enter())

    threads = [threading.Thread(target=contend) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert admitted.count(True) == 1


async def test_the_window_doubles_from_a_quarter_second_up_to_5_s(
    clock: Clock,
) -> None:
    from guard_core.handlers._redis_reconnect_gate import RedisReconnectGate

    gate = RedisReconnectGate()
    for window in (0.25, 0.5, 1.0, 2.0, 4.0, 5.0, 5.0, 5.0):
        assert gate.enter() is True
        assert gate.leave(connected=False) is False
        clock.now += window - 0.01
        assert gate.enter() is False
        clock.now += 0.02
    assert gate.enter() is True
    assert gate.leave(connected=True) is True
    assert gate.enter() is True
    assert gate.leave(connected=True) is False
    assert gate.enter() is True
    gate.leave(connected=False)
    clock.now += 0.26
    assert gate.enter() is True
    gate.leave(connected=True)


async def test_a_failure_is_reported_once_per_5_s(clock: Clock) -> None:
    from guard_core.handlers._redis_reconnect_gate import RedisReconnectGate

    gate = RedisReconnectGate()
    assert gate.report_due() is True
    clock.now += 4.9
    assert gate.report_due() is False
    clock.now += 0.2
    assert gate.report_due() is True


async def test_a_long_attempt_waits_twice_as_long_up_to_5_s(clock: Clock) -> None:
    from guard_core.handlers._redis_reconnect_gate import RedisReconnectGate

    gate = RedisReconnectGate()
    assert gate.enter() is True
    clock.now += 1.0
    gate.leave(connected=False)
    clock.now += 1.9
    assert gate.enter() is False
    clock.now += 0.2
    assert gate.enter() is True
    clock.now += 4.0
    gate.leave(connected=False)
    clock.now += 4.9
    assert gate.enter() is False
    clock.now += 0.2
    assert gate.enter() is True


async def test_a_refused_outage_held_30_s_is_tried_at_most_12_times_and_reported_7(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    manager = RedisManager(config_for(forwarder.url, prefix))
    events = Events()
    manager.agent_handler = events
    attempts = MagicMock(wraps=manager._open_connection)
    with patch.object(manager, "_open_connection", attempts):
        for _ in range(300):
            with pytest.raises(GuardRedisError):
                async with manager.get_connection():
                    pass
            await settle(manager)
            clock.now += 0.1
    assert 8 <= attempts.call_count <= 12
    assert 1 <= events.count("connection_failed") <= 7


async def test_a_fail_closed_blip_serves_within_half_a_second_of_the_restore(
    forwarder: RedisForwarder, prefix: str
) -> None:
    manager = RedisManager(config_for(forwarder.url, prefix, fail_open=False))
    with pytest.raises(GuardRedisError):
        async with manager.get_connection():
            pass
    await asyncio.sleep(0.1)
    forwarder.on()
    restored = monotonic()
    served = None
    while monotonic() - restored < 2.0:
        try:
            async with manager.get_connection() as connection:
                assert await connection.ping()
            served = monotonic() - restored
            break
        except GuardRedisError:
            await asyncio.sleep(0.05)
    assert served is not None and served < 0.5
    await manager.close()


async def test_a_fail_open_blip_writes_keys_on_the_first_attempt_after_the_first_window(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    # The first window after a failed attempt is 0.25 s, so a Redis that is back
    # inside it is reached by the first attempt after it and by no other. Counted
    # in attempts on the gate's clock, not in wall time: a loaded host that
    # stretches a sleep must not read as a slow recovery.
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    assert await app.request() is None
    forwarder.on()
    attempts = app.connects()
    with patch.object(app.redis, "_open_connection", attempts):
        clock.now += 0.24
        assert await app.request() is None
        await app.ban()
        assert attempts.call_count == 0
        assert keys_under(prefix) == 0
        clock.now += 0.02
        assert await app.request() is None
        assert await app.request() is None
        await app.ban()
    assert attempts.call_count == 1
    assert keys_under(prefix) > 0
    assert app.names() == []


class SuperCallingHandler(RedisHandlerBase):
    initialize_calls = 0

    async def initialize(self) -> None:
        type(self).initialize_calls += 1
        await super().initialize()


async def test_a_super_calling_handler_is_asked_once_per_window_and_connects(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    SuperCallingHandler.initialize_calls = 0
    config = config_for(forwarder.url, prefix)
    handler = SuperCallingHandler(config)
    initializer = HandlerInitializer(config, redis_handler=handler)
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("wp450")
    middleware.handler_initializer = initializer
    with patch.object(checks_factory, "DEFAULT_CHECK_CLASSES", ()):
        pipeline = build_default_pipeline(middleware)
    await initializer.initialize_redis_handlers()
    assert SuperCallingHandler.initialize_calls == 1
    assert pipeline.get_check_names() == [RECOVERY_CHECK]

    for _ in range(300):
        assert await serve(pipeline, initializer, handler) is None
        clock.now += 0.1
    assert 8 <= SuperCallingHandler.initialize_calls <= 13
    assert pipeline.get_check_names() == [RECOVERY_CHECK]

    forwarder.on()
    for _ in range(80):
        assert await serve(pipeline, initializer, handler) is None
        clock.now += 0.1
        if not pipeline.get_check_names():
            break
    assert pipeline.get_check_names() == []
    manager = ip_ban_manager_for(config)
    await manager.ban_ip(BANNED_IP, 60, config=config)
    assert keys_under(prefix) > 0
    await handler.close()


async def test_a_recovered_connection_sends_one_recovered_event(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    manager = RedisManager(config_for(forwarder.url, prefix))
    events = Events()
    manager.agent_handler = events
    with pytest.raises(GuardRedisError):
        async with manager.get_connection():
            pass
    forwarder.on()
    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    with pytest.raises(GuardRedisError):
        async with manager.get_connection():
            pass
    await settle(manager)
    async with manager.get_connection() as connection:
        assert await connection.ping()
    assert events.count("connection_recovered") == 1
    assert events.count("connection_established") == 1
    await manager.close()

    first_try = RedisManager(config_for(forwarder.url, prefix + "x:"))
    fresh = Events()
    first_try.agent_handler = fresh
    await first_try.initialize()
    assert fresh.count("connection_recovered") == 0
    await first_try.close()


class SwallowingHandler(RedisHandlerBase):
    initialize_calls = 0
    swallow = False

    async def initialize(self) -> None:
        type(self).initialize_calls += 1
        try:
            await super().initialize()
        except GuardRedisError:
            if not type(self).swallow:
                raise


async def test_an_initialize_that_swallows_the_failure_keeps_the_backoff(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    SwallowingHandler.initialize_calls = 0
    SwallowingHandler.swallow = False
    config = config_for(forwarder.url, prefix)
    handler = SwallowingHandler(config)
    initializer = HandlerInitializer(config, redis_handler=handler)
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("wp450")
    middleware.handler_initializer = initializer
    with patch.object(checks_factory, "DEFAULT_CHECK_CLASSES", ()):
        pipeline = build_default_pipeline(middleware)
    await initializer.initialize_redis_handlers()
    SwallowingHandler.swallow = True
    for _ in range(300):
        assert await serve(pipeline, initializer, handler) is None
        clock.now += 0.1
    assert 8 <= SwallowingHandler.initialize_calls <= 13
    assert pipeline.get_check_names() == [RECOVERY_CHECK]

    forwarder.on()
    for _ in range(80):
        assert await serve(pipeline, initializer, handler) is None
        clock.now += 0.1
        if not pipeline.get_check_names():
            break
    assert pipeline.get_check_names() == []
    await handler.close()


async def test_a_second_outage_after_a_recovery_reports_its_first_failure(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    manager = RedisManager(config_for(forwarder.url, prefix))
    events = Events()
    manager.agent_handler = events

    async def refused() -> None:
        with pytest.raises(GuardRedisError):
            async with manager.get_connection():
                pass

    await refused()
    assert events.count("connection_failed") == 1
    forwarder.on()
    clock.now += 0.3
    with pytest.raises(GuardRedisError):
        async with manager.get_connection():
            pass
    await settle(manager)
    async with manager.get_connection() as connection:
        assert await connection.ping()
    forwarder.off()
    await manager._discard_client()
    clock.now += 0.8
    await refused()
    assert events.count("connection_failed") == 2
    assert events.count("connection_recovered") == 1


async def test_a_second_outage_within_5_s_of_a_recovery_is_reported(
    clock: Clock,
) -> None:
    from guard_core.handlers._redis_reconnect_gate import RedisReconnectGate

    gate = RedisReconnectGate()
    assert gate.enter() is True
    assert gate.report_due() is True
    gate.leave(connected=False)
    clock.now += 0.3
    assert gate.enter() is True
    gate.leave(connected=True)
    clock.now += 0.8
    assert gate.enter() is True
    assert gate.report_due() is True
    gate.leave(connected=False)


class OtherAttributeClientHandler(RedisHandlerBase):
    """Keeps its client under ``_client`` and answers ``is_connected`` itself."""

    def __init__(self, config: SecurityConfig, url: str) -> None:
        self.config = config
        self._url = url
        self._client: Redis | None = None

    async def initialize(self) -> None:
        client = Redis.from_url(
            self._url, decode_responses=True, socket_connect_timeout=0.5
        )
        try:
            await client.ping()
        except RedisError as error:
            await close_redis_client(client)
            raise GuardRedisError(503, "Redis connection failed") from error
        await self.close()
        self._client = client

    @asynccontextmanager
    async def get_connection(self) -> AsyncIterator[Redis]:
        assert self._client is not None
        yield self._client

    def is_connected(self) -> bool:
        return self._client is not None

    async def close(self) -> None:
        if self._client is not None:
            await close_redis_client(self._client)


async def test_a_handler_with_its_client_elsewhere_recovers_through_is_connected(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    config = config_for(forwarder.url, prefix)
    handler = OtherAttributeClientHandler(config, forwarder.url)
    initializer = HandlerInitializer(config, redis_handler=handler)
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("wp456")
    middleware.handler_initializer = initializer
    with patch.object(checks_factory, "DEFAULT_CHECK_CLASSES", ()):
        pipeline = build_default_pipeline(middleware)
    await initializer.initialize_redis_handlers()
    assert pipeline.get_check_names() == [RECOVERY_CHECK]
    assert handler.is_connected() is False

    forwarder.on()
    for _ in range(80):
        assert await serve(pipeline, initializer, handler) is None
        clock.now += 0.1
        if not pipeline.get_check_names():
            break
    assert pipeline.get_check_names() == []
    assert handler.is_connected() is True
    await ip_ban_manager_for(config).ban_ip(BANNED_IP, 60, config=config)
    assert keys_under(prefix) > 0
    await handler.close()


class WithoutIsConnectedHandler(RedisHandlerBase):
    """A handler whose only connection state is ``_redis``: no ``is_connected``.

    Its own ``initialize`` keeps recovery on the path that reads state."""

    async def initialize(self) -> None:
        await super().initialize()

    def __getattribute__(self, name: str) -> object:
        if name == "is_connected":
            raise AttributeError(name)
        return super().__getattribute__(name)


async def test_a_handler_with_only_redis_attribute_starts_clean_and_recovers(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    config = config_for(forwarder.url, prefix)
    assert config.fail_on_misconfiguration is True
    handler = WithoutIsConnectedHandler(config)
    assert not hasattr(handler, "is_connected")
    initializer = HandlerInitializer(config, redis_handler=handler)
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("wp456")
    middleware.handler_initializer = initializer
    with patch.object(checks_factory, "DEFAULT_CHECK_CLASSES", ()):
        pipeline = build_default_pipeline(middleware)
    await initializer.initialize_redis_handlers()
    assert pipeline.get_check_names() == [RECOVERY_CHECK]

    forwarder.on()
    for _ in range(80):
        assert await serve(pipeline, initializer, handler) is None
        clock.now += 0.1
        if not pipeline.get_check_names():
            break
    assert pipeline.get_check_names() == []
    await ip_ban_manager_for(config).ban_ip(BANNED_IP, 60, config=config)
    assert keys_under(prefix) > 0
    await handler.close()


async def test_the_redis_manager_reports_is_connected_from_its_client(
    forwarder: RedisForwarder, prefix: str
) -> None:
    manager = RedisManager(config_for(forwarder.url, prefix))
    assert manager.is_connected() is False
    forwarder.on()
    await manager.initialize()
    assert manager.is_connected() is True
    await manager.close()
    assert manager.is_connected() is False


class AsyncIsConnectedHandler(OtherAttributeClientHandler):
    """Answers ``is_connected`` with a coroutine, which the engine never awaits."""

    def __getattribute__(self, name: str) -> object:
        if name == "is_connected":
            return async_false
        return super().__getattribute__(name)


async def test_an_async_is_connected_never_reads_as_connected(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    config = config_for(forwarder.url, prefix).model_copy(
        update={"fail_on_misconfiguration": False}
    )
    handler = AsyncIsConnectedHandler(config, forwarder.url)
    initializer = HandlerInitializer(config, redis_handler=handler)
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("wp456")
    middleware.handler_initializer = initializer
    with patch.object(checks_factory, "DEFAULT_CHECK_CLASSES", ()):
        pipeline = build_default_pipeline(middleware)
    await initializer.initialize_redis_handlers()
    assert pipeline.get_check_names() == [RECOVERY_CHECK]

    forwarder.on()
    for _ in range(20):
        assert await pipeline.execute(request_of()) is None
        clock.now += 0.5
    gc.collect()
    assert pipeline.get_check_names() == [RECOVERY_CHECK]
    await settle_gates(initializer._recovery_own_gate)
    await handler.close()


class CountingHandler(OtherAttributeClientHandler):
    initialize_calls = 0

    async def initialize(self) -> None:
        type(self).initialize_calls += 1
        await super().initialize()


async def test_a_handler_that_reports_connected_is_bound_without_initialize(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    CountingHandler.initialize_calls = 0
    config = config_for(forwarder.url, prefix)
    handler = CountingHandler(config, forwarder.url)
    initializer = HandlerInitializer(config, redis_handler=handler)
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("wp456")
    middleware.handler_initializer = initializer
    with patch.object(checks_factory, "DEFAULT_CHECK_CLASSES", ()):
        pipeline = build_default_pipeline(middleware)
    await initializer.initialize_redis_handlers()
    assert pipeline.get_check_names() == [RECOVERY_CHECK]
    assert CountingHandler.initialize_calls == 1

    forwarder.on()
    await handler.initialize()
    assert handler.is_connected() is True
    assert CountingHandler.initialize_calls == 2
    clock.now += 10
    assert await pipeline.execute(request_of()) is None
    assert pipeline.get_check_names() == []
    assert CountingHandler.initialize_calls == 2
    await settle_gates(initializer._recovery_own_gate)
    await handler.close()


class ClientAnsweringHandler(CountingHandler):
    """Answers ``is_connected`` with its client object, which is truthy."""

    def __getattribute__(self, name: str) -> object:
        if name == "is_connected":
            return super().__getattribute__("_client_or_none")
        return super().__getattribute__(name)

    def _client_or_none(self) -> object:
        return self._client


async def test_a_truthy_client_answer_from_is_connected_is_bound_without_initialize(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    ClientAnsweringHandler.initialize_calls = 0
    config = config_for(forwarder.url, prefix)
    handler = ClientAnsweringHandler(config, forwarder.url)
    initializer = HandlerInitializer(config, redis_handler=handler)
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("wp456")
    middleware.handler_initializer = initializer
    with patch.object(checks_factory, "DEFAULT_CHECK_CLASSES", ()):
        pipeline = build_default_pipeline(middleware)
    await initializer.initialize_redis_handlers()
    assert pipeline.get_check_names() == [RECOVERY_CHECK]

    forwarder.on()
    await handler.initialize()
    assert ClientAnsweringHandler.initialize_calls == 2
    clock.now += 10
    assert await pipeline.execute(request_of()) is None
    assert pipeline.get_check_names() == []
    assert ClientAnsweringHandler.initialize_calls == 2
    await settle_gates(initializer._recovery_own_gate)
    await handler.close()
