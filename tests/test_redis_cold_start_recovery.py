import asyncio
import logging
import socket
import threading
from collections.abc import Iterator
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

import pytest
import redis as redis_sync

from guard_core.core.checks import factory as checks_factory
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.factory import build_default_pipeline
from guard_core.core.checks.pipeline import (
    REDIS_OUTAGE_RETRY_AFTER,
    SecurityCheckPipeline,
)
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol
from tests.conftest import REDIS_URL, suite_redis_prefix

RECOVERY_CHECK = "redis_cold_start_recovery"
BANNED_IP = "203.0.113.9"


class RedisForwarder:
    """A local port that forwards to the real Redis only while it is on. Off, nothing
    listens on it, so a client gets connection refused like a Redis that is down."""

    def __init__(self) -> None:
        target = urlparse(REDIS_URL)
        self._target = (target.hostname or "127.0.0.1", target.port or 6379)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = int(probe.getsockname()[1])
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


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


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


@pytest.fixture
def forwarder() -> Iterator[RedisForwarder]:
    forward = RedisForwarder()
    yield forward
    forward.off()


@pytest.fixture
def clock() -> Iterator[Clock]:
    from guard_core.core.initialization import _redis_cold_start_recovery

    fake = Clock()
    with patch.object(_redis_cold_start_recovery, "monotonic", fake):
        yield fake


@pytest.fixture
def prefix() -> Iterator[str]:
    own = suite_redis_prefix("wp450")
    yield own
    client = redis_sync.Redis.from_url(REDIS_URL)
    for key in client.scan_iter(f"{own}*"):
        client.delete(key)
    client.close()


def request_of() -> MagicMock:
    request = MagicMock()
    request.state = SimpleNamespace()
    return request


def keys_under(prefix: str) -> int:
    client = redis_sync.Redis.from_url(REDIS_URL)
    count = sum(1 for _ in client.scan_iter(f"{prefix}*"))
    client.close()
    return count


class App:
    def __init__(self, config: SecurityConfig, with_handler: bool = True) -> None:
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

    async def request(self) -> object:
        return await self.pipeline.execute(request_of())

    async def ban(self) -> None:
        manager = ip_ban_manager_for(self.config)
        await manager.ban_ip(BANNED_IP, 60, config=self.config)

    def names(self) -> list[str]:
        return self.pipeline.get_check_names()


def config_for(
    url: str, prefix: str, *, fail_open: bool = True, enable_redis: bool = True
) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=enable_redis,
        redis_url=url,
        redis_prefix=prefix,
        redis_fail_open=fail_open,
        enable_rate_limiting=False,
    )


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

    await app.ban()
    assert keys_under(prefix) > 0


async def test_the_retry_interval_is_the_503_retry_after() -> None:
    from guard_core.core.initialization import _redis_cold_start_recovery

    interval = _redis_cold_start_recovery.REDIS_COLD_START_RETRY_INTERVAL
    assert interval == REDIS_OUTAGE_RETRY_AFTER == 5


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


async def test_a_second_failure_keeps_failing_open_and_retries_next_interval(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    assert app.redis is not None
    attempts = MagicMock(wraps=app.redis.initialize)
    with patch.object(app.redis, "initialize", attempts):
        await app.start()
        assert attempts.call_count == 1

        assert await app.request() is None
        assert attempts.call_count == 1

        clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
        assert await app.request() is None
        assert attempts.call_count == 2
        assert app.names() == [RECOVERY_CHECK]

        clock.now += 1
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
        assert app.names() == []

        clock.now += REDIS_OUTAGE_RETRY_AFTER * 3
        assert await app.request() is None
        assert attempts.call_count == 4


async def test_a_busy_retry_does_not_queue_another_one(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    forwarder.on()
    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    with patch.object(app.initializer, "_connect_redis") as connect:
        async with app.initializer._recovery_lock:
            assert await app.request() is None
        connect.assert_not_called()


async def test_the_due_check_is_repeated_once_the_lock_is_held(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    forwarder.on()
    with (
        patch.object(app.initializer, "_redis_recovery_due", side_effect=[True, False]),
        patch.object(app.initializer, "_connect_redis") as connect,
    ):
        assert await app.request() is None
    connect.assert_not_called()
    assert app.names() == [RECOVERY_CHECK]


async def test_a_failing_handler_setup_is_logged_and_retried_later(
    forwarder: RedisForwarder,
    prefix: str,
    clock: Clock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    forwarder.on()
    with (
        patch.object(
            app.initializer,
            "_initialize_connected_redis_handlers",
            side_effect=RuntimeError("setup broke"),
        ),
        caplog.at_level(logging.WARNING),
    ):
        clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
        assert await app.request() is None
    assert "Redis recovery after a cold start failed" in caplog.text
    assert app.names() == [RECOVERY_CHECK]

    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    assert await app.request() is None
    assert app.names() == []


async def test_an_unbound_initializer_arms_nothing(
    forwarder: RedisForwarder, prefix: str
) -> None:
    config = config_for(forwarder.url, prefix)
    initializer = HandlerInitializer(config, redis_handler=RedisManager(config))
    await initializer.initialize_redis_handlers()
    assert initializer._recovery_check is None


async def test_arming_twice_inserts_one_check(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    await app.start()
    assert app.names() == [RECOVERY_CHECK]


async def test_a_new_start_with_redis_back_removes_the_check(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    assert app.names() == [RECOVERY_CHECK]
    forwarder.on()
    await app.start()
    assert app.names() == []


async def test_concurrent_requests_set_the_handlers_up_once(  # async-only
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    forwarder.on()
    setups: list[int] = []
    real_setup = app.initializer._initialize_connected_redis_handlers

    async def slow_setup() -> None:
        setups.append(1)
        await asyncio.sleep(0.2)
        await real_setup()

    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    with patch.object(
        app.initializer, "_initialize_connected_redis_handlers", slow_setup
    ):
        results = await asyncio.gather(*(app.request() for _ in range(20)))
    assert results == [None] * 20
    assert len(setups) == 1
    assert app.names() == []


async def test_removing_the_last_check_never_skips_or_repeats_one(  # async-only
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix))
    await app.start()
    gate = threading.Event()
    first = Parked(app.middleware, "first", threading.Event())
    first._gate.set()
    middle = Parked(app.middleware, "middle", gate)
    app.pipeline.insert_check(0, first)
    app.pipeline.insert_check(1, middle)
    assert app.names() == ["first", "middle", RECOVERY_CHECK]

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
        assert app.names() == []

        app.config.rate_limit = 8
        assert await app.request() is None
        assert app.names() == []
