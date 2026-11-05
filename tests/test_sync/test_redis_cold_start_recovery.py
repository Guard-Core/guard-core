import logging
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from time import monotonic
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

import pytest
import redis as redis_sync
from redis import Redis
from redis.exceptions import RedisError

from guard_core.exceptions import GuardRedisError
from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks import factory as checks_factory
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.core.checks.pipeline import (
    REDIS_OUTAGE_RETRY_AFTER,
    SecurityCheckPipeline,
)
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from guard_core.sync.handlers.redis_handler import (
    RedisHandlerBase,
    RedisManager,
    close_redis_client,
)
from guard_core.sync.protocols.middleware_protocol import SyncGuardMiddlewareProtocol
from tests.test_sync.conftest import REDIS_URL, suite_redis_prefix

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


class SilentServer:
    """A loopback port whose connections complete in the kernel backlog and are never
    answered: a Redis behind a partition, where the connect works and the read hangs."""

    def __init__(self) -> None:
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(128)
        self.port = int(self._listener.getsockname()[1])

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

    def send_event(self, event: object) -> None:
        self.actions.append(str(getattr(event, "action_taken", "")))

    def count(self, action: str) -> int:
        return self.actions.count(action)


class Parked(SecurityCheck):
    """A check that records every request it sees and parks until released."""

    def __init__(
        self, middleware: SyncGuardMiddlewareProtocol, name: str, gate: threading.Event
    ) -> None:
        super().__init__(middleware)
        self._name = name
        self._gate = gate
        self.seen: list[object] = []

    @property
    def check_name(self) -> str:
        return self._name

    def check(self, request: object) -> None:
        self.seen.append(request)
        while not self._gate.is_set():
            time.sleep(0.01)


class Blocker(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "blocker"

    def check(self, request: object) -> MagicMock:
        return MagicMock()


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
    from guard_core.sync.handlers import _redis_reconnect_gate

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
) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=enable_redis,
        redis_url=url,
        redis_prefix=prefix,
        redis_fail_open=fail_open,
        enable_rate_limiting=False,
        redis_socket_connect_timeout=0.5,
        redis_socket_timeout=0.5,
        redis_retries=0,
    )


class App:
    def __init__(self, config: SyncSecurityConfig, with_handler: bool = True) -> None:
        self.config = config
        self.redis = RedisManager(config) if with_handler else None
        self.initializer = HandlerInitializer(config, redis_handler=self.redis)
        self.middleware = MagicMock()
        self.middleware.config = config
        self.middleware.logger = logging.getLogger("wp450")
        self.middleware.handler_initializer = self.initializer
        with patch.object(checks_factory, "DEFAULT_CHECK_CLASSES", ()):
            self.pipeline = build_default_pipeline(self.middleware)

    def start(self) -> None:
        self.initializer.initialize_redis_handlers()

    def request(self, **state: object) -> object:
        return self.pipeline.execute(request_of(**state))

    def ban(self) -> None:
        manager = ip_ban_manager_for(self.config)
        manager.ban_ip(BANNED_IP, 60, config=self.config)

    def names(self) -> list[str]:
        return self.pipeline.get_check_names()

    def connects(self) -> MagicMock:
        assert self.redis is not None
        return MagicMock(wraps=self.redis._open_connection)


def test_redis_is_used_after_the_retry_interval_when_it_comes_back(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix))
    app.start()
    assert app.request() is None
    app.ban()
    assert keys_under(prefix) == 0

    forwarder.on()
    time.sleep(REDIS_OUTAGE_RETRY_AFTER + 0.3)
    assert app.request() is None

    app.ban()
    assert keys_under(prefix) > 0
    assert app.names() == []


def test_the_retry_interval_is_the_503_retry_after() -> None:
    from guard_core.sync.core.initialization import _redis_cold_start_recovery
    from guard_core.sync.handlers import _redis_reconnect_gate

    interval = _redis_cold_start_recovery.REDIS_COLD_START_RETRY_INTERVAL
    assert interval == REDIS_OUTAGE_RETRY_AFTER == 5
    assert _redis_reconnect_gate.REDIS_RECONNECT_WINDOW_SECONDS == 5


def test_a_healthy_start_never_inserts_the_recovery_check(
    forwarder: RedisForwarder, prefix: str
) -> None:
    forwarder.on()
    app = App(config_for(forwarder.url, prefix))
    app.start()
    assert app.names() == []
    for _ in range(3):
        assert app.request() is None
        assert app.names() == []
    app.ban()
    assert keys_under(prefix) > 0


@pytest.mark.parametrize("enable_redis", [False, True])
def test_an_app_with_redis_off_on_purpose_never_retries(
    forwarder: RedisForwarder, prefix: str, enable_redis: bool, clock: Clock
) -> None:
    config = config_for(forwarder.url, prefix, enable_redis=enable_redis)
    app = App(config, with_handler=False)
    app.start()
    forwarder.on()
    clock.now += REDIS_OUTAGE_RETRY_AFTER * 10
    assert app.request() is None
    assert app.names() == []
    app.ban()
    assert keys_under(prefix) == 0


def test_fail_closed_start_raises_and_inserts_nothing(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix, fail_open=False))
    with pytest.raises(GuardRedisError):
        app.start()
    assert app.names() == []


def test_a_second_failure_keeps_failing_open_and_retries_next_window(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    assert app.redis is not None
    attempts = app.connects()
    with patch.object(app.redis, "_open_connection", attempts):
        app.start()
        assert attempts.call_count == 1
        assert app.names() == [RECOVERY_CHECK]

        assert app.request() is None
        clock.now += 0.1
        assert app.request() is None
        assert attempts.call_count == 1

        clock.now += 0.2
        assert app.request() is None
        assert attempts.call_count == 2
        assert app.names() == [RECOVERY_CHECK]

        clock.now += 0.3
        assert app.request() is None
        assert attempts.call_count == 2

        clock.now += REDIS_OUTAGE_RETRY_AFTER
        assert app.request() is None
        assert attempts.call_count == 3
        assert app.names() == [RECOVERY_CHECK]

        forwarder.on()
        clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
        assert app.request() is None
        assert attempts.call_count == 4
        assert app.names() == []

        clock.now += REDIS_OUTAGE_RETRY_AFTER * 3
        assert app.request() is None
        assert attempts.call_count == 4


def test_a_held_claim_makes_the_retry_return_without_connecting(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    app.start()
    forwarder.on()
    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    assert app.redis is not None
    with patch.object(app.redis, "_open_connection") as connect:
        claim = app.initializer._recovery_claim
        assert claim is not None
        assert claim.acquire(blocking=False)
        assert app.request() is None
        claim.release()
        connect.assert_not_called()


def test_the_armed_check_is_repeated_once_the_claim_is_held(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix))
    app.start()
    forwarder.on()
    with (
        patch.object(
            app.initializer, "_redis_recovery_armed", side_effect=[True, False]
        ),
        patch.object(app.initializer, "_bind_recovered_redis") as bind,
    ):
        assert app.request() is None
    bind.assert_not_called()
    assert app.names() == [RECOVERY_CHECK]


def test_a_disarmed_recovery_returns_before_taking_the_claim(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix))
    app.start()
    forwarder.on()
    with (
        patch.object(app.initializer, "_redis_recovery_armed", return_value=False),
        patch.object(app.initializer, "_bind_recovered_redis") as bind,
    ):
        assert app.request() is None
    bind.assert_not_called()


def test_a_manager_another_caller_reconnected_is_bound_without_a_connect(
    forwarder: RedisForwarder,
    prefix: str,
    clock: Clock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = App(config_for(forwarder.url, prefix))
    assert app.redis is not None
    app.start()
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
        assert app.request() is None
    assert "Redis recovery after a cold start failed" in caplog.text
    assert app.names() == [RECOVERY_CHECK]

    attempts = app.connects()
    with patch.object(app.redis, "_open_connection", attempts):
        assert app.request() is None
        assert app.request() is None
    attempts.assert_not_called()
    assert app.names() == []
    app.ban()
    assert keys_under(prefix) > 0


def test_an_unbound_initializer_arms_nothing(
    forwarder: RedisForwarder, prefix: str
) -> None:
    config = config_for(forwarder.url, prefix)
    initializer = HandlerInitializer(config, redis_handler=RedisManager(config))
    initializer.initialize_redis_handlers()
    assert initializer._recovery_check is None


def test_arming_twice_inserts_one_check(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    app.start()
    app.initializer._arm_redis_cold_start_recovery()
    assert app.names() == [RECOVERY_CHECK]


def test_a_new_start_with_redis_back_removes_the_check(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    app.start()
    assert app.names() == [RECOVERY_CHECK]
    forwarder.on()
    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    app.start()
    assert app.names() == []


def test_the_factory_binds_the_pipeline_without_adding_a_check(
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


def test_a_middleware_without_an_initializer_builds_a_pipeline(
    prefix: str,
) -> None:
    config = config_for("redis://127.0.0.1:1", prefix)
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("wp450")
    middleware.handler_initializer = None
    pipeline = build_default_pipeline(middleware)
    assert RECOVERY_CHECK not in pipeline.get_check_names()


def test_a_pipeline_rebuild_keeps_the_check_until_redis_recovers(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    app.start()
    with patch.object(checks_factory, "DEFAULT_CHECK_CLASSES", ()):
        app.config.rate_limit = 7
        assert app.request() is None
        assert app.names() == [RECOVERY_CHECK]

        forwarder.on()
        clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
        assert app.request() is None
        assert app.names() == []

        app.config.rate_limit = 8
        assert app.request() is None
        assert app.names() == []


def test_an_arming_between_the_build_and_the_assign_of_a_rebuild_survives(
    forwarder: RedisForwarder, prefix: str
) -> None:
    forwarder.on()
    app = App(config_for(forwarder.url, prefix))
    app.start()
    assert app.names() == []

    def build_while_arming() -> list[SecurityCheck]:
        app.initializer._arm_redis_cold_start_recovery()
        return []

    app.config.rate_limit = 9
    with patch.object(app.pipeline, "_rebuild_checks", build_while_arming):
        app.pipeline._rebuild_if_stale()
    assert app.names() == [RECOVERY_CHECK]


def test_a_blocked_request_alone_brings_redis_back(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    app.start()
    app.pipeline.add_check(Blocker(app.middleware))
    forwarder.on()
    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    assert app.request() is not None
    assert app.names() == ["blocker"]
    app.ban()
    assert keys_under(prefix) > 0


def test_an_excluded_path_probe_alone_brings_redis_back(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    app = App(config_for(forwarder.url, prefix))
    app.start()
    gate = threading.Event()
    gate.set()
    enforced_nowhere = Parked(app.middleware, "ordinary", gate)
    app.pipeline.add_check(enforced_nowhere)
    forwarder.on()
    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    assert app.request(guard_exclusion_scoped=True) is None
    assert enforced_nowhere.seen == []
    assert app.names() == ["ordinary"]
    app.ban()
    assert keys_under(prefix) > 0


def test_a_pending_ban_error_names_the_first_real_check_while_armed(
    forwarder: RedisForwarder, prefix: str, caplog: pytest.LogCaptureFixture
) -> None:
    app = App(config_for(forwarder.url, prefix))
    app.start()
    gate = threading.Event()
    gate.set()
    real = Parked(app.middleware, "first_real", gate)
    app.pipeline.add_check(real)
    assert app.pipeline.checks[0].middleware is real.middleware
    assert app.pipeline._first_real_check() is real
    app.middleware.create_error_response = MagicMock(return_value=MagicMock())
    with (
        patch.object(
            app.pipeline, "_resolve_pending_ban", side_effect=RuntimeError("boom")
        ),
        caplog.at_level(logging.ERROR),
    ):
        assert app.request() is not None
    assert "Error in security check first_real" in caplog.text
    assert RECOVERY_CHECK not in caplog.text


def test_the_first_real_check_falls_back_to_the_only_check(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix))
    app.start()
    assert app.pipeline._first_real_check().check_name == RECOVERY_CHECK


def test_removing_a_check_that_is_not_there_changes_nothing(
    forwarder: RedisForwarder, prefix: str
) -> None:
    forwarder.on()
    app = App(config_for(forwarder.url, prefix))
    assert app.pipeline.remove_check("nothing") is False


def test_a_black_hole_that_hangs_for_seconds_is_tried_once_per_5_s(
    silent: SilentServer, prefix: str, clock: Clock
) -> None:
    manager = RedisManager(config_for(silent.url, prefix))
    events = Events()
    manager.agent_handler = events
    real_open = manager._open_connection
    attempts: list[int] = []

    def hangs_like_the_defaults(url: str) -> None:
        attempts.append(1)
        try:
            real_open(url)
        finally:
            clock.now += 4.0

    def call() -> None:
        with pytest.raises(GuardRedisError):
            with manager.get_connection():
                pass

    with patch.object(manager, "_open_connection", hangs_like_the_defaults):
        call()
        assert (len(attempts), events.count("connection_failed")) == (1, 1)
        for step in (1.0, 1.0, 2.5):
            clock.now += step
            call()
        assert len(attempts) == 1
        clock.now += 1.0
        call()
        assert (len(attempts), events.count("connection_failed")) == (2, 2)
        clock.now += 1.0
        call()
        assert (len(attempts), events.count("connection_failed")) == (2, 2)
        clock.now += 9.0
        call()
        assert (len(attempts), events.count("connection_failed")) == (3, 3)


def test_fail_closed_gets_its_503_fast_during_an_outage(
    silent: SilentServer, prefix: str, clock: Clock
) -> None:
    app = App(config_for(silent.url, prefix, fail_open=False))
    assert app.redis is not None
    attempts = app.connects()
    with patch.object(app.redis, "_open_connection", attempts):
        with pytest.raises(GuardRedisError):
            app.start()
        began = monotonic()
        with pytest.raises(GuardRedisError):
            with app.redis.get_connection():
                pass
        assert monotonic() - began < 0.1
        assert attempts.call_count == 1
        clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
        with pytest.raises(GuardRedisError):
            with app.redis.get_connection():
                pass
        assert attempts.call_count == 2


def test_a_connected_manager_is_never_gated(
    forwarder: RedisForwarder, prefix: str
) -> None:
    forwarder.on()
    manager = RedisManager(config_for(forwarder.url, prefix))
    manager.initialize()
    manager.initialize()
    with manager.get_connection() as connection:
        assert connection.ping()
    manager.close()


def test_the_gate_lets_one_caller_in_and_waits_out_a_failure(
    clock: Clock,
) -> None:
    from guard_core.sync.handlers._redis_reconnect_gate import RedisReconnectGate

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


def test_the_gate_admits_exactly_one_thread() -> None:
    from guard_core.sync.handlers._redis_reconnect_gate import RedisReconnectGate

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


def test_the_window_doubles_from_a_quarter_second_up_to_5_s(
    clock: Clock,
) -> None:
    from guard_core.sync.handlers._redis_reconnect_gate import RedisReconnectGate

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


def test_a_failure_is_reported_once_per_5_s(clock: Clock) -> None:
    from guard_core.sync.handlers._redis_reconnect_gate import RedisReconnectGate

    gate = RedisReconnectGate()
    assert gate.report_due() is True
    clock.now += 4.9
    assert gate.report_due() is False
    clock.now += 0.2
    assert gate.report_due() is True


def test_a_long_attempt_waits_twice_as_long_up_to_5_s(clock: Clock) -> None:
    from guard_core.sync.handlers._redis_reconnect_gate import RedisReconnectGate

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


def test_a_refused_outage_held_30_s_is_tried_at_most_12_times_and_reported_7(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    manager = RedisManager(config_for(forwarder.url, prefix))
    events = Events()
    manager.agent_handler = events
    attempts = MagicMock(wraps=manager._open_connection)
    with patch.object(manager, "_open_connection", attempts):
        for _ in range(300):
            with pytest.raises(GuardRedisError):
                with manager.get_connection():
                    pass
            clock.now += 0.1
    assert 8 <= attempts.call_count <= 12
    assert 1 <= events.count("connection_failed") <= 7


def test_a_fail_closed_blip_serves_within_half_a_second_of_the_restore(
    forwarder: RedisForwarder, prefix: str
) -> None:
    manager = RedisManager(config_for(forwarder.url, prefix, fail_open=False))
    with pytest.raises(GuardRedisError):
        with manager.get_connection():
            pass
    time.sleep(0.1)
    forwarder.on()
    restored = monotonic()
    served = None
    while monotonic() - restored < 2.0:
        try:
            with manager.get_connection() as connection:
                assert connection.ping()
            served = monotonic() - restored
            break
        except GuardRedisError:
            time.sleep(0.05)
    assert served is not None and served < 0.5
    manager.close()


def test_a_fail_open_blip_writes_keys_within_half_a_second_of_the_restore(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = App(config_for(forwarder.url, prefix))
    app.start()
    assert app.request() is None
    time.sleep(0.1)
    forwarder.on()
    restored = monotonic()
    written = None
    while monotonic() - restored < 2.0:
        assert app.request() is None
        app.ban()
        if keys_under(prefix) > 0:
            written = monotonic() - restored
            break
        time.sleep(0.05)
    assert written is not None and written < 0.5
    assert app.names() == []


class SuperCallingHandler(RedisHandlerBase):
    initialize_calls = 0

    def initialize(self) -> None:
        type(self).initialize_calls += 1
        super().initialize()


def test_a_super_calling_handler_is_asked_once_per_window_and_connects(
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
    initializer.initialize_redis_handlers()
    assert SuperCallingHandler.initialize_calls == 1
    assert pipeline.get_check_names() == [RECOVERY_CHECK]

    for _ in range(300):
        assert pipeline.execute(request_of()) is None
        clock.now += 0.1
    assert 8 <= SuperCallingHandler.initialize_calls <= 13
    assert pipeline.get_check_names() == [RECOVERY_CHECK]

    forwarder.on()
    for _ in range(80):
        assert pipeline.execute(request_of()) is None
        clock.now += 0.1
        if not pipeline.get_check_names():
            break
    assert pipeline.get_check_names() == []
    manager = ip_ban_manager_for(config)
    manager.ban_ip(BANNED_IP, 60, config=config)
    assert keys_under(prefix) > 0
    handler.close()


def test_a_recovered_connection_sends_one_recovered_event(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    manager = RedisManager(config_for(forwarder.url, prefix))
    events = Events()
    manager.agent_handler = events
    with pytest.raises(GuardRedisError):
        with manager.get_connection():
            pass
    forwarder.on()
    clock.now += REDIS_OUTAGE_RETRY_AFTER + 0.1
    with manager.get_connection() as connection:
        assert connection.ping()
    assert events.count("connection_recovered") == 1
    assert events.count("connection_established") == 1
    manager.close()

    first_try = RedisManager(config_for(forwarder.url, prefix + "x:"))
    fresh = Events()
    first_try.agent_handler = fresh
    first_try.initialize()
    assert fresh.count("connection_recovered") == 0
    first_try.close()


class SwallowingHandler(RedisHandlerBase):
    initialize_calls = 0
    swallow = False

    def initialize(self) -> None:
        type(self).initialize_calls += 1
        try:
            super().initialize()
        except GuardRedisError:
            if not type(self).swallow:
                raise


def test_an_initialize_that_swallows_the_failure_keeps_the_backoff(
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
    initializer.initialize_redis_handlers()
    SwallowingHandler.swallow = True
    for _ in range(300):
        assert pipeline.execute(request_of()) is None
        clock.now += 0.1
    assert 8 <= SwallowingHandler.initialize_calls <= 13
    assert pipeline.get_check_names() == [RECOVERY_CHECK]

    forwarder.on()
    for _ in range(80):
        assert pipeline.execute(request_of()) is None
        clock.now += 0.1
        if not pipeline.get_check_names():
            break
    assert pipeline.get_check_names() == []
    handler.close()


def test_a_second_outage_after_a_recovery_reports_its_first_failure(
    forwarder: RedisForwarder, prefix: str, clock: Clock
) -> None:
    manager = RedisManager(config_for(forwarder.url, prefix))
    events = Events()
    manager.agent_handler = events

    def refused() -> None:
        with pytest.raises(GuardRedisError):
            with manager.get_connection():
                pass

    refused()
    assert events.count("connection_failed") == 1
    forwarder.on()
    clock.now += 0.3
    with manager.get_connection() as connection:
        assert connection.ping()
    forwarder.off()
    manager._discard_client()
    clock.now += 0.8
    refused()
    assert events.count("connection_failed") == 2
    assert events.count("connection_recovered") == 1


def test_a_second_outage_within_5_s_of_a_recovery_is_reported(
    clock: Clock,
) -> None:
    from guard_core.sync.handlers._redis_reconnect_gate import RedisReconnectGate

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

    def __init__(self, config: SyncSecurityConfig, url: str) -> None:
        self.config = config
        self._url = url
        self._client: Redis | None = None

    def initialize(self) -> None:
        client = Redis.from_url(
            self._url, decode_responses=True, socket_connect_timeout=0.5
        )
        try:
            client.ping()
        except RedisError as error:
            close_redis_client(client)
            raise GuardRedisError(503, "Redis connection failed") from error
        self._client = client

    @contextmanager
    def get_connection(self) -> Iterator[Redis]:
        assert self._client is not None
        yield self._client

    def is_connected(self) -> bool:
        return self._client is not None

    def close(self) -> None:
        if self._client is not None:
            close_redis_client(self._client)


def test_a_handler_with_its_client_elsewhere_recovers_through_is_connected(
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
    initializer.initialize_redis_handlers()
    assert pipeline.get_check_names() == [RECOVERY_CHECK]
    assert handler.is_connected() is False

    forwarder.on()
    for _ in range(80):
        assert pipeline.execute(request_of()) is None
        clock.now += 0.1
        if not pipeline.get_check_names():
            break
    assert pipeline.get_check_names() == []
    assert handler.is_connected() is True
    ip_ban_manager_for(config).ban_ip(BANNED_IP, 60, config=config)
    assert keys_under(prefix) > 0
    handler.close()


class WithoutIsConnectedHandler(RedisHandlerBase):
    """A handler whose only connection state is ``_redis``: no ``is_connected``.

    Its own ``initialize`` keeps recovery on the path that reads state."""

    def initialize(self) -> None:
        super().initialize()

    def __getattribute__(self, name: str) -> object:
        if name == "is_connected":
            raise AttributeError(name)
        return super().__getattribute__(name)


def test_a_handler_with_only_redis_attribute_starts_clean_and_recovers(
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
    initializer.initialize_redis_handlers()
    assert pipeline.get_check_names() == [RECOVERY_CHECK]

    forwarder.on()
    for _ in range(80):
        assert pipeline.execute(request_of()) is None
        clock.now += 0.1
        if not pipeline.get_check_names():
            break
    assert pipeline.get_check_names() == []
    ip_ban_manager_for(config).ban_ip(BANNED_IP, 60, config=config)
    assert keys_under(prefix) > 0
    handler.close()


def test_the_redis_manager_reports_is_connected_from_its_client(
    forwarder: RedisForwarder, prefix: str
) -> None:
    manager = RedisManager(config_for(forwarder.url, prefix))
    assert manager.is_connected() is False
    forwarder.on()
    manager.initialize()
    assert manager.is_connected() is True
    manager.close()
    assert manager.is_connected() is False
