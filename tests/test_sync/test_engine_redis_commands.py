import socket
import sys
import threading
import uuid
from collections.abc import Generator, Iterator
from urllib.parse import urlsplit, urlunsplit

import pytest
from redis import Redis

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager, close_redis_client
from tests.test_sync.conftest import REDIS_PREFIX, REDIS_URL, suite_redis_prefix
from tests.test_sync.engine_redis_commands import (
    _MONITORS,
    _PROCESS_CLIENT_NAME,
    _Monitor,
    _watch_engine_commands,
    engine_commands_sent,
    engine_redis_url,
    server_loses_the_script_of_the_next_evalsha,
    unwatch_all_engine_commands,
    unwatch_engine_commands,
)


@pytest.fixture
def engine() -> Generator[RedisManager, None]:
    config = SyncSecurityConfig(
        enable_redis=True,
        redis_url=engine_redis_url(REDIS_URL),
        redis_prefix=suite_redis_prefix("wp43"),
    )
    manager = RedisManager(config)
    manager.initialize()
    try:
        yield manager
    finally:
        manager.delete_pattern("*")
        manager.close()
        unwatch_engine_commands(config.redis_url)


def _another_client_sends_commands() -> None:
    other = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        for index in range(25):
            other.set(f"{REDIS_PREFIX}wp43:other:{index}", "1", ex=5)
            other.get(f"{REDIS_PREFIX}wp43:other:{index}")
            other.mget([f"{REDIS_PREFIX}wp43:other:{index}"])
            other.smembers(f"{REDIS_PREFIX}wp43:other:set:{index}")
    finally:
        close_redis_client(other)


def test_another_client_changes_no_count_of_the_engine(
    engine: RedisManager,
) -> None:
    url = engine.config.redis_url
    before_all = engine_commands_sent(url)
    before_get = engine_commands_sent(url, "get")

    _another_client_sends_commands()

    assert engine_commands_sent(url) == before_all
    assert engine_commands_sent(url, "get") == before_get


def test_one_extra_engine_command_is_one_more_in_every_count(
    engine: RedisManager,
) -> None:
    url = engine.config.redis_url
    before_all = engine_commands_sent(url)
    before_get = engine_commands_sent(url, "get")

    _another_client_sends_commands()
    with engine.get_connection() as conn:
        conn.get(f"{engine.config.redis_prefix}probe")

    assert engine_commands_sent(url) == before_all + 1
    assert engine_commands_sent(url, "get") == before_get + 1


def test_a_command_a_lua_script_runs_is_counted_under_its_own_name(
    engine: RedisManager,
) -> None:
    url = engine.config.redis_url
    before_all = engine_commands_sent(url)
    before_smembers = engine_commands_sent(url, "smembers")

    with engine.get_connection() as conn:
        conn.eval(
            "return redis.call('SMEMBERS', KEYS[1])", 1, f"{REDIS_PREFIX}wp43:set"
        )

    assert engine_commands_sent(url, "smembers") == before_smembers + 1
    assert engine_commands_sent(url, "eval") >= 1
    assert engine_commands_sent(url) == before_all + 2


def test_a_command_sent_through_a_second_pool_of_the_engine_is_counted(
    engine: RedisManager,
) -> None:
    url = engine.config.redis_url
    before_all = engine_commands_sent(url)
    second_pool = Redis.from_url(url, decode_responses=True)
    try:
        second_pool.get(f"{engine.config.redis_prefix}probe")
    finally:
        close_redis_client(second_pool)

    assert engine_commands_sent(url) > before_all


def test_unwatching_all_closes_every_monitor_a_test_left_open(
    engine: RedisManager,
) -> None:
    engine_commands_sent(engine.config.redis_url)
    monitor = next(iter(_MONITORS.values()))

    unwatch_all_engine_commands()

    assert not _MONITORS
    assert monitor._reader.closed
    monitor._thread.join(timeout=5)
    assert not monitor._thread.is_alive()


def test_a_noscript_retry_counts_as_one_script_call(
    engine: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = engine.config.redis_url
    key = f"noscript_{uuid.uuid4().hex}"
    engine.record_sliding_window_hit("wp152", key, 2e9, 2e9 - 1000, 60)
    before_evalsha = engine_commands_sent(url, "evalsha")
    before_script = engine_commands_sent(url, "script")
    turned = server_loses_the_script_of_the_next_evalsha(monkeypatch)

    engine.record_sliding_window_hit("wp152", key, 2e9, 2e9 - 1000, 60)

    assert len(turned) == 1
    assert engine_commands_sent(url, "evalsha") - before_evalsha == 1
    assert engine_commands_sent(url, "script") - before_script == 0
    engine.record_sliding_window_hit("wp152", key, 2e9, 2e9 - 1000, 60)
    assert engine_commands_sent(url, "evalsha") - before_evalsha == 2


def test_commands_of_another_database_are_not_kept_by_the_watch(
    engine: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = engine.config.redis_url
    assert url is not None
    watched = int(urlsplit(url).path.lstrip("/") or 0)
    other_url = urlunsplit(urlsplit(REDIS_URL)._replace(path=f"/{(watched + 3) % 16}"))
    # only reads of a key nothing ever writes: another database may be a
    # neighbour suite's on the shared server, so it is never written (LEDGER 6.737)
    other_key = f"{REDIS_PREFIX}wp548:other-db-{uuid.uuid4().hex}"
    before = engine_commands_sent(url, "get")

    other = Redis.from_url(other_url, decode_responses=True)
    sent: list[str] = []
    real = other.execute_command

    def record(name: str, *args: object, **kw: object) -> object:
        sent.append(name)
        return real(name, *args, **kw)

    monkeypatch.setattr(other, "execute_command", record)
    try:
        for _ in range(20):
            other.get(other_key)
    finally:
        close_redis_client(other)
    assert set(sent) == {"GET"}
    with engine.get_connection() as conn:
        conn.get(f"{engine.config.redis_prefix}probe")

    assert engine_commands_sent(url, "get") == before + 1
    kept = [arguments for _, _, arguments in _MONITORS[url].snapshot()]
    assert not [arguments for arguments in kept if other_key in arguments]


def test_another_clients_commands_on_the_watched_database_are_not_kept(
    engine: RedisManager,
) -> None:
    url = engine.config.redis_url
    assert url is not None
    watched = int(urlsplit(url).path.lstrip("/") or 0)
    same_db_url = urlunsplit(urlsplit(REDIS_URL)._replace(path=f"/{watched}"))
    other_key = f"{REDIS_PREFIX}6737:same-db-{uuid.uuid4().hex}"
    before = engine_commands_sent(url, "get")

    other = Redis.from_url(same_db_url, decode_responses=True)
    try:
        for _ in range(20):
            other.set(other_key, "1", ex=5)
            other.get(other_key)
    finally:
        other.delete(other_key)
        close_redis_client(other)
    with engine.get_connection() as conn:
        conn.get(f"{engine.config.redis_prefix}probe")

    assert engine_commands_sent(url, "get") == before + 1
    kept = [arguments for _, _, arguments in _MONITORS[url].snapshot()]
    assert not [arguments for arguments in kept if other_key in arguments]


def test_an_engine_connection_opened_after_the_first_read_is_counted_whole() -> None:
    database = int(urlsplit(REDIS_URL).path.lstrip("/") or 0) or 1
    url = engine_redis_url(
        urlunsplit(urlsplit(REDIS_URL)._replace(path=f"/{database}"))
    )
    key = f"{REDIS_PREFIX}6737:late-{uuid.uuid4().hex}"
    early = Redis.from_url(url, decode_responses=True)
    try:
        early.get(key)
        gets = engine_commands_sent(url, "get")
        sets = engine_commands_sent(url, "set")
        late = Redis.from_url(url, decode_responses=True)
        try:
            late.get(key)
            late.set(key, "1", ex=5)
            # its handshake runs before SELECT, so MONITOR shows it on database 0;
            # the read still matches the server's own count of the connection
            assert engine_commands_sent(url, "get") == gets + 1
            assert engine_commands_sent(url, "set") == sets + 1
        finally:
            late.delete(key)
            close_redis_client(late)
    finally:
        close_redis_client(early)
        unwatch_engine_commands(url)


class _FakeMonitorServer:
    """A server that accepts MONITOR (or refuses it) and then sends the lines it
    is given, so the attribution is tested without any real Redis traffic."""

    def __init__(self, reply: bytes = b"+OK\r\n") -> None:
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port: int = self._listener.getsockname()[1]
        self._reply = reply
        self._peer: socket.socket | None = None
        self._ready = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        try:
            self._peer, _ = self._listener.accept()
        except OSError:
            return
        self._peer.recv(64)
        self._peer.sendall(self._reply)
        self._ready.set()

    def feed(self, *lines: tuple[str, ...]) -> None:
        assert self._ready.wait(5)
        assert self._peer is not None
        for address, *arguments in lines:
            quoted = " ".join(f'"{argument}"' for argument in arguments)
            self._peer.sendall(f"1700000000.5 [0 {address}] {quoted}\r\n".encode())

    def close(self) -> None:
        try:
            self._listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._listener.close()
        if self._peer is not None:
            self._peer.close()


@pytest.fixture
def fake_server() -> Iterator[_FakeMonitorServer]:
    server = _FakeMonitorServer()
    yield server
    server.close()


def _kept_by(server: _FakeMonitorServer, *lines: tuple[str, ...]) -> list[list[str]]:
    monitor = _Monitor("127.0.0.1", server.port)
    try:
        server.feed(*lines, ("1.1.1.1:1", "ECHO", "guardtest-barrier-end"))
        for _ in range(500):
            kept = [arguments for _, _, arguments in monitor.snapshot()]
            if kept and kept[-1][0] == "ECHO":
                return kept[:-1]
            threading.Event().wait(0.01)
        raise AssertionError("the fake stream was not read")
    finally:
        monitor.close()


# the async or the sync copy of the helper, whichever this file imports
engine_redis_commands = sys.modules[_Monitor.__module__]
_NAME = _PROCESS_CLIENT_NAME


def test_6737a_a_new_connection_on_a_closed_engine_address_is_not_the_engines(
    fake_server: _FakeMonitorServer,
) -> None:
    kept = _kept_by(
        fake_server,
        ("10.0.0.1:5000", "CLIENT", "SETNAME", _NAME),
        ("10.0.0.1:5000", "CLIENT", "SETINFO", "LIB-NAME", "redis-py"),
        ("10.0.0.1:5000", "GET", "engine-key"),
        ("10.0.0.1:5000", "CLIENT", "SETINFO", "LIB-NAME", "redis-py"),
        ("10.0.0.1:5000", "GET", "stranger-key"),
    )

    assert ["GET", "engine-key"] in kept
    assert ["GET", "stranger-key"] not in kept
    assert ["CLIENT", "SETINFO", "LIB-NAME", "redis-py"] in kept


def test_6737b_a_handshake_before_the_name_is_kept_for_the_engine_only(
    fake_server: _FakeMonitorServer,
) -> None:
    kept = _kept_by(
        fake_server,
        ("10.0.0.2:5000", "AUTH", "engine-secret"),
        ("10.0.0.2:5000", "CLIENT", "SETINFO", "LIB-NAME", "redis-py"),
        ("10.0.0.2:5000", "CLIENT", "SETNAME", _NAME),
        ("10.0.0.2:5000", "GET", "engine-key"),
        ("10.0.0.3:5000", "AUTH", "stranger-secret"),
        ("10.0.0.3:5000", "CLIENT", "SETNAME", "someone-else"),
        ("10.0.0.3:5000", "GET", "stranger-key"),
    )

    assert ["AUTH", "engine-secret"] in kept
    assert ["CLIENT", "SETINFO", "LIB-NAME", "redis-py"] in kept
    assert ["GET", "engine-key"] in kept
    assert not [arguments for arguments in kept if "stranger" in " ".join(arguments)]


def _sockets_the_monitor_opens(
    monkeypatch: pytest.MonkeyPatch,
) -> list[socket.socket]:
    opened: list[socket.socket] = []
    real = socket.create_connection

    def spy(address: tuple[str, int]) -> socket.socket:
        opened.append(real(address))
        return opened[-1]

    monkeypatch.setattr(socket, "create_connection", spy)
    return opened


def test_6737c_a_monitor_the_server_refuses_closes_its_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = _FakeMonitorServer(reply=b"-ERR no MONITOR\r\n")
    opened = _sockets_the_monitor_opens(monkeypatch)
    try:
        with pytest.raises(AssertionError):
            _Monitor("127.0.0.1", server.port)
        assert opened[0].fileno() == -1
    finally:
        server.close()


def test_6737c_a_watch_that_fails_after_registering_closes_its_monitor(
    fake_server: _FakeMonitorServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened = _sockets_the_monitor_opens(monkeypatch)

    def fails(url: str) -> dict[str, int]:
        raise RuntimeError("the server did not answer")

    monkeypatch.setattr(engine_redis_commands, "_engine_connections", fails)
    url = f"redis://127.0.0.1:{fake_server.port}/0"

    with pytest.raises(RuntimeError):
        _watch_engine_commands(url)

    assert url not in _MONITORS
    assert opened[0].fileno() == -1


def test_6737d_a_handshake_that_never_continues_is_dropped_when_stale(
    fake_server: _FakeMonitorServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engine_redis_commands, "_HANDSHAKE_SECONDS", 0, raising=False)
    kept = _kept_by(
        fake_server,
        ("10.0.0.4:5000", "HELLO", "3"),
        ("10.0.0.5:5000", "HELLO", "3"),
        ("10.0.0.4:5000", "CLIENT", "SETNAME", _NAME),
        ("10.0.0.4:5000", "GET", "engine-key"),
    )

    assert ["HELLO", "3"] not in kept
    assert ["GET", "engine-key"] in kept
