import re
import socket
import threading
import time
import uuid
from collections import Counter
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pytest
from redis import Redis
from redis.connection import Connection

from guard_core.sync.handlers.redis_handler import close_redis_client

_PROCESS_CLIENT_NAME = f"guardtest-{uuid.uuid4().hex}"
_OBSERVER_CLIENT_NAME = f"guardtest-observer-{uuid.uuid4().hex}"
_MONITOR_LINE = re.compile(r"^\+?[\d.]+ \[(\d+) (.+?)\] (.*)$")
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_MONITORS: dict[str, "_Monitor"] = {}
_SHA_OF_AN_EVALSHA = re.compile(rb"(EVALSHA\r\n\$40\r\n)[0-9a-f]{40}")
_SHA_THE_SERVER_NEVER_LOADED = b"0" * 40


class _Monitor:
    """The server's MONITOR stream of one Redis, read on a thread of its own.

    MONITOR is the one place Redis names every command, including the ones a
    Lua script runs inside an EVALSHA (shown as `lua`, straight after the
    EVALSHA of the connection that ran it, because a script is atomic). Each
    line carries the address of the connection that sent it, which is how the
    engine's commands are told from every other client's: a connection is the
    engine's from the moment its CLIENT SETNAME (or HELLO ... SETNAME) line
    carries the name `engine_redis_url` put in the URL, so even a client that
    connects, sends and closes between two reads is attributed.
    """

    def __init__(self, host: str, port: int) -> None:
        self.lines: list[tuple[str, str, list[str]]] = []
        self.start = 0
        self.served_baseline: dict[str, int] = {}
        self.engine_addresses: set[str] = set()
        self._lock = threading.Lock()
        self._socket = socket.create_connection((host, port))
        self._socket.sendall(b"*1\r\n$7\r\nMONITOR\r\n")
        self._reader = self._socket.makefile("rb")
        assert self._reader.readline().startswith(b"+OK")
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()

    def _read(self) -> None:
        current = ""
        try:
            for raw in self._reader:
                found = _MONITOR_LINE.match(raw.decode("utf-8", "replace").rstrip())
                if found is None:
                    continue
                address = found.group(2)
                if address != "lua":
                    current = address
                arguments = _QUOTED.findall(found.group(3))
                with self._lock:
                    if _PROCESS_CLIENT_NAME in arguments:
                        self.engine_addresses.add(current)
                    self.lines.append((current, address, arguments))
        except (OSError, ValueError):
            return

    def snapshot(self) -> list[tuple[str, str, list[str]]]:
        with self._lock:
            return list(self.lines)

    def close(self) -> None:
        """Stop the stream: closing the socket alone leaves the file object made
        from it open, so the reader thread kept appending every command."""
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._reader.close()
        self._socket.close()


def server_loses_the_script_of_the_next_evalsha(
    monkeypatch: pytest.MonkeyPatch,
) -> list[bytes]:
    """Make the next EVALSHA the engine sends name a script the server never
    loaded, so the server answers NOSCRIPT for real, exactly as it does after the
    script cache was flushed, without flushing the cache every other client of
    the server shares. Returns the list of EVALSHAs it turned (one entry each),
    so a test can prove the reload path ran."""
    real = Connection.send_packed_command
    turned: list[bytes] = []

    def lose(
        connection: Connection,
        command: bytes | list[bytes],
        *rest: object,
        **kw: object,
    ) -> None:
        chunks = command if isinstance(command, list) else [command]
        if not turned and chunks[0].split(b"\r\n")[2] == b"EVALSHA":
            turned.append(chunks[0])
            lost = _SHA_OF_AN_EVALSHA.sub(
                rb"\g<1>" + _SHA_THE_SERVER_NEVER_LOADED, chunks[0], count=1
            )
            command = [lost, *chunks[1:]] if isinstance(command, list) else lost
        real(connection, command, *rest, **kw)

    monkeypatch.setattr(Connection, "send_packed_command", lose)
    return turned


def _without_script_reloads(
    lines: list[tuple[str, list[str]]],
) -> list[tuple[str, list[str]]]:
    """The commands without the NOSCRIPT retry: an EVALSHA the server could not
    run (no command of a script follows it) and the SCRIPT LOAD straight after
    it on the same connection go, so the EVALSHA that then ran counts once."""
    kept: list[tuple[str, list[str]]] = []
    for owner, arguments in lines:
        if (
            arguments[0].lower() == "script"
            and kept
            and kept[-1][0] == owner
            and kept[-1][1][0].lower() == "evalsha"
        ):
            kept.pop()
            continue
        kept.append((owner, arguments))
    return kept


def unwatch_all_engine_commands() -> None:
    """Close every MONITOR a test left open: each one reads, and keeps, every
    command the shared Redis serves until it is closed."""
    for url in list(_MONITORS):
        unwatch_engine_commands(url)


def engine_redis_url(url: str) -> str:
    """The URL with a client name, unique to this test process, that every
    connection of an engine built from it carries, so the server can tell the
    engine's connections from any other client's."""
    parts = urlsplit(url)
    query = [*parse_qsl(parts.query), ("client_name", _PROCESS_CLIENT_NAME)]
    return urlunsplit(parts._replace(query=urlencode(query)))


def _observer_url(url: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query) if k != "client_name"]
    query.append(("client_name", _OBSERVER_CLIENT_NAME))
    return urlunsplit(parts._replace(query=urlencode(query)))


def _engine_connections(url: str) -> dict[str, int]:
    """address -> the server's own `tot-cmds` of each connection named by
    `engine_redis_url`."""
    observer = Redis.from_url(_observer_url(url), decode_responses=True)
    try:
        listing = observer.client_list()
    finally:
        close_redis_client(observer)
    return {
        entry["addr"]: int(entry["tot-cmds"])
        for entry in listing
        if entry["name"] == _PROCESS_CLIENT_NAME
    }


def _wait_for_the_stream_to_catch_up(url: str, monitor: _Monitor) -> None:
    token = f"guardtest-barrier-{uuid.uuid4().hex}"
    observer = Redis.from_url(_observer_url(url), decode_responses=True)
    try:
        observer.echo(token)
    finally:
        close_redis_client(observer)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if any(token in arguments for _, _, arguments in monitor.snapshot()):
            return
        time.sleep(0.005)
    raise AssertionError("the MONITOR stream did not deliver the barrier command")


def _watch_engine_commands(url: str) -> None:
    """Start counting what the engine's connections (named by `engine_redis_url`)
    send, until `unwatch_engine_commands`. It starts at the first read, so a test
    that never counts pays nothing for MONITOR."""
    parts = urlsplit(url)
    monitor = _Monitor(parts.hostname or "localhost", parts.port or 6379)
    _MONITORS[url] = monitor
    _wait_for_the_stream_to_catch_up(url, monitor)
    monitor.start = len(monitor.snapshot())
    existing = _engine_connections(url)
    monitor.served_baseline = existing


def _required(url: str | None) -> str:
    if url is None:
        raise AssertionError("the engine has no redis_url to count the commands of")
    return url


def unwatch_engine_commands(engine_url: str | None) -> None:
    monitor = _MONITORS.pop(_required(engine_url), None)
    if monitor is not None:
        monitor.close()


def engine_commands_sent(engine_url: str | None, command: str | None = None) -> int:
    """Commands the engine's connections ran since the first read: every
    one, or those named `command` (lower case, as in INFO commandstats),
    counting the ones a Lua script ran too, and not counting a NOSCRIPT retry (the
    EVALSHA the server could not run and the SCRIPT LOAD after it).

    The count is proven complete on every read: the server's own `tot-cmds` of
    the engine's connections (which no other client can change) must equal the
    commands attributed to them, so a connection the attribution missed fails the
    read instead of lowering the count. Some servers' MONITOR leaves out EXEC, so
    a MULTI without its EXEC line stands for it.
    """
    url = _required(engine_url)
    if url not in _MONITORS:
        _watch_engine_commands(url)
    monitor = _MONITORS[url]
    _wait_for_the_stream_to_catch_up(url, monitor)
    connections = _engine_connections(url)
    monitor.engine_addresses |= set(connections)
    sent: Counter[str] = Counter()
    sent_on_live_connections: Counter[str] = Counter()
    engine_lines = [
        (owner, arguments)
        for owner, _address, arguments in monitor.snapshot()[monitor.start :]
        if owner in monitor.engine_addresses and arguments
    ]
    for owner, arguments in engine_lines:
        if owner in connections:
            sent_on_live_connections[arguments[0].lower()] += 1
    for _owner, arguments in _without_script_reloads(engine_lines):
        sent[arguments[0].lower()] += 1
    seen = sum(sent_on_live_connections.values()) + max(
        sent_on_live_connections["multi"] - sent_on_live_connections["exec"], 0
    )
    served = sum(
        commands - monitor.served_baseline.get(address, 0)
        for address, commands in connections.items()
    )
    assert seen == served, (
        f"MONITOR attributed {seen} commands to the engine's open connections, the "
        f"server counted {served} on them: {dict(sent_on_live_connections)}"
    )
    return sent[command] if command else sum(sent.values())
