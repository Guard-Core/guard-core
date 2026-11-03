import gzip
import socket
import ssl
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

import pytest
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

from tests.live_smoke.scenarios.rate_limit_and_bans import _build_single_entry_mmdb

CLIENT_IP = "203.0.113.5"


def country_database_bytes(country: str, ip: str = CLIENT_IP) -> bytes:
    return _build_single_entry_mmdb(ip, country)


def padded_database_bytes(padding: bytes, size: int, country: str = "CN") -> bytes:
    """A valid MMDB of exactly `size` bytes, padded before its metadata."""
    valid = country_database_bytes(country)
    metadata_at = valid.rfind(b"\xab\xcd\xefMaxMind.com")
    fill = size - len(valid)
    filler = (padding * (fill // len(padding) + 1))[:fill]
    return valid[:metadata_at] + filler + valid[metadata_at:]


class GeoDownloadServer:
    """A real local HTTP server that scripts how each download attempt behaves."""

    HOLD_SECONDS = 4.0

    def __init__(
        self,
        behavior: Callable[[socket.socket, int], None],
        tls: ssl.SSLContext | None = None,
        read_request: bool = True,
    ) -> None:
        self._behavior = behavior
        self._tls = tls
        self._read_request = read_request
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.1)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._serving: list[threading.Thread] = []
        self._streams: list[Any] = []
        self.attempts = 0

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._listener.getsockname()[1]}/country_asn.mmdb"

    def __enter__(self) -> "GeoDownloadServer":
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._listener.close()
        for stream in self._streams:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                continue
        for thread in self._serving:
            thread.join(timeout=2)
        assert not [t for t in self._serving if t.is_alive()], "a stub thread outlived"

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except OSError:
                continue
            attempt = self.attempts
            self.attempts += 1
            serving = threading.Thread(
                target=self._serve, args=(conn, attempt), daemon=True
            )
            self._serving.append(serving)
            serving.start()

    def _serve(self, conn: socket.socket, attempt: int) -> None:
        try:
            conn.settimeout(self.HOLD_SECONDS)
            self._streams.append(conn)
            stream = (
                self._tls.wrap_socket(conn, server_side=True) if self._tls else conn
            )
            self._streams.append(stream)
            with stream:
                if self._read_request:
                    read_request(stream)
                self._behavior(stream, attempt)
        except OSError:
            return
        finally:
            conn.close()


class Stream(Protocol):
    def recv(self, size: int, /) -> bytes: ...

    def sendall(self, data: bytes, /) -> None: ...


def read_request(conn: Stream) -> None:
    request = b""
    while b"\r\n\r\n" not in request:
        if not (data := conn.recv(4096)):
            raise OSError("the peer closed before the request was complete")
        request += data


def hold_until_the_peer_ends(conn: Stream) -> None:
    """Keeps the connection open and silent until the peer or the server closes it."""
    try:
        while conn.recv(4096):
            continue
    except OSError:
        return


def _hold_silently(conn: socket.socket, attempt: int) -> None:
    hold_until_the_peer_ends(conn)


def _headers(length: int) -> bytes:
    return (
        f"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n"
        "Content-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n"
    ).encode()


OPEN_ENDED_HEADERS = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
    b"Connection: close\r\n\r\n"
)


def silent_server() -> GeoDownloadServer:
    return GeoDownloadServer(_hold_silently)


def trickling_server(gap: float, pieces: int = 5) -> GeoDownloadServer:
    body = country_database_bytes("CN")
    size = -(-len(body) // pieces)

    def behavior(conn: socket.socket, attempt: int) -> None:
        conn.sendall(_headers(len(body)))
        for start in range(0, len(body), size):
            time.sleep(gap)
            conn.sendall(body[start : start + size])

    return GeoDownloadServer(behavior)


def stalls_once_server() -> GeoDownloadServer:
    body = country_database_bytes("CN")

    def behavior(conn: socket.socket, attempt: int) -> None:
        if attempt == 0:
            hold_until_the_peer_ends(conn)
            return
        conn.sendall(_headers(len(body)) + body)

    return GeoDownloadServer(behavior)


def endless_server(gap: float) -> GeoDownloadServer:
    def behavior(conn: socket.socket, attempt: int) -> None:
        conn.sendall(OPEN_ENDED_HEADERS)
        deadline = time.monotonic() + GeoDownloadServer.HOLD_SECONDS
        while time.monotonic() < deadline:
            conn.sendall(b"x" * 16)
            time.sleep(gap)

    return GeoDownloadServer(behavior)


def _chunked(data: bytes) -> bytes:
    return f"{len(data):x}\r\n".encode() + data + b"\r\n"


def fast_endless_server(chunked: bool) -> GeoDownloadServer:
    """Sends a body that never ends, as fast as the client reads it."""
    head = OPEN_ENDED_HEADERS
    piece = b"x" * 65536
    if chunked:
        head = head.replace(b"Connection: close", b"Transfer-Encoding: chunked")
        piece = _chunked(piece)

    def behavior(conn: socket.socket, attempt: int) -> None:
        conn.sendall(head)
        deadline = time.monotonic() + GeoDownloadServer.HOLD_SECONDS
        while time.monotonic() < deadline:
            conn.sendall(piece)

    return GeoDownloadServer(behavior)


def gzip_inflating_server(inflated: int, layers: int = 1) -> GeoDownloadServer:
    """A small, complete gzip body, `layers` deep, that decodes to `inflated` bytes."""
    body = b"\0" * inflated
    for _ in range(layers):
        body = gzip.compress(body, compresslevel=9)
    encoding = b"Content-Encoding: " + b", ".join([b"gzip"] * layers) + b"\r\n"

    def behavior(conn: socket.socket, attempt: int) -> None:
        conn.sendall(
            _headers(len(body)).replace(b"Content-Type", encoding + b"Content-Type")
            + body
        )

    return GeoDownloadServer(behavior)


def declared_length_server(declared: int, sent: int) -> GeoDownloadServer:
    """Declares `declared` bytes, then sends only `sent` of them and holds."""

    def behavior(conn: socket.socket, attempt: int) -> None:
        conn.sendall(_headers(declared) + b"x" * sent)
        hold_until_the_peer_ends(conn)

    return GeoDownloadServer(behavior)


def sized_body_server(total: int) -> GeoDownloadServer:
    """Sends `total` zero bytes without ever holding them all in this process."""
    piece = b"\0" * 65536

    def behavior(conn: socket.socket, attempt: int) -> None:
        conn.sendall(_headers(total))
        for _ in range(total // len(piece)):
            conn.sendall(piece)

    return GeoDownloadServer(behavior)


def database_server(body: bytes) -> GeoDownloadServer:
    def behavior(conn: socket.socket, attempt: int) -> None:
        conn.sendall(_headers(len(body)) + body)

    return GeoDownloadServer(behavior)


def trickles_then_delays_server(gap: float, delay: float) -> GeoDownloadServer:
    body = country_database_bytes("CN")

    def behavior(conn: socket.socket, attempt: int) -> None:
        if attempt == 0:
            conn.sendall(OPEN_ENDED_HEADERS)
            deadline = time.monotonic() + GeoDownloadServer.HOLD_SECONDS
            while time.monotonic() < deadline:
                conn.sendall(b"x" * 16)
                time.sleep(gap)
            return
        conn.sendall(_headers(len(body)))
        time.sleep(delay)
        conn.sendall(body)

    return GeoDownloadServer(behavior)


HOST = "geo.example.invalid"
STALL_GAP = 0.05
GZIP_ENDLESS_COMMENT = b"\x1f\x8b\x08\x10\x00\x00\x00\x00\x00\xff"
DEFLATE_EMPTY_STORED_BLOCK = b"\x00\x00\x00\xff\xff"
STALL_KINDS = ("header", "gzip", "deflate", "trickle")


def make_tls_material(directory: Path) -> tuple[Path, Path]:
    certificate, key = directory / "cert.pem", directory / "key.pem"
    command = [
        *("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes"),
        *("-keyout", str(key), "-out", str(certificate), "-days", "1"),
        *("-subj", f"/CN={HOST}"),
        *("-addext", f"subjectAltName=DNS:{HOST},IP:127.0.0.1"),
    ]
    subprocess.run(command, check=True, capture_output=True)
    return certificate, key


def tls_server_context(certificate: Path, key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    return context


def _stall(conn: Stream, kind: str, keep_alive: bool) -> None:
    connection = b"keep-alive" if keep_alive else b"close"
    head = b"HTTP/1.1 200 OK\r\nConnection: " + connection + b"\r\n"
    sized = head + b"Content-Length: 1000000\r\n"
    if kind == "header":
        conn.sendall(head + b"X-Slow: ")
        unit = b"h"
    elif kind == "gzip":
        conn.sendall(sized + b"Content-Encoding: gzip\r\n\r\n" + GZIP_ENDLESS_COMMENT)
        unit = b"c"
    elif kind == "deflate":
        conn.sendall(sized + b"Content-Encoding: deflate\r\n\r\n\x78\x9c")
        unit = DEFLATE_EMPTY_STORED_BLOCK
    elif kind == "idle":
        conn.sendall(sized + b"\r\nx")
        hold_until_the_peer_ends(conn)
        return
    else:
        conn.sendall(sized + b"\r\n")
        unit = b"x"
    deadline = time.monotonic() + GeoDownloadServer.HOLD_SECONDS
    while time.monotonic() < deadline:
        conn.sendall(unit)
        time.sleep(STALL_GAP)


def stalling_server(
    kind: str, keep_alive: bool, tls: ssl.SSLContext | None = None
) -> GeoDownloadServer:
    return GeoDownloadServer(
        lambda conn, attempt: _stall(conn, kind, keep_alive), tls=tls
    )


def close_delimited_prefix_server() -> GeoDownloadServer:
    body = country_database_bytes("CN")

    def behavior(conn: socket.socket, attempt: int) -> None:
        conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + body[:-1])
        hold_until_the_peer_ends(conn)

    return GeoDownloadServer(behavior)


class TlsInTlsStream:
    """A TLS server running inside another stream (a proxy tunnel), over memory BIOs."""

    def __init__(
        self, outer: socket.socket, context: ssl.SSLContext, slow: bool = False
    ) -> None:
        self._outer = outer
        self._incoming, self._outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self._tls = context.wrap_bio(self._incoming, self._outgoing, server_side=True)
        self._slow = slow
        self._end = time.monotonic() + GeoDownloadServer.HOLD_SECONDS

    def _flush(self) -> None:
        data = self._outgoing.read()
        if not self._slow:
            if data:
                self._outer.sendall(data)
            return
        for index in range(len(data)):
            if time.monotonic() >= self._end:
                raise OSError("the slow handshake was held long enough")
            self._outer.sendall(data[index : index + 1])
            time.sleep(STALL_GAP)

    def _feed(self) -> None:
        data = self._outer.recv(65536)
        if not data:
            raise OSError("the peer closed during the handshake")
        self._incoming.write(data)

    def _until_ready(self, step: Callable[[], bytes | None]) -> bytes | None:
        while True:
            try:
                return step()
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()

    def handshake(self) -> None:
        self._until_ready(self._tls.do_handshake)
        self._flush()

    def recv(self, size: int) -> bytes:
        return self._until_ready(lambda: self._tls.read(size)) or b""

    def sendall(self, data: bytes) -> None:
        self._tls.write(data)
        self._flush()


def _tunnel_established(conn: socket.socket) -> None:
    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")


def connect_proxy_server(
    kind: str, tls: ssl.SSLContext, proxy_tls: ssl.SSLContext | None = None
) -> GeoDownloadServer:
    def behavior(conn: socket.socket, attempt: int) -> None:
        _tunnel_established(conn)
        stream = TlsInTlsStream(conn, tls)
        stream.handshake()
        read_request(stream)
        _stall(stream, kind, keep_alive=True)

    return GeoDownloadServer(behavior, tls=proxy_tls)


def slow_handshake_server(
    origin_tls: ssl.SSLContext, via_proxy: bool, proxy_tls: ssl.SSLContext | None = None
) -> GeoDownloadServer:
    """Relays the origin's TLS handshake one byte at a time, so it never completes."""

    def behavior(conn: socket.socket, attempt: int) -> None:
        if via_proxy:
            _tunnel_established(conn)
        TlsInTlsStream(conn, origin_tls, slow=True).handshake()

    return GeoDownloadServer(behavior, tls=proxy_tls, read_request=via_proxy)


def socks5_proxy_server(kind: str) -> GeoDownloadServer:
    def behavior(conn: socket.socket, attempt: int) -> None:
        conn.recv(3)
        conn.sendall(b"\x05\x00")
        conn.recv(4096)
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        read_request(conn)
        _stall(conn, kind, keep_alive=True)

    return GeoDownloadServer(behavior, read_request=False)


def count_connections(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Every connection a pool creates: pins count connections, not records."""
    connections: list[object] = []
    for pool_class in (HTTPConnectionPool, HTTPSConnectionPool):
        monkeypatch.setattr(
            pool_class, "_new_conn", _counting(pool_class._new_conn, connections)
        )
    return connections


def _counting(
    new_connection: Callable[[Any], Any], connections: list[object]
) -> Callable[[Any], Any]:
    def counting(pool: object) -> object:
        connection = new_connection(pool)
        connections.append(connection)
        return connection

    return counting
