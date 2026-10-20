import socket
import ssl
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path

from tests.live_smoke.scenarios.rate_limit_and_bans import _build_single_entry_mmdb

CLIENT_IP = "203.0.113.5"


def country_database_bytes(country: str, ip: str = CLIENT_IP) -> bytes:
    return _build_single_entry_mmdb(ip, country)


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

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except OSError:
                continue
            attempt = self.attempts
            self.attempts += 1
            threading.Thread(
                target=self._serve, args=(conn, attempt), daemon=True
            ).start()

    def _serve(self, conn: socket.socket, attempt: int) -> None:
        try:
            conn.settimeout(self.HOLD_SECONDS)
            stream = (
                self._tls.wrap_socket(conn, server_side=True) if self._tls else conn
            )
            with stream:
                if self._read_request:
                    read_request(stream)
                self._behavior(stream, attempt)
        except OSError:
            return
        finally:
            conn.close()


def read_request(conn: socket.socket) -> None:
    request = b""
    while b"\r\n\r\n" not in request:
        request += conn.recv(4096)


def _hold_silently(conn: socket.socket, attempt: int) -> None:
    time.sleep(GeoDownloadServer.HOLD_SECONDS)


def _headers(length: int) -> bytes:
    return (
        f"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n"
        "Content-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n"
    ).encode()


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
            time.sleep(GeoDownloadServer.HOLD_SECONDS)
            return
        conn.sendall(_headers(len(body)) + body)

    return GeoDownloadServer(behavior)


def endless_server(gap: float) -> GeoDownloadServer:
    def behavior(conn: socket.socket, attempt: int) -> None:
        conn.sendall(_headers(10**9))
        deadline = time.monotonic() + GeoDownloadServer.HOLD_SECONDS
        while time.monotonic() < deadline:
            conn.sendall(b"x" * 16)
            time.sleep(gap)

    return GeoDownloadServer(behavior)


def trickles_then_delays_server(gap: float, delay: float) -> GeoDownloadServer:
    body = country_database_bytes("CN")

    def behavior(conn: socket.socket, attempt: int) -> None:
        if attempt == 0:
            conn.sendall(_headers(10**9))
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


def _stall(conn: socket.socket, kind: str, keep_alive: bool) -> None:
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
        time.sleep(GeoDownloadServer.HOLD_SECONDS)
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
        time.sleep(GeoDownloadServer.HOLD_SECONDS)

    return GeoDownloadServer(behavior)


def connect_proxy_server(kind: str, tls: ssl.SSLContext) -> GeoDownloadServer:
    def behavior(conn: socket.socket, attempt: int) -> None:
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        with tls.wrap_socket(conn, server_side=True) as tunnel:
            read_request(tunnel)
            _stall(tunnel, kind, keep_alive=True)

    return GeoDownloadServer(behavior)


def socks5_proxy_server(kind: str) -> GeoDownloadServer:
    def behavior(conn: socket.socket, attempt: int) -> None:
        conn.recv(3)
        conn.sendall(b"\x05\x00")
        conn.recv(4096)
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        read_request(conn)
        _stall(conn, kind, keep_alive=True)

    return GeoDownloadServer(behavior, read_request=False)
