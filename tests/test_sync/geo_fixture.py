import socket
import threading
import time
from collections.abc import Callable

from tests.live_smoke.scenarios.rate_limit_and_bans import _build_single_entry_mmdb

CLIENT_IP = "203.0.113.5"


def country_database_bytes(country: str, ip: str = CLIENT_IP) -> bytes:
    return _build_single_entry_mmdb(ip, country)


class GeoDownloadServer:
    """A real local HTTP server that scripts how each download attempt behaves."""

    HOLD_SECONDS = 4.0

    def __init__(self, behavior: Callable[[socket.socket, int], None]) -> None:
        self._behavior = behavior
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
        with conn:
            conn.settimeout(self.HOLD_SECONDS)
            try:
                request = b""
                while b"\r\n\r\n" not in request:
                    request += conn.recv(4096)
                self._behavior(conn, attempt)
            except OSError:
                return


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
