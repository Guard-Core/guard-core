"""Stand-ins for a Redis outage: a listener that never answers, and a TCP proxy to the
suite's Redis that can stop answering on every open and new connection (the shape of
a mid-life outage). Plain threads and sockets, so both trees' tests share them."""

import asyncio
import socket
import threading
import time
from urllib.parse import urlparse

from tests.conftest import REDIS_URL


class HungListener:
    """Listens and never answers: the handshake completes, a PING waits for the
    socket timeout. A stand-in for a black hole that needs no remote host."""

    def __enter__(self) -> "HungListener":
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4096)
        self.url = f"redis://127.0.0.1:{self._sock.getsockname()[1]}/0"
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._sock.close()


class WatchedListener:
    """Accepts connections and never answers; counts the accepted connections the peer
    has closed, so a test can see that a client was closed and not just dropped."""

    def __enter__(self) -> "WatchedListener":
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.1)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.accepted = 0
        self.closed = 0
        self._port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()
        return self

    def url(self, query: str = "") -> str:
        return f"redis://127.0.0.1:{self._port}/0{query}"

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with self._lock:
                self.accepted += 1
            threading.Thread(
                target=self._watch, args=(connection,), daemon=True
            ).start()

    def _watch(self, connection: socket.socket) -> None:
        connection.settimeout(3.0)
        peer_closed = True
        try:
            while connection.recv(4096):
                pass
        except TimeoutError:
            peer_closed = False
        except OSError:
            pass
        connection.close()
        if peer_closed:
            with self._lock:
                self.closed += 1

    def wait_until_closed(self, count: int, seconds: float = 2.0) -> bool:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if self.closed >= count:
                return True
            time.sleep(0.02)
        return self.closed >= count

    def __exit__(self, *exc_info: object) -> None:
        self._stop.set()
        self._thread.join(2)
        self._sock.close()


class HangableProxy:
    """Forwards to the suite's Redis until ``hang()``; then every open and new
    connection accepts and never replies."""

    def __enter__(self) -> "HangableProxy":
        target = urlparse(REDIS_URL)
        self._target = (target.hostname or "127.0.0.1", target.port or 6379)
        self._db = target.path or "/0"
        self._hung = threading.Event()
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._port = 0
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        self._ready.wait(5)
        self.url = f"redis://127.0.0.1:{self._port}{self._db}"
        return self

    def hang(self) -> None:
        self._hung.set()

    def release(self) -> None:
        self._hung.clear()

    def __exit__(self, *exc_info: object) -> None:
        self._stop.set()
        self._thread.join(5)

    def _serve(self) -> None:
        asyncio.run(self._main())

    async def _main(self) -> None:
        writers: list[asyncio.StreamWriter] = []

        async def pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            try:
                while data := await r.read(65536):
                    while self._hung.is_set():
                        await asyncio.sleep(0.05)
                    w.write(data)
                    await w.drain()
            except (OSError, asyncio.CancelledError):
                return

        async def handle(cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
            writers.append(cw)
            while self._hung.is_set():
                await asyncio.sleep(0.05)
            ur, uw = await asyncio.open_connection(*self._target)
            writers.append(uw)
            await asyncio.gather(pipe(cr, uw), pipe(ur, cw))

        server = await asyncio.start_server(handle, "127.0.0.1", 0, backlog=4096)
        self._port = server.sockets[0].getsockname()[1]
        self._ready.set()
        while not self._stop.is_set():
            await asyncio.sleep(0.05)
        server.close()
        for writer in writers:
            writer.close()
        await asyncio.sleep(0.05)
