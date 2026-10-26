import socket
import ssl
import threading
import time
from typing import Any

from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.poolmanager import PoolManager

_WRAPPER_LEVELS = 4
_SETUP_TIMED_OUT = "GeoIP connection setup exceeded the total time bound"


class DownloadCut:
    def __init__(self, total: float) -> None:
        self.lock = threading.Lock()
        self._sockets: list[socket.socket] = []
        self._live = True
        self._fired = False
        self._total = total
        self._deadline = 0.0
        self._timer = threading.Timer(total, self.fire)
        self._timer.daemon = True

    def arm(self) -> None:
        self._deadline = time.monotonic() + self._total
        self._timer.start()

    def time_left(self) -> float:
        return max(self._deadline - time.monotonic(), 0.0)

    def record(self, sock: Any) -> None:
        os_socket = sock
        for _ in range(_WRAPPER_LEVELS):
            if isinstance(os_socket, socket.socket):
                break
            os_socket = getattr(os_socket, "socket", None)
        if not isinstance(os_socket, socket.socket):
            raise TypeError(f"no OS socket under {type(sock).__name__}")
        with self.lock:
            self._sockets.append(os_socket)
            if self._fired:
                self._shut_down(os_socket)

    def fire(self) -> None:
        with self.lock:
            if not self._live:
                return
            self._fired = True
            for sock in self._sockets:
                self._shut_down(sock)

    def has_fired(self) -> bool:
        with self.lock:
            return self._fired

    def stop(self) -> bool:
        with self.lock:
            self._live = False
            self._timer.cancel()
            return self._fired

    @staticmethod
    def _shut_down(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RD)
        except OSError:
            return


_SSL_CREATE_CODE = vars(ssl.SSLSocket)["_create"].__func__.__code__


def _close_sockets_ssl_create_left_open(error: BaseException) -> None:
    # CPython 3.10 SSLSocket._create raises without closing its half-built
    # socket when getpeername fails with anything but ENOTCONN (macOS: EINVAL) or
    # when its recv(1) then fails (Linux: ECONNRESET); 3.11 and later close it.
    pending: list[BaseException | None] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        trace = current.__traceback__
        while trace is not None:
            if trace.tb_frame.f_code is _SSL_CREATE_CODE:
                half_built = trace.tb_frame.f_locals.get("self")
                if isinstance(half_built, ssl.SSLSocket):
                    half_built.close()
            trace = trace.tb_next
        pending += [current.__cause__, current.__context__]


class _RecordingConnection(HTTPConnection):
    _cut: DownloadCut
    _setup_running = False
    _close_pending = False

    @property
    def sock(self) -> Any:
        return self.__dict__.get("_recorded_sock")

    @sock.setter
    def sock(self, value: Any) -> None:
        if value is not None:
            self._cut.record(value)
        self.__dict__["_recorded_sock"] = value

    def connect(self) -> None:
        finished = threading.Event()
        failures: list[BaseException] = []

        def setup() -> None:
            try:
                super(_RecordingConnection, self).connect()
            except BaseException as error:
                _close_sockets_ssl_create_left_open(error)
                failures.append(error)
            self._finish_setup()
            finished.set()

        with self._cut.lock:
            self._setup_running = True
        threading.Thread(target=setup, daemon=True, name="geo-connect").start()
        if not finished.wait(self._cut.time_left()):
            self._abandon_setup()
            raise TimeoutError(_SETUP_TIMED_OUT)
        if failures:
            raise failures[0]

    def _tunnel(self) -> None:
        super()._tunnel()
        if self._cut.has_fired():
            raise TimeoutError(_SETUP_TIMED_OUT)

    def close(self) -> None:
        with self._cut.lock:
            if self._setup_running:
                self._close_pending = True
                return
        super().close()

    def _abandon_setup(self) -> None:
        self._cut.fire()
        with self._cut.lock:
            self._close_pending = self._setup_running

    def _finish_setup(self) -> None:
        with self._cut.lock:
            self._setup_running = False
            closing = self._close_pending
        if closing:
            super().close()


class RecordingAdapter(HTTPAdapter):
    def __init__(self, cut: DownloadCut) -> None:
        self._cut = cut
        super().__init__()

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        super().init_poolmanager(*args, **kwargs)
        self._record_through(self.poolmanager)

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> PoolManager:
        manager: PoolManager = super().proxy_manager_for(proxy, **proxy_kwargs)
        self._record_through(manager)
        return manager

    def _record_through(self, manager: PoolManager) -> None:
        manager.pool_classes_by_scheme = {
            scheme: self._recording_pool(pool_class)
            for scheme, pool_class in manager.pool_classes_by_scheme.items()
        }

    def _recording_pool(
        self, pool_class: type[HTTPConnectionPool]
    ) -> type[HTTPConnectionPool]:
        connection_class = pool_class.ConnectionCls
        if issubclass(connection_class, _RecordingConnection):
            return pool_class
        recording = type(
            "RecordingConnection",
            (_RecordingConnection, connection_class),
            {"_cut": self._cut},
        )
        pool = type("RecordingPool", (pool_class,), {"ConnectionCls": recording})
        if not issubclass(pool, HTTPConnectionPool):
            raise TypeError("RecordingPool is not an HTTPConnectionPool subclass")
        return pool
