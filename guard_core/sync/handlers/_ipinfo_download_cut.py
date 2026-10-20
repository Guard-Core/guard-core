import socket
import threading
from typing import Any, cast

from requests.adapters import HTTPAdapter
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.poolmanager import PoolManager


class DownloadCut:
    def __init__(self, total: float) -> None:
        self._lock = threading.Lock()
        self._sockets: list[socket.socket] = []
        self._live = True
        self._fired = False
        self._timer = threading.Timer(total, self.fire)
        self._timer.daemon = True

    def arm(self) -> None:
        self._timer.start()

    def record(self, sock: socket.socket) -> None:
        with self._lock:
            self._sockets.append(sock)
            if self._fired:
                self._shut_down(sock)

    def fire(self) -> None:
        with self._lock:
            if not self._live:
                return
            self._fired = True
            for sock in self._sockets:
                self._shut_down(sock)

    def stop(self) -> bool:
        with self._lock:
            self._live = False
            self._timer.cancel()
            return self._fired

    @staticmethod
    def _shut_down(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RD)
        except OSError:
            return


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
        cut = self._cut
        connection_class = pool_class.ConnectionCls

        def connect(connection: Any) -> None:
            connection_class.connect(connection)
            cut.record(connection.sock)

        recording = type(
            "RecordingConnection", (connection_class,), {"connect": connect}
        )
        pool = type("RecordingPool", (pool_class,), {"ConnectionCls": recording})
        return cast(type[HTTPConnectionPool], pool)
