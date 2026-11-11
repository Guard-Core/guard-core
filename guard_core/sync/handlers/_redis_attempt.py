import threading
from collections.abc import Callable

_JOIN_SECONDS = 0.5


class ConnectionLocks:
    """The connection lock of one manager."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def here(self) -> threading.Lock:
        return self._lock

    def any_locked(self) -> bool:
        return self._lock.locked()


class RedisAttemptSlot:
    """The one reconnect attempt a degraded manager runs off the request path, on a
    daemon thread."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None

    def spawn(self, work: Callable[[], None]) -> None:
        self._thread = threading.Thread(target=work, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        thread = self._thread
        if thread is not None:
            thread.join(timeout=_JOIN_SECONDS)
