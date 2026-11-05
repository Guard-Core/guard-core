import threading
from time import monotonic

# The Retry-After of the fail-secure 503: one connection attempt per 5 s at most.
REDIS_RECONNECT_WINDOW_SECONDS = 5


class RedisReconnectGate:
    """Single-flight reconnect with a backoff. After a failed attempt nobody enters
    until the window passes; when it opens exactly one caller enters and every other
    caller is refused at once. The claim is a non-blocking acquire, so it is atomic
    for coroutines and for threads alike and never waits."""

    def __init__(self) -> None:
        self._claim = threading.Lock()
        self._not_before = 0.0

    def enter(self) -> bool:
        if monotonic() < self._not_before:
            return False
        return self._claim.acquire(blocking=False)

    def leave(self, connected: bool) -> None:
        self._not_before = (
            0.0 if connected else monotonic() + REDIS_RECONNECT_WINDOW_SECONDS
        )
        self._claim.release()
