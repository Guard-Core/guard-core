import threading
from time import monotonic

REDIS_RECONNECT_WINDOW_SECONDS = 5
_FIRST_WINDOW_SECONDS = 0.25
_MAX_DOUBLINGS = 16


class RedisReconnectGate:
    """Single-flight reconnect with an adaptive backoff. After a failed attempt nobody
    enters until the window passes; when it opens exactly one caller enters and every
    other caller is refused at once. The claim is a non-blocking acquire, so it is
    atomic for coroutines and for threads alike and never waits.

    The window after the n-th consecutive failure is
    ``min(5, max(0.25 * 2 ** (n - 1), 2 * attempt_seconds))``: a blip recovers within
    0.25 s, a sustained refusal settles at one attempt per 5 s, and an attempt that
    itself hangs for seconds waits the full 5 s."""

    def __init__(self) -> None:
        self._claim = threading.Lock()
        self._not_before = 0.0
        self._failures = 0
        self._began = 0.0
        self._reported_at: float | None = None

    def enter(self) -> bool:
        now = monotonic()
        if now < self._not_before:
            return False
        if not self._claim.acquire(blocking=False):
            return False
        self._began = now
        return True

    def leave(self, connected: bool) -> bool:
        """Close the attempt; True when it is the first success after failures."""
        now = monotonic()
        recovered = connected and self._failures > 0
        if connected:
            if recovered:
                self._reported_at = None
            self._failures = 0
            self._not_before = 0.0
        else:
            self._failures += 1
            doubling = _FIRST_WINDOW_SECONDS * 2 ** min(
                self._failures - 1, _MAX_DOUBLINGS
            )
            window = max(doubling, 2 * (now - self._began))
            self._not_before = now + min(REDIS_RECONNECT_WINDOW_SECONDS, window)
        self._claim.release()
        return recovered

    def report_due(self) -> bool:
        """True at most once per REDIS_RECONNECT_WINDOW_SECONDS: the caller reports
        a failure (log line, event) only when it is."""
        now = monotonic()
        if (
            self._reported_at is not None
            and now - self._reported_at < REDIS_RECONNECT_WINDOW_SECONDS
        ):
            return False
        self._reported_at = now
        return True
