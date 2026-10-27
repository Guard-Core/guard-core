import threading
from collections import deque
from collections.abc import Mapping
from typing import TYPE_CHECKING

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.ip_extraction import _client_identity

if TYPE_CHECKING:
    from guard_core.sync.core.checks._strike_forget import StrikeCountingMiddleware
    from guard_core.sync.protocols.middleware_protocol import (
        SyncGuardMiddlewareProtocol,
    )

_suspicious_counts_lock = threading.Lock()


def _strike_identity(config: SyncSecurityConfig, client_ip: str) -> str:
    if ":" not in client_ip:
        return client_ip
    return _client_identity(client_ip, config.ipv6_prefix_length)


def _ip_strike_counts(
    middleware: "SyncGuardMiddlewareProtocol", client_ip: str
) -> Mapping[str, int]:
    return middleware.suspicious_request_counts.get(
        _strike_identity(middleware.config, client_ip), {}
    )


_RATE_LIMIT_FEED_CATEGORY = "rate_limit"


class _WindowedCategoryCounts(dict[str, int]):
    """Per-category counts of the events inside the last ``SUSPICIOUS_COUNT_WINDOW``.

    The dict itself holds the live count per category, so every reader of
    ``suspicious_request_counts`` keeps seeing ``{category: int}``. The event
    times behind the counts are kept in a bounded deque per category.
    """

    def __init__(self) -> None:
        super().__init__()
        self._event_times: dict[str, deque[float]] = {}
        self._request_times: deque[float] = deque()

    @property
    def request_total(self) -> int:
        return len(self._request_times)

    def record_request(self, now: float, retain: int) -> None:
        if self._request_times.maxlen != retain:
            self._request_times = deque(self._request_times, maxlen=retain)
        self._request_times.append(now)

    def expire_before(self, cutoff: float) -> None:
        while self._request_times and self._request_times[0] <= cutoff:
            self._request_times.popleft()
        for category in tuple(self._event_times):
            times = self._event_times[category]
            while times and times[0] <= cutoff:
                times.popleft()
            if times:
                self[category] = len(times)
            else:
                del self._event_times[category]
                self.pop(category, None)

    def forget(self, category: str) -> None:
        self._event_times.pop(category, None)
        self.pop(category, None)

    def record(self, category: str, now: float, retain: int) -> None:
        times = self._event_times.get(category)
        if times is None or times.maxlen != retain:
            times = deque(times or (), maxlen=retain)
            self._event_times[category] = times
        times.append(now)
        self[category] = len(times)

    @classmethod
    def adopting(
        cls, counts: Mapping[str, int], now: float, retain: int
    ) -> "_WindowedCategoryCounts":
        adopted = cls()
        for category, count in counts.items():
            for _ in range(min(count, retain)):
                adopted.record(category, now, retain)
                if category != _RATE_LIMIT_FEED_CATEGORY:
                    adopted.record_request(now, retain)
        return adopted


def _forget_suspicious_counts(
    middleware: "StrikeCountingMiddleware", client_ip: str
) -> None:
    strike_key = _strike_identity(middleware.config, client_ip)
    with _suspicious_counts_lock:
        middleware.suspicious_request_counts.pop(strike_key, None)
