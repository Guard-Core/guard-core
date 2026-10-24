import logging
import time
from collections.abc import Callable, Collection
from typing import TYPE_CHECKING, Any, NamedTuple

from guard_core._redis_enablement import redis_is_configured
from guard_core.sync.core.checks._ban_flow import BanFlow

if TYPE_CHECKING:
    from guard_core.sync.protocols.middleware_protocol import (
        SyncGuardMiddlewareProtocol,
    )

_logger = logging.getLogger("guard_core.sync.core.checks.shared_strikes")


def strike_categories(categories: str | Collection[str]) -> Collection[str]:
    return (
        (categories,)
        if isinstance(categories, str)
        else categories or ("uncategorized",)
    )


class SharedStrikes(NamedTuple):
    counts: dict[str, int]
    total: int
    rate_limit_violations: int = 0

    @property
    def event_count(self) -> int:
        return self.total + self.rate_limit_violations


class StrikeReport:
    """Carries the shared strike count of one threshold decision back to the
    caller that reports it in an event (``None`` when nothing was shared)."""

    def __init__(self) -> None:
        self.count: int | None = None
        self.banning_count: int | None = None
        self.banned_duration: int | None = None

    def record(
        self,
        shared: SharedStrikes | None,
        banned: bool,
        counted: int | None = None,
        duration: int | None = None,
    ) -> None:
        self.banned_duration = duration
        self.banning_count = counted if shared is None else shared.event_count
        if shared is not None:
            self.count = 0 if banned else shared.event_count

    def count_or(self, in_process: Callable[[], int]) -> int:
        return in_process() if self.count is None else self.count


class FusedStrike:
    """One detection strike a request is certain to record, handed to the ban
    lookup so that the lookup records it in the round trip that reads the bans.
    ``shared`` is set only when that round trip recorded it."""

    def __init__(
        self,
        client_ip: str,
        category: str,
        window_seconds: int,
        cap: int,
    ) -> None:
        self.client_ip = client_ip
        self.categories = (category,)
        self.window_seconds = window_seconds
        self.cap = cap
        self.shared: SharedStrikes | None = None

    def record(self, recorded: tuple[int, int, dict[str, int]] | None) -> None:
        self.shared = (
            None
            if recorded is None
            else SharedStrikes(recorded[2], recorded[0], recorded[1])
        )

    def take_if_recorded_for(
        self, client_ip: str, categories: str | Collection[str]
    ) -> SharedStrikes | None:
        shared, self.shared = self.shared, None
        matches = client_ip == self.client_ip and tuple(categories) == self.categories
        return shared if matches else None


def _shared_strikes_redis(middleware: "SyncGuardMiddlewareProtocol") -> Any:
    if not redis_is_configured(middleware.config):
        return None
    return getattr(middleware.rate_limit_handler, "redis_handler", None)


def record_shared_detection_strikes(
    middleware: "SyncGuardMiddlewareProtocol",
    client_ip: str,
    categories: str | Collection[str],
    window_seconds: int,
    cap: int,
) -> SharedStrikes | None:
    config = middleware.config
    redis_handler = _shared_strikes_redis(middleware)
    if not redis_handler or config.passive_mode or not config.enable_ip_banning:
        return None
    now = time.time()
    try:
        total, violations, counts = redis_handler.record_detection_strikes(
            client_ip,
            tuple(strike_categories(categories)),
            now,
            now - window_seconds,
            window_seconds,
            cap,
        )
    except Exception as error:
        _logger.warning(
            "Shared detection strike counter unavailable, counting this "
            "detection strike in this process only: %s",
            error,
        )
        return None
    return SharedStrikes(counts, total, violations)


def forget_shared_detection_strikes(
    middleware: "SyncGuardMiddlewareProtocol", client_ip: str
) -> None:
    redis_handler = _shared_strikes_redis(middleware)
    try:
        redis_handler.forget_detection_strikes(client_ip)
    except Exception as error:
        _logger.warning(
            "Shared detection strike counters of %s could not be cleared after "
            "the ban, they expire on their own: %s",
            client_ip,
            error,
        )


def read_shared_detection_categories(
    redis_handler: Any, client_ip: str, window_seconds: int
) -> list[str] | None:
    try:
        categories: list[str] = redis_handler.read_detection_categories(
            client_ip, time.time() - window_seconds
        )
    except Exception as error:
        _logger.warning(
            "Shared detection categories unavailable, using the categories this "
            "process saw: %s",
            error,
        )
        return None
    return categories


def fused_or_recorded_shared_strikes(
    request: Any,
    middleware: "SyncGuardMiddlewareProtocol",
    client_ip: str,
    categories: str | Collection[str],
    window_seconds: int,
    cap: Callable[[], int],
) -> SharedStrikes | None:
    flow = getattr(request.state, "guard_ban_flow", None)
    fused = flow.fused if isinstance(flow, BanFlow) else None
    if isinstance(fused, FusedStrike):
        recorded = fused.take_if_recorded_for(client_ip, categories)
        if recorded is not None:
            return recorded
    return record_shared_detection_strikes(
        middleware, client_ip, categories, window_seconds, cap()
    )
