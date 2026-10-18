import logging
import time
from collections.abc import Collection
from typing import TYPE_CHECKING, Any, NamedTuple

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


def _shared_strikes_redis(middleware: "SyncGuardMiddlewareProtocol") -> Any:
    if not middleware.config.enable_redis:
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
        total, counts = redis_handler.record_detection_strikes(
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
    return SharedStrikes(counts, total)


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
