import threading
from collections import defaultdict, deque
from collections.abc import Callable
from typing import TYPE_CHECKING

from guard_core._utils.sampling import PerApp

if TYPE_CHECKING:
    from guard_core.core.checks.helpers import _WindowedCategoryCounts


class ByIpWindows(defaultdict[str, deque[float]]):
    """The request windows of one app's ``check_rate_limit_by_ip`` calls."""

    def __init__(self) -> None:
        super().__init__(deque)


class ByIpStrikes(dict[str, "_WindowedCategoryCounts"]):
    """The rate-limit strikes of one app's ``check_rate_limit_by_ip`` calls."""


by_ip_request_timestamps = PerApp("by_ip_windows", ByIpWindows)
by_ip_autoban_counts = PerApp("by_ip_strikes", ByIpStrikes)
by_ip_lock = threading.Lock()
by_ip_autoban_lock = threading.Lock()


def forget_strikes_of(client_ip: str) -> None:
    with by_ip_autoban_lock:
        for strikes in by_ip_autoban_counts.tables():
            strikes.pop(client_ip, None)


def clear_strikes() -> None:
    with by_ip_autoban_lock:
        for strikes in by_ip_autoban_counts.tables():
            strikes.clear()


def clear_windows() -> None:
    with by_ip_lock:
        for windows in by_ip_request_timestamps.tables():
            windows.clear()


def forget_strikes_inside(covers: Callable[[str], bool]) -> None:
    with by_ip_autoban_lock:
        for strikes in by_ip_autoban_counts.tables():
            for client_ip in tuple(strikes):
                if covers(client_ip):
                    del strikes[client_ip]
