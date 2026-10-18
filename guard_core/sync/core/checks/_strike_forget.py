import logging
import threading
import weakref
from collections.abc import Callable
from typing import Any

_registered: "weakref.WeakSet[Any]" = weakref.WeakSet()
_registry_lock = threading.Lock()
_logger = logging.getLogger("guard_core.sync.core.checks.strike_forget")
_unregistrable_warned = False


def register_strike_middleware(middleware: Any) -> None:
    global _unregistrable_warned
    with _registry_lock:
        try:
            _registered.add(middleware)
        except TypeError:
            if not _unregistrable_warned:
                _unregistrable_warned = True
                _logger.warning(
                    "This middleware cannot be weakly referenced, so unban and "
                    "reset calls cannot clear its in-process strike counts. This "
                    "is logged once."
                )


def _registered_middlewares() -> list[Any]:
    with _registry_lock:
        return list(_registered)


def forget_identity_strikes(client_ip: str) -> None:
    from guard_core.sync.core.checks.helpers import _forget_suspicious_counts

    for middleware in _registered_middlewares():
        _forget_suspicious_counts(middleware, client_ip)


def forget_category_strikes(category: str) -> None:
    from guard_core.sync.core.checks.helpers import _suspicious_counts_lock

    for middleware in _registered_middlewares():
        with _suspicious_counts_lock:
            counts = middleware.suspicious_request_counts
            for client_ip in tuple(counts):
                ip_counts = counts[client_ip]
                forget = getattr(ip_counts, "forget", None)
                if forget is None:
                    ip_counts.pop(category, None)
                else:
                    forget(category)
                if not ip_counts:
                    del counts[client_ip]


def has_category_strikes(category: str) -> bool:
    from guard_core.sync.core.checks.helpers import _suspicious_counts_lock

    for middleware in _registered_middlewares():
        with _suspicious_counts_lock:
            if any(
                category in ip_counts
                for ip_counts in middleware.suspicious_request_counts.values()
            ):
                return True
    return False


def forget_identities_inside(covers: Callable[[str], bool]) -> None:
    from guard_core.sync.core.checks.helpers import _suspicious_counts_lock

    for middleware in _registered_middlewares():
        with _suspicious_counts_lock:
            counts = middleware.suspicious_request_counts
            for client_ip in tuple(counts):
                if covers(client_ip):
                    del counts[client_ip]


def forget_all_strikes() -> None:
    from guard_core.sync.core.checks.helpers import _suspicious_counts_lock

    for middleware in _registered_middlewares():
        with _suspicious_counts_lock:
            middleware.suspicious_request_counts.clear()
