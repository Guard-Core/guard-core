from contextvars import ContextVar
from threading import RLock
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from guard_core.handlers._suspatterns_state import _DetectionState
    from guard_core.handlers.suspatterns_handler import SusPatternsManager
    from guard_core.models import SecurityConfig


class ScanConfigScope(NamedTuple):
    manager: object
    config: "SecurityConfig"
    state: "_DetectionState"


# Two apps on one Redis prefix share one manager, and every request re-runs
# configure(config) on it, so any config field the scan reads after an await can
# belong to the other app. The scan of a request reads its own config and detection
# state from here instead, captured in the same synchronous step as configure.
_scan_config_scope: ContextVar[ScanConfigScope | None] = ContextVar(
    "guard_core_scan_config_scope", default=None
)


# The preprocessor scan window of the request being scanned: the limit that applies to
# that request (multipart: the file limit, any other body: the body limit), set by
# _scan_value_budget. None outside a request scan, so the detection state's own window
# (the larger of the two limits) applies.
_request_scan_window: ContextVar[int | None] = ContextVar(
    "guard_core_request_scan_window", default=None
)


# Held for the synchronous configure-and-capture step only, never across a scan:
# with threads, another app's configure between this request's configure and the
# read of the manager's detection state would hand it the other app's state.
configure_lock = RLock()


def scoped_config(
    manager: object, fallback: "SecurityConfig | None"
) -> "SecurityConfig | None":
    scope = _scan_config_scope.get()
    return scope.config if scope is not None and scope.manager is manager else fallback


def scoped_state(manager: object, fallback: "_DetectionState") -> "_DetectionState":
    scope = _scan_config_scope.get()
    return scope.state if scope is not None and scope.manager is manager else fallback


def scan_config_scope_of(
    config: "SecurityConfig | None", manager: "SusPatternsManager"
) -> ScanConfigScope | None:
    if config is None:
        return None
    return ScanConfigScope(manager, config, manager._detection_state)
