from contextvars import ContextVar
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.handlers._suspatterns_state import _DetectionState
    from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager


class ScanConfigScope(NamedTuple):
    manager: object
    config: "SyncSecurityConfig"
    state: "_DetectionState"


# Two apps on one Redis prefix share one manager, and every request re-runs
# configure(config) on it, so any config field the scan reads after an can
# belong to the other app. The scan of a request reads its own config and detection
# state from here instead, captured in the same synchronous step as configure.
_scan_config_scope: ContextVar[ScanConfigScope | None] = ContextVar(
    "guard_core_scan_config_scope", default=None
)


def scoped_config(
    manager: object, fallback: "SyncSecurityConfig | None"
) -> "SyncSecurityConfig | None":
    scope = _scan_config_scope.get()
    return scope.config if scope is not None and scope.manager is manager else fallback


def scoped_state(manager: object, fallback: "_DetectionState") -> "_DetectionState":
    scope = _scan_config_scope.get()
    return scope.state if scope is not None and scope.manager is manager else fallback


def scan_config_scope_of(
    config: "SyncSecurityConfig | None", manager: "SusPatternsManager"
) -> ScanConfigScope | None:
    if config is None:
        return None
    return ScanConfigScope(manager, config, manager._detection_state)
