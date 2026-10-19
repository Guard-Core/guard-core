import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig

_PROBE_SEGMENTS = frozenset(
    {
        "alive",
        "health",
        "healthcheck",
        "health-check",
        "healthy",
        "healthz",
        "heartbeat",
        "live",
        "liveness",
        "livez",
        "ping",
        "probe",
        "ready",
        "readiness",
        "readyz",
        "status",
        "up",
    }
)


def _is_probe_path(entry: str) -> bool:
    from guard_core.core.validation.path_matching import normalize_url_path

    normalized = normalize_url_path(entry)
    return normalized is not None and any(
        segment.lower() in _PROBE_SEGMENTS for segment in normalized.split("/")
    )


def unexempted_probe_paths(config: "SecurityConfig") -> list[str]:
    from guard_core.core.validation.path_matching import path_is_excluded

    return [
        entry
        for entry in config.exclude_paths
        if _is_probe_path(entry)
        and not path_is_excluded(entry, config.emergency_exempt_paths)
    ]


def warn_unexempted_probe_paths(
    config: "SecurityConfig", logger: logging.Logger
) -> None:
    if not config.emergency_mode:
        return
    paths = unexempted_probe_paths(config)
    if paths:
        logger.warning(
            "[EMERGENCY MODE] exclude_paths holds %s, which emergency mode now "
            "blocks for every client outside the emergency whitelist. List the "
            "probe paths that must stay reachable in emergency_exempt_paths.",
            ", ".join(repr(path) for path in paths),
        )
