import logging
import warnings
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig

logger = logging.getLogger("guard_core.models")

FLAG_NAME = "fail_on_misconfiguration"

_NOT_SET_NOTE = (
    f"{FLAG_NAME} is not set. guard-core 5.0.0 will refuse to start with this "
    f"misconfiguration. Pass {FLAG_NAME}=True to SecurityConfig now to opt in, "
    f"or {FLAG_NAME}=False to keep starting with it."
)
_FALSE_NOTE = (
    f"{FLAG_NAME}=False keeps starting with it. guard-core 5.0.0 will refuse to "
    "start with this misconfiguration unless that setting is False."
)
_TRUE_NOTE = f"Set {FLAG_NAME}=False to start with it anyway."


def report_misconfiguration(
    config: "SecurityConfig", problem: str, *, stacklevel: int
) -> None:
    if FLAG_NAME not in config.model_fields_set:
        message = f"{problem} {_NOT_SET_NOTE}"
    elif config.fail_on_misconfiguration:
        raise ValueError(f"{problem} {_TRUE_NOTE}")
    else:
        message = f"{problem} {_FALSE_NOTE}"
    logger.warning(message)
    warnings.warn(message, DeprecationWarning, stacklevel=stacklevel)


def _non_positive_rate_limit_problems(config: "SecurityConfig") -> list[str]:
    problems = []
    if config.rate_limit < 1:
        problems.append(
            f"rate_limit is {config.rate_limit}: a limit below 1 blocks every request."
        )
    if config.rate_limit_window < 1:
        problems.append(
            f"rate_limit_window is {config.rate_limit_window}: a window below 1 "
            "second disables the rate limiter."
        )
    for path, (limit, window) in config.endpoint_rate_limits.items():
        if limit < 1 or window < 1:
            problems.append(
                f"endpoint_rate_limits[{path!r}] is ({limit}, {window}): the "
                "limit and the window must both be at least 1."
            )
    return problems


def _zero_detection_threshold_problems(config: "SecurityConfig") -> list[str]:
    return [
        f"{name} is 0.0: every request would be flagged as a threat."
        for name in ("detection_threat_score_threshold", "detection_semantic_threshold")
        if getattr(config, name) <= 0
    ]


def _glob_exclude_path_problems(config: "SecurityConfig") -> list[str]:
    return [
        f"exclude_paths entry {entry!r} is not a glob: wildcards are literal "
        "characters, so it excludes nothing."
        for entry in config.exclude_paths
        if any(char in entry for char in "*?#")
    ]


def config_misconfigurations(config: "SecurityConfig") -> list[str]:
    return [
        *_glob_exclude_path_problems(config),
        *_non_positive_rate_limit_problems(config),
        *_zero_detection_threshold_problems(config),
    ]


def report_config_misconfigurations(
    config: "SecurityConfig", *, stacklevel: int
) -> None:
    for problem in config_misconfigurations(config):
        report_misconfiguration(config, problem, stacklevel=stacklevel + 1)
