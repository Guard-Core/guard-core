import logging
from typing import TYPE_CHECKING

from guard_core._emergency_exemptions import warn_unexempted_probe_paths
from guard_core._security_config_fields import DEFAULT_EXCLUDE_PATHS
from guard_core._security_headers_defaults import unknown_security_headers_keys
from guard_core.core.validation.path_matching import (
    _has_routing_anomaly_in_any_decoding,
)

if TYPE_CHECKING:
    from guard_core._security_config_fields import RequestT
    from guard_core.models import SecurityConfig

config_logger = logging.getLogger("guard_core.models")

FLAG_NAME = "fail_on_misconfiguration"

_FALSE_NOTE = f"{FLAG_NAME}=False keeps starting with it."
_TRUE_NOTE = f"Set {FLAG_NAME}=False to start with it anyway."


def report_misconfiguration(
    config: "SecurityConfig[RequestT]",
    problem: str,
    *,
    logger: logging.Logger,
    stacklevel: int,
) -> None:
    if config.fail_on_misconfiguration:
        raise ValueError(f"{problem} {_TRUE_NOTE}")
    logger.warning(f"{problem} {_FALSE_NOTE}", stacklevel=stacklevel)


def _non_positive_rate_limit_problems(config: "SecurityConfig[RequestT]") -> list[str]:
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


def _zero_detection_threshold_problems(config: "SecurityConfig[RequestT]") -> list[str]:
    return [
        f"{name} is 0.0: every request would be flagged as a threat."
        for name in ("detection_threat_score_threshold", "detection_semantic_threshold")
        if getattr(config, name) <= 0
    ]


def _glob_exclude_path_problems(config: "SecurityConfig[RequestT]") -> list[str]:
    return [
        f"exclude_paths entry {entry!r} is not a glob: wildcards are literal "
        "characters, so it excludes nothing."
        for entry in config.exclude_paths
        if any(char in entry for char in "*?#")
    ]


def _anomalous_path_problems(config: "SecurityConfig[RequestT]") -> list[str]:
    spelling = (
        "has a dot segment, an empty segment, a backslash or an encoded dot or "
        "separator (in any decoding round), a spelling the router does not "
        "serve as written. Write the plain path."
    )
    return [
        *(
            f"exclude_paths entry {entry!r} {spelling}"
            for entry in config.exclude_paths
            if entry not in DEFAULT_EXCLUDE_PATHS
            and _has_routing_anomaly_in_any_decoding(entry)
        ),
        *(
            f"endpoint_rate_limits key {key!r} {spelling}"
            for key in config.endpoint_rate_limits
            if _has_routing_anomaly_in_any_decoding(key)
        ),
    ]


def _unknown_security_headers_key_problems(
    config: "SecurityConfig[RequestT]",
) -> list[str]:
    return [
        f"security_headers key {key!r} is not a known key, so it is ignored "
        "and has no effect."
        for key in unknown_security_headers_keys(config.security_headers)
    ]


def config_misconfigurations(config: "SecurityConfig[RequestT]") -> list[str]:
    return [
        *_unknown_security_headers_key_problems(config),
        *_glob_exclude_path_problems(config),
        *_anomalous_path_problems(config),
        *_non_positive_rate_limit_problems(config),
        *_zero_detection_threshold_problems(config),
    ]


def report_config_misconfigurations(
    config: "SecurityConfig[RequestT]", *, stacklevel: int
) -> None:
    for problem in config_misconfigurations(config):
        report_misconfiguration(
            config, problem, logger=config_logger, stacklevel=stacklevel + 1
        )
    warn_unexempted_probe_paths(config, config_logger)
