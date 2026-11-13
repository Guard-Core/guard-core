import logging
from collections.abc import Collection, Sequence
from typing import TYPE_CHECKING

from guard_core._misconfiguration_kinds import (
    K_CORS_WILDCARD_WITH_CREDENTIALS,
    K_ENDPOINT_KEY_ROUTER_TEMPLATE,
    K_ENDPOINT_KEY_ROUTING_ANOMALY,
    K_ENDPOINT_LIMIT_BELOW_ONE,
    K_EXCLUDE_PATHS_GLOB,
    K_EXCLUDE_PATHS_ROUTING_ANOMALY,
    K_RATE_LIMIT_BELOW_ONE,
    K_RATE_LIMIT_WINDOW_BELOW_ONE,
    K_SECURITY_HEADERS_UNKNOWN_KEY,
    K_SEMANTIC_THRESHOLD_NON_POSITIVE,
    K_THREAT_SCORE_THRESHOLD_NON_POSITIVE,
    Problem,
    problem_log_extra,
)
from guard_core._security_config_fields import DEFAULT_EXCLUDE_PATHS
from guard_core._security_headers_defaults import unknown_security_headers_keys
from guard_core._utils.sampling import PerApp, WarnedKeys
from guard_core.exceptions import MisconfigurationError

if TYPE_CHECKING:
    from guard_core._security_config_fields import RequestT
    from guard_core.models import SecurityConfig

config_logger = logging.getLogger("guard_core.models")

FLAG_NAME = "fail_on_misconfiguration"

_FALSE_NOTE = f"{FLAG_NAME}=False keeps starting with it."
_TRUE_NOTE = f"Set {FLAG_NAME}=False to start with it anyway."


def report_misconfiguration(
    config: "SecurityConfig[RequestT]",
    problem: Problem,
    *,
    logger: logging.Logger,
    stacklevel: int,
) -> None:
    if config.fail_on_misconfiguration:
        raise MisconfigurationError(f"{problem} {_TRUE_NOTE}", [problem])
    logger.warning(
        f"{problem} {_FALSE_NOTE}",
        extra=problem_log_extra(problem),
        stacklevel=stacklevel,
    )


def _raised_message(problems: Sequence[Problem]) -> str:
    if len(problems) == 1:
        return f"{problems[0]} {_TRUE_NOTE}"
    listed = "\n".join(f"- {problem}" for problem in problems)
    return f"{len(problems)} misconfigurations:\n{listed}\n{_TRUE_NOTE}"


def report_misconfigurations(
    config: "SecurityConfig[RequestT]",
    problems: Sequence[Problem],
    *,
    logger: logging.Logger,
    stacklevel: int,
) -> None:
    if config.fail_on_misconfiguration and problems:
        raise MisconfigurationError(_raised_message(problems), list(problems))
    for problem in problems:
        logger.warning(
            f"{problem} {_FALSE_NOTE}",
            extra=problem_log_extra(problem),
            stacklevel=stacklevel,
        )


_declared_path_params_reported: PerApp[WarnedKeys] = PerApp(
    "declared_path_params", WarnedKeys
)


_DECLARED_PROBLEMS_CAP = 4096


class _DeclaredProblems(dict[tuple[str, str, frozenset[str]], list[Problem]]):
    """The problems of each (route, template, declared names) one app asked about."""


_declared_problems_found: PerApp[_DeclaredProblems] = PerApp(
    "declared_path_problems", _DeclaredProblems
)


def declared_path_problems_of(
    config: "SecurityConfig[RequestT]",
    route_id: str,
    template: str,
    declared: Collection[str],
) -> list[Problem]:
    """The kinded problems of one declaration, built once per app: a later request
    on the same route is a dict lookup, not a walk of the template."""
    from guard_core._utils.route_gate import detection_exclusion_path_param_problems

    found = _declared_problems_found.for_app(config)
    key = (route_id, template, frozenset(declared))
    problems = found.get(key)
    if problems is None:
        if len(found) >= _DECLARED_PROBLEMS_CAP:
            found.clear()
        problems = found[key] = detection_exclusion_path_param_problems(
            route_id, template, declared
        )
    return problems


def report_declared_path_param_problems(
    config: "SecurityConfig[RequestT]",
    problems: Sequence[Problem],
    *,
    logger: logging.Logger,
    stacklevel: int,
) -> None:
    """The one report point of the @detection_exclusion(path_params=...) problems,
    shared by every adapter and the engine's own request-time check. With the flag
    on every call raises a fresh error listing every problem; with it off each
    problem warns once per app, whichever caller finds it first."""
    if config.fail_on_misconfiguration:
        report_misconfigurations(
            config, problems, logger=logger, stacklevel=stacklevel + 1
        )
        return
    reported = _declared_path_params_reported.for_app(config)
    fresh = [problem for problem in problems if str(problem) not in reported]
    reported.update(str(problem) for problem in fresh)
    report_misconfigurations(config, fresh, logger=logger, stacklevel=stacklevel + 1)


def _non_positive_rate_limit_problems(
    config: "SecurityConfig[RequestT]",
) -> list[Problem]:
    if not config.enable_rate_limiting:
        return []
    problems: list[Problem] = []
    if config.rate_limit < 1:
        problems.append(
            Problem(
                f"rate_limit is {config.rate_limit}: a limit below 1 blocks every "
                "request.",
                kind=K_RATE_LIMIT_BELOW_ONE,
            )
        )
    if config.rate_limit_window < 1:
        problems.append(
            Problem(
                f"rate_limit_window is {config.rate_limit_window}: a window below 1 "
                "second disables the rate limiter.",
                kind=K_RATE_LIMIT_WINDOW_BELOW_ONE,
            )
        )
    for path, (limit, window) in config.endpoint_rate_limits.items():
        if limit < 1 or window < 1:
            problems.append(
                Problem(
                    f"endpoint_rate_limits[{path!r}] is ({limit}, {window}): the "
                    "limit and the window must both be at least 1.",
                    kind=K_ENDPOINT_LIMIT_BELOW_ONE,
                    subject=path,
                )
            )
    return problems


def _zero_detection_threshold_problems(
    config: "SecurityConfig[RequestT]",
) -> list[Problem]:
    return [
        Problem(
            f"{name} is 0.0: every request would be flagged as a threat.", kind=kind
        )
        for name, kind in (
            ("detection_threat_score_threshold", K_THREAT_SCORE_THRESHOLD_NON_POSITIVE),
            ("detection_semantic_threshold", K_SEMANTIC_THRESHOLD_NON_POSITIVE),
        )
        if getattr(config, name) <= 0
    ]


def _glob_exclude_path_problems(
    config: "SecurityConfig[RequestT]",
) -> list[Problem]:
    from guard_core.core.validation.path_matching import has_glob_character

    return [
        Problem(
            f"exclude_paths entry {entry!r} is not a glob: wildcards are literal "
            "characters, so it excludes nothing.",
            kind=K_EXCLUDE_PATHS_GLOB,
            subject=entry,
        )
        for entry in config.exclude_paths
        if has_glob_character(entry)
    ]


def _anomalous_path_problems(
    config: "SecurityConfig[RequestT]",
) -> list[Problem]:
    from guard_core.core.validation.path_matching import (
        _has_routing_anomaly_in_any_decoding,
        is_router_template,
    )

    spelling = (
        "has a dot segment, an empty segment, a backslash or an encoded dot or "
        "separator (in any decoding round), a spelling the router does not "
        "serve as written. Write the plain path."
    )
    return [
        *(
            Problem(
                f"exclude_paths entry {entry!r} {spelling}",
                kind=K_EXCLUDE_PATHS_ROUTING_ANOMALY,
                subject=entry,
            )
            for entry in config.exclude_paths
            if entry not in DEFAULT_EXCLUDE_PATHS
            and _has_routing_anomaly_in_any_decoding(entry)
        ),
        *(
            Problem(
                f"endpoint_rate_limits key {key!r} {spelling}",
                kind=K_ENDPOINT_KEY_ROUTING_ANOMALY,
                subject=key,
            )
            for key in config.endpoint_rate_limits
            if _has_routing_anomaly_in_any_decoding(key)
        ),
        *(
            Problem(
                f"endpoint_rate_limits key {key!r} is a router template, a regex "
                "route or a glob ({name}, <name>, :name, (?P<name>...), ([0-9]+), "
                "[0-9]+, .* or *): it matches only that literal text, so it limits "
                "nothing. Write a concrete path, or put the limit on the route with "
                "the rate_limit decorator.",
                kind=K_ENDPOINT_KEY_ROUTER_TEMPLATE,
                subject=key,
            )
            for key in config.endpoint_rate_limits
            if is_router_template(key)
        ),
    ]


WILDCARD_CORS_CREDENTIALS_PROBLEM = Problem(
    "CORS misconfiguration: wildcard origin '*' is incompatible "
    "with cors_allow_credentials=True.",
    kind=K_CORS_WILDCARD_WITH_CREDENTIALS,
)


def wildcard_cors_credentials_problems(
    config: "SecurityConfig[RequestT]",
) -> list[Problem]:
    if (
        config.enable_cors
        and config.cors_allow_credentials
        and "*" in (config.cors_allow_origins or [])
    ):
        return [WILDCARD_CORS_CREDENTIALS_PROBLEM]
    return []


def _unknown_security_headers_key_problems(
    config: "SecurityConfig[RequestT]",
) -> list[Problem]:
    return [
        Problem(
            f"security_headers key {key!r} is not a known key, so it is ignored "
            "and has no effect.",
            kind=K_SECURITY_HEADERS_UNKNOWN_KEY,
            subject=key,
        )
        for key in unknown_security_headers_keys(config.security_headers)
    ]


# Every field a check below reads. A config that states none of them holds only
# defaults, which are valid by construction, so it is not checked at all.
CHECKED_FIELDS = frozenset(
    {
        "security_headers",
        "exclude_paths",
        "endpoint_rate_limits",
        "rate_limit",
        "rate_limit_window",
        "enable_rate_limiting",
        "detection_threat_score_threshold",
        "detection_semantic_threshold",
        "enable_cors",
        "cors_allow_origins",
        "cors_allow_credentials",
    }
)

# What can need a report once rate_limit alone is stated: a valid rate_limit is
# the one stated field that is checked without a report.
CHECKED_FIELDS_BESIDES_RATE_LIMIT = CHECKED_FIELDS - {"rate_limit"}

# The same fields by check: a check whose fields are all unset sees only
# defaults, so it does not run.
_HEADER_FIELDS = frozenset({"security_headers"})
_PATH_FIELDS = frozenset({"exclude_paths", "endpoint_rate_limits"})
_RATE_LIMIT_FIELDS = frozenset(
    {"rate_limit", "rate_limit_window", "endpoint_rate_limits", "enable_rate_limiting"}
)
_THRESHOLD_FIELDS = frozenset(
    {"detection_threat_score_threshold", "detection_semantic_threshold"}
)
_CORS_FIELDS = frozenset(
    {"enable_cors", "cors_allow_origins", "cors_allow_credentials"}
)


def config_misconfigurations(config: "SecurityConfig[RequestT]") -> list[Problem]:
    stated = config.__pydantic_fields_set__
    problems: list[Problem] = []
    if not stated.isdisjoint(_HEADER_FIELDS):
        problems += _unknown_security_headers_key_problems(config)
    if "exclude_paths" in stated:
        problems += _glob_exclude_path_problems(config)
    if not stated.isdisjoint(_PATH_FIELDS):
        problems += _anomalous_path_problems(config)
    if not stated.isdisjoint(_RATE_LIMIT_FIELDS):
        problems += _non_positive_rate_limit_problems(config)
    if not stated.isdisjoint(_THRESHOLD_FIELDS):
        problems += _zero_detection_threshold_problems(config)
    if not stated.isdisjoint(_CORS_FIELDS):
        problems += wildcard_cors_credentials_problems(config)
    return problems


def report_config_misconfigurations(
    config: "SecurityConfig[RequestT]", *, stacklevel: int
) -> None:
    report_misconfigurations(
        config,
        config_misconfigurations(config),
        logger=config_logger,
        stacklevel=stacklevel + 1,
    )
    if config.emergency_mode:
        from guard_core._emergency_exemptions import warn_unexempted_probe_paths

        warn_unexempted_probe_paths(config, config_logger)
