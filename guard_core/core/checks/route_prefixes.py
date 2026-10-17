import re
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from guard_core._misconfiguration import config_logger
from guard_core._security_config_fields import DEFAULT_EXCLUDE_PATHS
from guard_core.core.validation.path_matching import (
    _has_routing_anomaly_in_any_decoding,
)

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig

_REGEX_META = frozenset("\\.[](){}*+?|$")
_OPTIONAL_AFTER = frozenset("?*{")
_TRAILING_ANCHOR = "$"
_PARAM_MARKERS = re.compile(r"[{<]")
_EXCLUDE_PATHS_EXAMINED = "exclude_paths examined"


def template_route_prefix(template: str) -> str:
    match = _PARAM_MARKERS.search(template)
    if match is None:
        return template.rstrip("/")
    head = template[: match.start()]
    return head[: head.rfind("/") + 1] or "/"


def regex_route_prefix(pattern: str) -> str:
    source = pattern.removeprefix("^")
    literal = ""
    for index, char in enumerate(source):
        if char not in _REGEX_META:
            literal += char
            continue
        if char == _TRAILING_ANCHOR and index == len(source) - 1:
            return ("/" + literal.lstrip("/")).rstrip("/")
        if char in _OPTIONAL_AFTER:
            literal = literal[:-1]
        head = "/" + literal.lstrip("/")
        return head[: head.rfind("/") + 1]
    return "/" + literal.lstrip("/").rstrip("/") + "/"


def entry_matches_route_prefixes(entry: str, prefixes: Iterable[str]) -> bool:
    wanted = entry.rstrip("/") or "/"
    for prefix in prefixes:
        base = prefix.rstrip("/") or "/"
        is_open = prefix.endswith("/")
        if base == "/" and is_open:
            return True
        if base == wanted or base.startswith(wanted + "/"):
            return True
        if is_open and wanted.startswith(base + "/"):
            return True
    return False


def _reported(middleware: Any) -> set[str]:
    reported: set[str] = middleware.__dict__.setdefault("_guard_route_warnings", set())
    return reported


def _warn_once(middleware: Any, message: str) -> None:
    reported = _reported(middleware)
    if message in reported:
        return
    reported.add(message)
    config_logger.warning(message)


def warn_unmatched_endpoint_keys(middleware: Any, keys: Iterable[str]) -> None:
    for key in sorted(keys):
        _warn_once(
            middleware,
            f"endpoint_rate_limits key {key!r} matches no registered route; "
            "check it for a typo. It still applies to requests whose path "
            "matches it after normalization.",
        )


def warn_unmatched_exclude_paths(middleware: Any, config: "SecurityConfig") -> None:
    reported = _reported(middleware)
    if _EXCLUDE_PATHS_EXAMINED in reported:
        return
    reported.add(_EXCLUDE_PATHS_EXAMINED)
    provider = getattr(middleware, "static_route_prefixes", None)
    if provider is None:
        return
    candidates = [
        entry
        for entry in config.exclude_paths
        if entry not in DEFAULT_EXCLUDE_PATHS
        and entry.rstrip("/")
        and not _has_routing_anomaly_in_any_decoding(entry)
    ]
    if not candidates:
        return
    prefixes = tuple(provider())
    for entry in candidates:
        if not entry_matches_route_prefixes(entry, prefixes):
            _warn_once(
                middleware,
                f"exclude_paths entry {entry!r} matches no registered route; "
                "check it for a typo.",
            )
