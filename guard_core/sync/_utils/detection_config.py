from collections.abc import Collection, Mapping
from typing import TYPE_CHECKING

from guard_core.sync._utils.request_logging import (
    _DEFAULT_SENSITIVE_LOG_FIELDS,
    _merge_sensitive_log_headers,
    _merge_sensitive_names,
)

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig
    from guard_core.sync.decorators.base import RouteConfig


def _excluded_params_by_name(
    listed: "Collection[str] | Mapping[str, Collection[str]]",
) -> dict[str, frozenset[str]]:
    if isinstance(listed, Mapping):
        return {name.lower(): frozenset(listed[name]) for name in listed}
    return {name.lower(): frozenset() for name in listed}


def _resolve_excluded_params(
    config: "SecurityConfig | None", route_config: "RouteConfig | None"
) -> dict[str, frozenset[str]]:
    if route_config is not None and route_config.excluded_detection_params is not None:
        return _excluded_params_by_name(route_config.excluded_detection_params)
    if config is not None:
        return _excluded_params_by_name(config.excluded_detection_params)
    return {}


def _resolve_excluded_body_fields(
    config: "SecurityConfig | None", route_config: "RouteConfig | None"
) -> set[str]:
    if (
        route_config is not None
        and route_config.excluded_detection_body_fields is not None
    ):
        return {k.lower() for k in route_config.excluded_detection_body_fields}
    if config is not None:
        return {k.lower() for k in config.excluded_detection_body_fields}
    return set()


def _resolve_enabled_categories(
    config: "SecurityConfig | None", route_config: "RouteConfig | None"
) -> set[str] | None:
    if (
        route_config is not None
        and route_config.enabled_detection_categories is not None
    ):
        return set(route_config.enabled_detection_categories)
    if config is not None:
        return set(config.enabled_detection_categories)
    return None


def _resolve_scan_body(
    config: "SecurityConfig | None", route_config: "RouteConfig | None"
) -> bool:
    if route_config is not None and route_config.detection_scan_body is not None:
        return route_config.detection_scan_body
    if config is not None:
        return config.detection_scan_body
    return True


_DEFAULT_EXCLUDED_HEADERS: frozenset[str] = frozenset(
    {
        "host",
        "user-agent",
        "accept",
        "accept-encoding",
        "connection",
        "origin",
        "referer",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "x-client-ip",
        "x-cluster-client-ip",
        "cf-connecting-ip",
        "true-client-ip",
        "fly-client-ip",
        "x-envoy-external-address",
    }
)


def _resolve_excluded_headers(
    config: "SecurityConfig | None", route_config: "RouteConfig | None"
) -> set[str]:
    excluded = set(_DEFAULT_EXCLUDED_HEADERS)
    if config is not None:
        excluded |= {h.lower() for h in config.excluded_detection_headers}
    if route_config is not None and route_config.excluded_detection_headers is not None:
        excluded |= {h.lower() for h in route_config.excluded_detection_headers}
    return excluded


def _resolve_operator_excluded_headers(
    config: "SecurityConfig | None", route_config: "RouteConfig | None"
) -> frozenset[str]:
    listed: set[str] = set()
    if config is not None:
        listed |= {h.strip().lower() for h in config.excluded_detection_headers}
    if route_config is not None and route_config.excluded_detection_headers is not None:
        listed |= {h.strip().lower() for h in route_config.excluded_detection_headers}
    return frozenset(listed)


_ADDRESS_HEADER_SKIP_CATEGORIES: frozenset[str] = frozenset({"ssrf"})

_GENERIC_EXCLUDED_HEADER_SKIP_CATEGORIES: frozenset[str] = frozenset()

_HEADER_CATEGORY_EXCLUSIONS: dict[str, frozenset[str]] = {
    "host": _ADDRESS_HEADER_SKIP_CATEGORIES,
    "origin": _ADDRESS_HEADER_SKIP_CATEGORIES,
    "x-forwarded-for": _ADDRESS_HEADER_SKIP_CATEGORIES,
    "x-forwarded-host": _ADDRESS_HEADER_SKIP_CATEGORIES,
    "x-real-ip": _ADDRESS_HEADER_SKIP_CATEGORIES,
    "x-client-ip": _ADDRESS_HEADER_SKIP_CATEGORIES,
    "x-cluster-client-ip": _ADDRESS_HEADER_SKIP_CATEGORIES,
    "cf-connecting-ip": _ADDRESS_HEADER_SKIP_CATEGORIES,
    "true-client-ip": _ADDRESS_HEADER_SKIP_CATEGORIES,
    "fly-client-ip": _ADDRESS_HEADER_SKIP_CATEGORIES,
    "x-envoy-external-address": _ADDRESS_HEADER_SKIP_CATEGORIES,
    "via": _ADDRESS_HEADER_SKIP_CATEGORIES,
}


def _address_chain_token_is_address(token: str) -> bool:
    from ipaddress import ip_address

    from guard_core.sync._utils.ip_extraction import _strip_forwarded_entry_port

    try:
        ip_address(_strip_forwarded_entry_port(token))
    except ValueError:
        return False
    return True


def _value_looks_like_address_chain(value: str) -> bool:
    tokens = [token.strip() for token in value.split(",") if token.strip()]
    if not tokens:
        return False
    return all(_address_chain_token_is_address(token) for token in tokens)


_INTERNAL_HOST_HEADER_EXCLUSIONS: dict[str, frozenset[str]] = {
    "referer": _ADDRESS_HEADER_SKIP_CATEGORIES,
    "user-agent": _ADDRESS_HEADER_SKIP_CATEGORIES,
}
_INTERNAL_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")


def _host_header_names_an_internal_host(host: str) -> bool:
    from ipaddress import ip_address

    name = host.strip().lower()
    if name.startswith("["):
        name = name[1:].split("]", 1)[0]
    elif name.count(":") == 1:
        name = name.split(":", 1)[0]
    if name == "localhost" or name.endswith(_INTERNAL_HOST_SUFFIXES):
        return True
    try:
        address = ip_address(name)
    except ValueError:
        return False
    return (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_unspecified
    )


def _excluded_header_skip_categories(
    key: str, value: str, internal_host: bool = False
) -> frozenset[str]:
    normalized = key.strip().lower()
    mapped = _HEADER_CATEGORY_EXCLUSIONS.get(normalized)
    if mapped is not None:
        return mapped
    if internal_host and normalized in _INTERNAL_HOST_HEADER_EXCLUSIONS:
        return _INTERNAL_HOST_HEADER_EXCLUSIONS[normalized]
    if _value_looks_like_address_chain(value):
        return _ADDRESS_HEADER_SKIP_CATEGORIES
    return _GENERIC_EXCLUDED_HEADER_SKIP_CATEGORIES


def _excluded_header_effective_categories(
    key: str,
    value: str,
    enabled_categories: set[str] | None,
    internal_host: bool = False,
) -> set[str] | None:
    skip = _excluded_header_skip_categories(key, value, internal_host)
    if not skip:
        return enabled_categories
    return _categories_without(enabled_categories, skip)


def _categories_without(
    enabled_categories: set[str] | None, skipped: frozenset[str]
) -> set[str]:
    from guard_core.sync.handlers.suspatterns_handler import ALL_DETECTION_CATEGORIES

    base = (
        set(enabled_categories)
        if enabled_categories is not None
        else set(ALL_DETECTION_CATEGORIES)
    )
    return base - skipped


def _param_scan_categories(
    key: str,
    excluded_params: "Collection[str] | Mapping[str, frozenset[str]]",
    enabled_categories: set[str] | None,
) -> tuple[bool, set[str] | None]:
    name = key.lower()
    if isinstance(excluded_params, Mapping):
        skipped = excluded_params.get(name)
    else:
        skipped = frozenset() if name in excluded_params else None
    if skipped is None:
        return True, enabled_categories
    if not skipped:
        return False, enabled_categories
    return True, _categories_without(enabled_categories, skipped)


def _resolve_log_level(config: "SecurityConfig | None") -> str | None:
    return config.log_suspicious_level if config is not None else "WARNING"


def _resolve_sensitive_log_headers(config: "SecurityConfig | None") -> frozenset[str]:
    return _merge_sensitive_log_headers(
        config.log_sensitive_headers if config is not None else None
    )


def _resolve_sensitive_log_params(config: "SecurityConfig | None") -> frozenset[str]:
    return _merge_sensitive_names(
        _DEFAULT_SENSITIVE_LOG_FIELDS,
        config.log_sensitive_params if config is not None else None,
    )


def _resolve_sensitive_log_body_fields(
    config: "SecurityConfig | None",
) -> frozenset[str]:
    return _merge_sensitive_names(
        _DEFAULT_SENSITIVE_LOG_FIELDS,
        config.log_sensitive_body_fields if config is not None else None,
    )


_DEFAULT_MAX_SCAN_VALUES = 512


def _resolve_max_scan_values(config: "SecurityConfig | None") -> int:
    return (
        config.detection_max_scan_values
        if config is not None
        else _DEFAULT_MAX_SCAN_VALUES
    )


_DEFAULT_MAX_SCAN_CHARS = 65536


def _resolve_max_scan_chars(config: "SecurityConfig | None") -> int:
    return (
        config.detection_max_scan_chars
        if config is not None
        else _DEFAULT_MAX_SCAN_CHARS
    )


_DEFAULT_MAX_JSON_DEPTH = 32


def _resolve_max_json_depth(config: "SecurityConfig | None") -> int:
    return (
        config.detection_max_json_depth
        if config is not None
        else _DEFAULT_MAX_JSON_DEPTH
    )


_DEFAULT_BINARY_MIN_RUN_LENGTH = 16


def _resolve_binary_min_run_length(config: "SecurityConfig | None") -> int:
    return (
        config.detection_binary_min_run_length
        if config is not None
        else _DEFAULT_BINARY_MIN_RUN_LENGTH
    )


_DEFAULT_MAX_SCAN_SECONDS = 10.0


def _resolve_max_scan_seconds(config: "SecurityConfig | None") -> float:
    return (
        config.detection_max_scan_seconds
        if config is not None
        else _DEFAULT_MAX_SCAN_SECONDS
    )


def _resolve_semantic_excluded_headers(
    config: "SecurityConfig | None", route_config: "RouteConfig | None"
) -> frozenset[str]:
    excluded: set[str] = set()
    if config is not None:
        excluded |= {
            h.strip().lower() for h in config.excluded_semantic_detection_headers
        }
    if (
        route_config is not None
        and route_config.excluded_semantic_detection_headers is not None
    ):
        excluded |= {
            h.strip().lower() for h in route_config.excluded_semantic_detection_headers
        }
    return frozenset(excluded)
