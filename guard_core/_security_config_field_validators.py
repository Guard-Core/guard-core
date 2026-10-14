import logging
import warnings
from collections.abc import Callable
from functools import partial
from ipaddress import ip_address, ip_network
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, get_args

from pydantic import BaseModel, Field, TypeAdapter

from guard_core._config_field_revalidators import (
    _validate_bool_field_value,
    _validate_endpoint_rate_limits_value,
    _validate_int_field_value,
    _validate_positive_int_field_value,
    _validate_str_list_field_value,
)
from guard_core._security_config_geo_validators import _validate_country_set_value
from guard_core._security_config_typed_validators import (
    _INT_KEYED_STR_DICT_ADAPTER,
    _OPTIONAL_STR_ANY_DICT_ADAPTER,
    _OPTIONAL_STR_LIST_ADAPTER,
    _STR_KEYED_STR_DICT_ADAPTER,
    _STR_LIST_ADAPTER,
    _STR_SET_ADAPTER,
    _validate_typed_collection_field_value,
)
from guard_core.handlers.suspatterns_handler import ALL_DETECTION_CATEGORIES

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig

logger = logging.getLogger("guard_core.models")


CloudProvider = Literal["AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"]
VALID_CLOUD_PROVIDERS: frozenset[str] = frozenset(get_args(CloudProvider))

_GLOBAL_BEHAVIOR_RULE_FIELDS = frozenset(
    {"global_behavior_rules", "behavior_scan_response_body"}
)


def _validate_exclude_paths_value(v: list[str], *, stacklevel: int) -> list[str]:
    from guard_core.core.validation.path_matching import normalize_url_path

    if not isinstance(v, list) or not all(isinstance(entry, str) for entry in v):
        raise ValueError("exclude_paths must be a list of str")

    for entry in v:
        normalized = normalize_url_path(entry)
        if normalized is None:
            raise ValueError(
                f"exclude_paths entry {entry!r} could not be normalized "
                "(malformed percent-encoding or invalid UTF-8); it would "
                "silently exclude nothing at request time. Fix or remove it."
            )
        if normalized != "/":
            continue
        if entry != "/":
            raise ValueError(
                f"exclude_paths entry {entry!r} normalizes to the root "
                "path '/', which would exclude the entire application "
                "from all security checks. Remove it, or configure the "
                "literal '/' if you really intend to exclude everything."
            )
        warnings.warn(
            "exclude_paths contains the literal '/' entry, which "
            "excludes the entire application from all security checks "
            "(IP banning, rate limiting, penetration detection, "
            "everything). Confirm this is intentional.",
            UserWarning,
            stacklevel=stacklevel,
        )
    return v


class ThreatBanConfig(BaseModel):
    threshold: int = Field(ge=1, description="Number of detections before auto-ban.")
    duration: int = Field(ge=1, description="Ban duration in seconds.")


THREAT_BAN_CONFIG_CATEGORIES: frozenset[str] = ALL_DETECTION_CATEGORIES | frozenset(
    {"rate_limit"}
)


class BehaviorRuleConfig(BaseModel):
    rule_type: Literal["usage", "return_pattern", "frequency"]
    threshold: int = Field(ge=1)
    window: int = Field(default=3600, ge=1)
    pattern: str | None = None
    action: Literal["ban", "log", "throttle", "alert"] = "log"
    ban_duration: int | None = Field(default=None, ge=1)
    correlate_with_detection: bool = False


def return_pattern_requires_response_body(pattern: str) -> bool:
    return not pattern.startswith("status:")


def _validate_return_pattern_requires_scan(
    pattern: str, *, scan_response_body: bool
) -> None:
    if not return_pattern_requires_response_body(pattern):
        return
    if scan_response_body:
        return
    from guard_core._utils.detection_scan import _redact_pattern_source

    raise ValueError(
        f"return_pattern rule with pattern {_redact_pattern_source(pattern)!r} "
        "requires reading the "
        "response body, but behavior_scan_response_body is False. This rule "
        "would never match: set behavior_scan_response_body=True to enable "
        "response-body inspection, or use a status: pattern instead."
    )


def _validate_return_pattern_body_scan(pattern: str, config: "SecurityConfig") -> None:
    _validate_return_pattern_requires_scan(
        pattern, scan_response_body=config.behavior_scan_response_body
    )


def _validate_global_behavior_rule_assignment(
    config: "SecurityConfig", name: str, value: Any
) -> None:
    candidate_rules = (
        value if name == "global_behavior_rules" else config.global_behavior_rules
    )
    candidate_scan_flag = (
        value
        if name == "behavior_scan_response_body"
        else config.behavior_scan_response_body
    )
    for rule in candidate_rules:
        if rule.rule_type != "return_pattern" or not rule.pattern:
            continue
        _validate_return_pattern_requires_scan(
            rule.pattern, scan_response_body=candidate_scan_flag
        )


def _revalidate_global_behavior_rules(config: "SecurityConfig") -> None:
    for rule in config.global_behavior_rules:
        if rule.rule_type != "return_pattern" or not rule.pattern:
            continue
        _validate_return_pattern_body_scan(rule.pattern, config)


def _validate_ip_or_cidr_list(
    v: Any, *, invalid_message: str, allow_unix: bool = False
) -> Any:
    if v is None:
        return None
    validated: list[str] = []
    for entry in v:
        if allow_unix and entry == "unix":
            validated.append("unix")
            continue
        try:
            if "/" in entry:
                validated.append(str(ip_network(entry, strict=False)))
            else:
                validated.append(str(ip_address(entry)))
        except ValueError:
            raise ValueError(f"{invalid_message}: {entry}") from None
    return tuple(validated)


def _validate_whitelist_value(v: Any) -> Any:
    return _validate_ip_or_cidr_list(v, invalid_message="Invalid IP or CIDR range")


def _validate_blacklist_value(v: Any) -> Any:
    return _validate_ip_or_cidr_list(v, invalid_message="Invalid IP or CIDR range")


def _validate_trusted_proxies_value(v: Any) -> Any:
    return _validate_ip_or_cidr_list(
        v, invalid_message="Invalid proxy IP or CIDR range", allow_unix=True
    )


def _is_prefix_zero_network_entry(entry: str) -> bool:
    try:
        return ip_network(entry, strict=False).prefixlen == 0
    except ValueError:
        return False


def _warn_trusted_proxies_prefix_zero() -> None:
    logger.warning(
        "trusted_proxies contains a /0 network (0.0.0.0/0 or ::/0): every "
        "peer is trusted to set X-Forwarded-For, which lets any client "
        "spoof its IP for rate limiting, IP banning and detection "
        "attribution. Restrict trusted_proxies to your actual reverse "
        "proxy addresses."
    )


def _warn_whitelist_prefix_zero() -> None:
    logger.warning(
        "whitelist contains a /0 network (0.0.0.0/0 or ::/0): every "
        "address is whitelisted, so blacklist, blocked_countries and IP "
        "bans cannot block anyone. Remove the /0 entry or list the "
        "specific networks you trust."
    )


def _warn_exempt_ips_prefix_zero(entries: tuple[str, ...]) -> None:
    if not any(_is_prefix_zero_network_entry(entry) for entry in entries):
        return
    logger.warning(
        "exempt_ips contains a /0 network (0.0.0.0/0 or ::/0): every "
        "address skips rate limiting and the user-agent and cloud-provider "
        "checks. Remove the /0 entry or list the specific networks you trust."
    )


def _warn_empty_enabled_detection_categories() -> None:
    logger.warning(
        "enabled_detection_categories is empty while "
        "enable_penetration_detection is True: penetration detection is "
        "enabled but will never match any category. Set "
        "enabled_detection_categories to a non-empty subset, or set "
        "enable_penetration_detection=False."
    )


def _validate_threat_ban_config_value(v: Any) -> MappingProxyType[str, Any]:
    mapping = {
        key: value if isinstance(value, ThreatBanConfig) else ThreatBanConfig(**value)
        for key, value in dict(v).items()
    }
    unknown = set(mapping.keys()) - THREAT_BAN_CONFIG_CATEGORIES
    if unknown:
        raise ValueError(
            f"Unknown threat categories in threat_ban_config: {sorted(unknown)}. "
            f"Valid: {sorted(THREAT_BAN_CONFIG_CATEGORIES)}"
        )
    return MappingProxyType(mapping)


def _validate_enabled_detection_categories_value(v: Any) -> frozenset[str]:
    result = frozenset(v)
    unknown = result - ALL_DETECTION_CATEGORIES
    if unknown:
        raise ValueError(
            f"Unknown detection categories: {sorted(unknown)}. "
            f"Valid: {sorted(ALL_DETECTION_CATEGORIES)}"
        )
    return result


def _validate_muted_event_types_value(v: Any) -> frozenset[str]:
    from guard_core.core.events.event_types import EVENT_TYPE_VALUES

    result = frozenset(v)
    invalid = result - EVENT_TYPE_VALUES
    if invalid:
        raise ValueError(
            f"Unknown event types in muted_event_types: {sorted(invalid)}. "
            f"Valid: {sorted(EVENT_TYPE_VALUES)}"
        )
    return result


def _validate_muted_metric_types_value(v: Any) -> frozenset[str]:
    from guard_core.core.events.event_types import METRIC_TYPE_VALUES

    result = frozenset(v)
    invalid = result - METRIC_TYPE_VALUES
    if invalid:
        raise ValueError(
            f"Unknown metric types in muted_metric_types: {sorted(invalid)}. "
            f"Valid: {sorted(METRIC_TYPE_VALUES)}"
        )
    return result


def _validate_muted_check_logs_value(v: Any) -> frozenset[str]:
    from guard_core.core.events.event_types import CHECK_NAME_VALUES

    result = frozenset(v)
    invalid = result - CHECK_NAME_VALUES
    if invalid:
        raise ValueError(
            f"Unknown check names in muted_check_logs: {sorted(invalid)}. "
            f"Valid: {sorted(CHECK_NAME_VALUES)}"
        )
    return result


def _validate_sensitive_name_set_value(v: Any, field_name: str) -> frozenset[str]:
    if isinstance(v, str | bytes):
        raise ValueError(
            f"{field_name} must be a collection of names, not a bare string"
        )
    result = frozenset(v)
    if not all(isinstance(item, str) for item in result):
        raise ValueError(f"{field_name} items must be strings")
    return result


def _validate_block_cloud_providers_value(v: Any) -> frozenset[str] | None:
    if v is None:
        return None
    result = frozenset(v)
    invalid = {
        sel for sel in result if sel.partition(":!")[0] not in VALID_CLOUD_PROVIDERS
    }
    if invalid:
        raise ValueError(
            f"Unknown cloud providers in block_cloud_providers: {sorted(invalid)}. "
            f"Valid: {sorted(VALID_CLOUD_PROVIDERS)} (a bare name blocks the whole "
            "provider; suffix ':!region' to carve out a region exception)"
        )
    return result


def _validate_blocked_user_agents_value(v: Any) -> list[str]:
    from guard_core._utils.detection_scan import _redact_pattern_source
    from guard_core.detection_engine.compiler import PatternCompiler
    from guard_core.utils import _MAX_USER_AGENT_MATCH_LENGTH

    patterns = _validate_str_list_field_value(v, field_name="blocked_user_agents")
    compiler = PatternCompiler()
    for pattern in patterns:
        is_safe, reason = compiler.validate_pattern_safety(
            pattern, max_content_length=_MAX_USER_AGENT_MATCH_LENGTH
        )
        if not is_safe:
            raise ValueError(
                f"blocked_user_agents pattern rejected by ReDoS validator: "
                f"{_redact_pattern_source(pattern)!r} ({reason})"
            )
    return patterns


def _validate_dynamic_rules_cache_path_value(v: Any) -> Path | None:
    if v is None:
        return None
    if not isinstance(v, str | Path):
        raise ValueError(
            "dynamic_rules_cache_path must be a non-empty filesystem path "
            f"string or None, got {type(v).__name__}"
        )
    if not str(v).strip():
        raise ValueError(
            "dynamic_rules_cache_path must not be empty or whitespace-only; "
            "leave it unset (None) to disable the local snapshot fallback"
        )
    return Path(v)


_GLOBAL_BEHAVIOR_RULES_ADAPTER: TypeAdapter[tuple[BehaviorRuleConfig, ...]] = (
    TypeAdapter(tuple[BehaviorRuleConfig, ...])
)


_FIELD_REVALIDATORS: dict[str, Callable[[Any], Any]] = {
    "whitelist": _validate_whitelist_value,
    "blacklist": _validate_blacklist_value,
    "exempt_ips": partial(
        _validate_ip_or_cidr_list, invalid_message="Invalid IP or CIDR range"
    ),
    "trusted_proxies": _validate_trusted_proxies_value,
    "threat_ban_config": _validate_threat_ban_config_value,
    "enabled_detection_categories": _validate_enabled_detection_categories_value,
    "muted_event_types": _validate_muted_event_types_value,
    "muted_metric_types": _validate_muted_metric_types_value,
    "muted_check_logs": _validate_muted_check_logs_value,
    "log_sensitive_headers": partial(
        _validate_sensitive_name_set_value, field_name="log_sensitive_headers"
    ),
    "log_sensitive_params": partial(
        _validate_sensitive_name_set_value, field_name="log_sensitive_params"
    ),
    "log_sensitive_body_fields": partial(
        _validate_sensitive_name_set_value, field_name="log_sensitive_body_fields"
    ),
    "block_cloud_providers": _validate_block_cloud_providers_value,
    "blocked_countries": _validate_country_set_value,
    "whitelist_countries": _validate_country_set_value,
    "rate_limit": partial(_validate_int_field_value, field_name="rate_limit"),
    "rate_limit_window": partial(
        _validate_int_field_value, field_name="rate_limit_window"
    ),
    "endpoint_rate_limits": _validate_endpoint_rate_limits_value,
    "blocked_user_agents": _validate_blocked_user_agents_value,
    "enable_penetration_detection": partial(
        _validate_bool_field_value, field_name="enable_penetration_detection"
    ),
    "enable_ip_banning": partial(
        _validate_bool_field_value, field_name="enable_ip_banning"
    ),
    "enable_rate_limiting": partial(
        _validate_bool_field_value, field_name="enable_rate_limiting"
    ),
    "emergency_mode": partial(_validate_bool_field_value, field_name="emergency_mode"),
    "emergency_whitelist": partial(
        _validate_str_list_field_value, field_name="emergency_whitelist"
    ),
    "auto_ban_threshold": partial(
        _validate_positive_int_field_value, field_name="auto_ban_threshold"
    ),
    "auto_ban_duration": partial(
        _validate_positive_int_field_value, field_name="auto_ban_duration"
    ),
    "enable_rate_limit_auto_ban": partial(
        _validate_bool_field_value, field_name="enable_rate_limit_auto_ban"
    ),
    "dynamic_rules_cache_path": _validate_dynamic_rules_cache_path_value,
    "exclude_paths": partial(_validate_exclude_paths_value, stacklevel=3),
    "global_behavior_rules": partial(
        _validate_typed_collection_field_value,
        adapter=_GLOBAL_BEHAVIOR_RULES_ADAPTER,
        field_name="global_behavior_rules",
    ),
    "custom_error_responses": partial(
        _validate_typed_collection_field_value,
        adapter=_INT_KEYED_STR_DICT_ADAPTER,
        field_name="custom_error_responses",
    ),
    "security_headers": partial(
        _validate_typed_collection_field_value,
        adapter=_OPTIONAL_STR_ANY_DICT_ADAPTER,
        field_name="security_headers",
    ),
    "cors_allow_origins": partial(
        _validate_typed_collection_field_value,
        adapter=_STR_LIST_ADAPTER,
        field_name="cors_allow_origins",
    ),
    "cors_allow_methods": partial(
        _validate_typed_collection_field_value,
        adapter=_STR_LIST_ADAPTER,
        field_name="cors_allow_methods",
    ),
    "cors_allow_headers": partial(
        _validate_typed_collection_field_value,
        adapter=_STR_LIST_ADAPTER,
        field_name="cors_allow_headers",
    ),
    "cors_expose_headers": partial(
        _validate_typed_collection_field_value,
        adapter=_STR_LIST_ADAPTER,
        field_name="cors_expose_headers",
    ),
    "agent_sensitive_headers": partial(
        _validate_typed_collection_field_value,
        adapter=_OPTIONAL_STR_LIST_ADAPTER,
        field_name="agent_sensitive_headers",
    ),
    "otel_resource_attributes": partial(
        _validate_typed_collection_field_value,
        adapter=_STR_KEYED_STR_DICT_ADAPTER,
        field_name="otel_resource_attributes",
    ),
    "excluded_detection_headers": partial(
        _validate_typed_collection_field_value,
        adapter=_STR_SET_ADAPTER,
        field_name="excluded_detection_headers",
    ),
    "excluded_semantic_detection_headers": partial(
        _validate_typed_collection_field_value,
        adapter=_STR_SET_ADAPTER,
        field_name="excluded_semantic_detection_headers",
    ),
    "excluded_detection_params": partial(
        _validate_typed_collection_field_value,
        adapter=_STR_SET_ADAPTER,
        field_name="excluded_detection_params",
    ),
    "excluded_detection_body_fields": partial(
        _validate_typed_collection_field_value,
        adapter=_STR_SET_ADAPTER,
        field_name="excluded_detection_body_fields",
    ),
}
