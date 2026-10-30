import logging
import warnings
from collections.abc import Callable, ItemsView, Iterable, Iterator
from functools import partial
from ipaddress import ip_address, ip_network
from pathlib import Path
from types import MappingProxyType
from typing import (
    TYPE_CHECKING,
    Annotated,
    Literal,
    Protocol,
    get_args,
    overload,
    runtime_checkable,
)

from pydantic import AfterValidator, BaseModel, Field, TypeAdapter

from guard_core import _security_config_exempt_purge_validators as _exempt_purge
from guard_core._config_field_revalidators import (
    _validate_bool_field_value,
    _validate_endpoint_rate_limits_value,
    _validate_int_field_value,
    _validate_optional_callable_field_value,
    _validate_positive_int_field_value,
    _validate_str_list_field_value,
)
from guard_core._security_config_blocked_user_agents import (
    _validate_blocked_user_agents_value,
)
from guard_core._security_config_geo_validators import _validate_country_set_value
from guard_core._security_config_name_set_validators import (
    _frozenset_of_names,
    _ItemsByIndex,
    _validate_enabled_detection_categories_value,
    _validate_muted_check_logs_value,
    _validate_muted_event_types_value,
    _validate_muted_metric_types_value,
    _validate_sensitive_name_set_value,
)
from guard_core._security_config_typed_validators import (
    _INT_KEYED_STR_DICT_ADAPTER,
    _OPTIONAL_STR_ANY_DICT_ADAPTER,
    _OPTIONAL_STR_LIST_ADAPTER,
    _STR_KEYED_STR_DICT_ADAPTER,
    _STR_LIST_ADAPTER,
    _STR_SET_ADAPTER,
    _STR_SET_OR_CATEGORY_MAP_ADAPTER,
    _validate_typed_collection_field_value,
)
from guard_core._security_headers_override import (
    CORS_VALUE_CHECKS,
    checked_security_headers_config,
)
from guard_core._utils.whitelist_match import unwrap_ipv4_mapped_network
from guard_core.handlers.suspatterns_handler import ALL_DETECTION_CATEGORIES

if TYPE_CHECKING:
    from guard_core._security_config_fields import RequestT
    from guard_core._utils.pattern_source_redaction import _ConfigSensitiveNames
    from guard_core.models import SecurityConfig

logger = logging.getLogger("guard_core.models")


CloudProvider = Literal["AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"]
VALID_CLOUD_PROVIDERS: frozenset[str] = frozenset(get_args(CloudProvider))
_CANONICAL_CLOUD_PROVIDERS = {name.lower(): name for name in VALID_CLOUD_PROVIDERS}


def canonicalize_cloud_provider_selector(selector: object) -> str | None:
    if not isinstance(selector, str):
        return None
    name, separator, region = selector.partition(":!")
    canonical = _CANONICAL_CLOUD_PROVIDERS.get(name.lower())
    if canonical is None:
        return None
    return f"{canonical}{separator}{region}"


_GLOBAL_BEHAVIOR_RULE_FIELDS = frozenset(
    {"global_behavior_rules", "behavior_scan_response_body"}
)


def _validate_exclude_paths_value(v: object) -> list[str]:
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
        if normalized == "/" and entry != "/":
            raise ValueError(
                f"exclude_paths entry {entry!r} normalizes to the root "
                "path '/', which would exclude the root page. Write the "
                "literal '/' if you really intend that, or "
                "exclude_all_paths=True to exclude the whole application."
            )
    return v


class ThreatBanConfig(BaseModel):
    threshold: int = Field(ge=1, description="Number of detections before auto-ban.")
    duration: int = Field(ge=1, description="Ban duration in seconds.")


THREAT_BAN_CONFIG_CATEGORIES: frozenset[str] = ALL_DETECTION_CATEGORIES | frozenset(
    {
        "rate_limit",
        "honeypot",
        "auth_failure",
        "required_header",
        "referrer",
        "ip_list",
        "country",
        "cloud",
        "user_agent",
        "ip_spoofing",
    }
)


class BehaviorRuleConfig(BaseModel):
    rule_type: Literal["usage", "return_pattern", "frequency"]
    threshold: int = Field(ge=1)
    window: int = Field(default=3600, ge=1)
    pattern: str | None = None
    action: Literal["ban", "log", "throttle", "alert"] = "log"
    ban_duration: int | None = Field(default=None, ge=1)
    correlate_with_detection: bool = False


def _drop_exact_duplicate_rules(
    rules: tuple[BehaviorRuleConfig, ...],
) -> tuple[BehaviorRuleConfig, ...]:
    unique: list[BehaviorRuleConfig] = []
    for rule in rules:
        if rule not in unique:
            unique.append(rule)
    return tuple(unique)


PurgeTarget = _exempt_purge.PurgeTarget
EmergencyExemptPaths = _exempt_purge.EmergencyExemptPaths
_validate_purge_target = _exempt_purge._validate_purge_target
_validate_emergency_exempt_paths_value = (
    _exempt_purge._validate_emergency_exempt_paths_value
)

GlobalBehaviorRules = Annotated[
    tuple[BehaviorRuleConfig, ...], AfterValidator(_drop_exact_duplicate_rules)
]


def return_pattern_requires_response_body(pattern: str) -> bool:
    return not pattern.startswith("status:")


def _reject_non_numeric_status_pattern(
    pattern: str, names: "_ConfigSensitiveNames | None"
) -> None:
    from guard_core._utils.detection_scan import _redact_pattern_source

    try:
        int(pattern.partition(":")[2])
    except ValueError:
        shown = _redact_pattern_source(pattern, names)
        raise ValueError(
            f"return_pattern rule with pattern {shown!r}"
            " has no status code after 'status:'. This rule would never match: "
            "use 'status:' followed by an integer such as 'status:404'."
        ) from None


def _reject_unsafe_return_pattern_regex(
    pattern: str,
    config: "SecurityConfig[RequestT] | None",
    names: "_ConfigSensitiveNames | None",
) -> None:
    import re

    from guard_core._utils.detection_scan import _redact_pattern_source
    from guard_core.detection_engine.compiler import PatternCompiler

    cap = (
        config.behavior_max_response_body_inspect_bytes
        if config is not None
        else 262144
    )
    is_safe, reason = PatternCompiler(redaction_names=names).validate_pattern_safety(
        pattern.partition(":")[2], max_content_length=cap, flags=re.IGNORECASE
    )
    if not is_safe:
        raise ValueError(
            "return_pattern regex rejected by ReDoS validator or does not compile: "
            f"{_redact_pattern_source(pattern, names)!r} ({reason}). The pattern "
            "runs on the event loop over the response body."
        )


def _validate_return_pattern_requires_scan(
    pattern: str,
    *,
    scan_response_body: bool,
    config: "SecurityConfig[RequestT] | None" = None,
) -> None:
    from guard_core._utils.detection_scan import _redact_pattern_source
    from guard_core._utils.pattern_source_redaction import _ConfigSensitiveNames

    names = _ConfigSensitiveNames(config) if config is not None else None
    if pattern.startswith("status:"):
        _reject_non_numeric_status_pattern(pattern, names)
    if not return_pattern_requires_response_body(pattern):
        return
    if scan_response_body:
        if pattern.startswith("regex:"):
            _reject_unsafe_return_pattern_regex(pattern, config, names)
        return
    raise ValueError(
        f"return_pattern rule with pattern {_redact_pattern_source(pattern, names)!r} "
        "requires reading the "
        "response body, but behavior_scan_response_body is False. This rule "
        "would never match: set behavior_scan_response_body=True to enable "
        "response-body inspection, or use a status: pattern instead."
    )


def _validate_return_pattern_body_scan(
    pattern: str, config: "SecurityConfig[RequestT]"
) -> None:
    _validate_return_pattern_requires_scan(
        pattern, scan_response_body=config.behavior_scan_response_body, config=config
    )


def _behavior_rules_assigned(value: object) -> Iterable[BehaviorRuleConfig]:
    if not isinstance(value, Iterable):
        raise TypeError(f"'{type(value).__name__}' object is not iterable")
    rules = tuple(value)
    for rule in rules:
        if not isinstance(rule, BehaviorRuleConfig):
            raise TypeError(
                "global_behavior_rules holds a "
                f"{type(rule).__name__}, expected a BehaviorRuleConfig"
            )
    return rules


def _validate_global_behavior_rule_assignment(
    config: "SecurityConfig[RequestT]", name: str, value: object
) -> None:
    candidate_rules = (
        _behavior_rules_assigned(value)
        if name == "global_behavior_rules"
        else config.global_behavior_rules
    )
    candidate_scan_flag = (
        bool(value)
        if name == "behavior_scan_response_body"
        else config.behavior_scan_response_body
    )
    for rule in candidate_rules:
        if rule.rule_type != "return_pattern" or not rule.pattern:
            continue
        _validate_return_pattern_requires_scan(
            rule.pattern, scan_response_body=candidate_scan_flag, config=config
        )


def _revalidate_global_behavior_rules(config: "SecurityConfig[RequestT]") -> None:
    for rule in config.global_behavior_rules:
        if rule.rule_type != "return_pattern" or not rule.pattern:
            continue
        _validate_return_pattern_body_scan(rule.pattern, config)


@overload
def _validate_ip_or_cidr_list(
    v: None, *, invalid_message: str, allow_unix: bool = False
) -> None: ...


@overload
def _validate_ip_or_cidr_list(
    v: object, *, invalid_message: str, allow_unix: bool = False
) -> tuple[str, ...]: ...


def _validate_ip_or_cidr_list(
    v: object, *, invalid_message: str, allow_unix: bool = False
) -> tuple[str, ...] | None:
    if v is None:
        return None
    entries: Iterator[object]
    if isinstance(v, Iterable):
        entries = iter(v)
    elif isinstance(v, _ItemsByIndex):
        entries = iter(v)
    else:
        raise ValueError(
            f"{invalid_message}: expected a list of strings, got {type(v).__name__}"
        )
    validated: list[str] = []
    for entry in entries:
        if not isinstance(entry, str):
            raise ValueError(f"{invalid_message}: {entry}")
        if allow_unix and entry == "unix":
            validated.append("unix")
            continue
        try:
            if "/" in entry:
                validated.append(
                    str(unwrap_ipv4_mapped_network(ip_network(entry, strict=False)))
                )
            else:
                validated.append(str(ip_address(entry)))
        except ValueError:
            raise ValueError(f"{invalid_message}: {entry}") from None
    return tuple(validated)


def _validate_emergency_whitelist_value(v: object) -> list[str]:
    entries = _validate_str_list_field_value(v, field_name="emergency_whitelist")
    validated = _validate_ip_or_cidr_list(
        entries, invalid_message="Invalid IP or CIDR range"
    )
    return list(validated)


def _validate_whitelist_value(v: object) -> tuple[str, ...] | None:
    return _validate_ip_or_cidr_list(v, invalid_message="Invalid IP or CIDR range")


def _validate_blacklist_value(v: object) -> tuple[str, ...] | None:
    return _validate_ip_or_cidr_list(v, invalid_message="Invalid IP or CIDR range")


def _validate_trusted_proxies_value(v: object) -> tuple[str, ...] | None:
    return _validate_ip_or_cidr_list(
        v, invalid_message="Invalid proxy IP or CIDR range", allow_unix=True
    )


def _is_prefix_zero_network_entry(entry: str) -> bool:
    try:
        return ip_network(entry, strict=False).prefixlen == 0
    except ValueError:
        return False


def _warn_exclude_all_paths(*, stacklevel: int) -> None:
    warnings.warn(
        "exclude_all_paths=True excludes the entire application from all "
        "security checks (IP banning, rate limiting, penetration detection, "
        "everything). Confirm this is intentional.",
        UserWarning,
        stacklevel=stacklevel,
    )


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


@runtime_checkable
class _KeysAndItems(Protocol):
    """The mapping surface ``dict()`` and ``**`` read: ``keys()`` plus item access.

    An entry or a whole ``threat_ban_config`` may be any object with this surface,
    not only a ``Mapping`` subclass.
    """

    def keys(self) -> Iterable[str]: ...

    def __getitem__(self, key: str, /) -> object: ...


def _threat_ban_entry(key: object, value: object) -> ThreatBanConfig:
    if isinstance(value, ThreatBanConfig):
        return value
    if isinstance(value, _KeysAndItems):
        try:
            return ThreatBanConfig(**value)
        except TypeError:
            pass
    raise ValueError(
        f"threat_ban_config[{key!r}] must be a ThreatBanConfig or a dict "
        f"with str keys, got {type(value).__name__}"
    )


def _threat_ban_items(v: object) -> ItemsView[object, object]:
    if isinstance(v, Iterable | _KeysAndItems):
        try:
            return dict(v).items()
        except TypeError:
            pass
    raise ValueError(
        "threat_ban_config must be a dict of category to ThreatBanConfig, "
        f"got {type(v).__name__}"
    )


def _validate_threat_ban_config_value(
    v: object,
) -> MappingProxyType[str, ThreatBanConfig]:
    mapping = {
        key: _threat_ban_entry(key, value) for key, value in _threat_ban_items(v)
    }
    unknown = set(mapping.keys()) - THREAT_BAN_CONFIG_CATEGORIES
    if unknown:
        raise ValueError(
            f"Unknown threat categories in threat_ban_config: "
            f"{sorted(unknown, key=str)}. "
            f"Valid: {sorted(THREAT_BAN_CONFIG_CATEGORIES)}"
        )
    return MappingProxyType(
        {key: entry for key, entry in mapping.items() if isinstance(key, str)}
    )


def _validate_excluded_detection_params_value(
    v: object, field_name: str = "excluded_detection_params"
) -> set[str] | dict[str, set[str]]:
    result = _validate_typed_collection_field_value(
        v,
        adapter=_STR_SET_OR_CATEGORY_MAP_ADAPTER,
        field_name=field_name,
    )
    if isinstance(result, dict):
        _check_excluded_params_categories(result, field_name)
    return result


def _check_excluded_params_categories(
    mapping: dict[str, set[str]], field_name: str
) -> None:
    for param, categories in mapping.items():
        if not categories:
            raise ValueError(
                f"{field_name} lists no category for {param!r}: "
                "name at least one, or list the parameter in a plain set to "
                "exclude every category"
            )
        unknown = categories - ALL_DETECTION_CATEGORIES
        if unknown:
            raise ValueError(
                f"Unknown detection categories for {field_name} "
                f"{param!r}: {sorted(unknown)}. Valid: "
                f"{sorted(ALL_DETECTION_CATEGORIES)}"
            )


def _validate_block_cloud_providers_value(v: object) -> frozenset[str] | None:
    if v is None:
        return None
    selectors = _frozenset_of_names(v, "block_cloud_providers")
    canonical = {sel: canonicalize_cloud_provider_selector(sel) for sel in selectors}
    invalid = {sel for sel, name in canonical.items() if name is None}
    result = frozenset(name for name in canonical.values() if name is not None)
    if invalid:
        raise ValueError(
            "Unknown cloud providers in block_cloud_providers: "
            f"{sorted(invalid, key=str)}. "
            f"Valid: {sorted(VALID_CLOUD_PROVIDERS)} (a bare name blocks the whole "
            "provider; suffix ':!region' to carve out a region exception)"
        )
    return result


def _validate_dynamic_rules_cache_path_value(v: object) -> Path | None:
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
    TypeAdapter(GlobalBehaviorRules)
)


_CORS_OVERRIDE_KEYS = {
    "cors_allow_origins": "cors_origins",
    "cors_allow_methods": "cors_allow_methods",
    "cors_allow_headers": "cors_allow_headers",
    "cors_expose_headers": "cors_expose_headers",
}


def _validate_cors_values(
    v: object, *, override_key: str, field_name: str
) -> list[str]:
    values = _validate_typed_collection_field_value(
        v, adapter=_STR_LIST_ADAPTER, field_name=field_name
    )
    if not all(map(CORS_VALUE_CHECKS[override_key], values)):
        raise ValueError(f"{field_name} holds a control character or an invalid origin")
    return values


def _validate_cors_field_value(field_name: str, v: object) -> list[str]:
    return _validate_cors_values(
        v, override_key=_CORS_OVERRIDE_KEYS[field_name], field_name=field_name
    )


def _validate_security_headers_value(v: object) -> dict[str, object] | None:
    headers = _validate_typed_collection_field_value(
        v, adapter=_OPTIONAL_STR_ANY_DICT_ADAPTER, field_name="security_headers"
    )
    if headers:
        checked_security_headers_config(headers)
    return headers


_FIELD_REVALIDATORS: dict[str, Callable[[object], object]] = {
    "custom_request_check": partial(
        _validate_optional_callable_field_value, field_name="custom_request_check"
    ),
    "custom_response_modifier": partial(
        _validate_optional_callable_field_value, field_name="custom_response_modifier"
    ),
    "auth_verifier": partial(
        _validate_optional_callable_field_value, field_name="auth_verifier"
    ),
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
    "emergency_whitelist": _validate_emergency_whitelist_value,
    "emergency_exempt_paths": _validate_emergency_exempt_paths_value,
    "emergency_whitelist_only": partial(
        _validate_bool_field_value, field_name="emergency_whitelist_only"
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
    "exclude_paths": _validate_exclude_paths_value,
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
    "security_headers": _validate_security_headers_value,
    "cors_allow_origins": partial(
        _validate_cors_values,
        override_key=_CORS_OVERRIDE_KEYS["cors_allow_origins"],
        field_name="cors_allow_origins",
    ),
    "cors_allow_methods": partial(
        _validate_cors_values,
        override_key=_CORS_OVERRIDE_KEYS["cors_allow_methods"],
        field_name="cors_allow_methods",
    ),
    "cors_allow_headers": partial(
        _validate_cors_values,
        override_key=_CORS_OVERRIDE_KEYS["cors_allow_headers"],
        field_name="cors_allow_headers",
    ),
    "cors_expose_headers": partial(
        _validate_cors_values,
        override_key=_CORS_OVERRIDE_KEYS["cors_expose_headers"],
        field_name="cors_expose_headers",
    ),
    "nat64_prefixes": partial(
        _validate_typed_collection_field_value,
        adapter=_STR_LIST_ADAPTER,
        field_name="nat64_prefixes",
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
    "excluded_detection_params": _validate_excluded_detection_params_value,
    "excluded_detection_body_fields": partial(
        _validate_excluded_detection_params_value,
        field_name="excluded_detection_body_fields",
    ),
}


def require_agent_config(config: "SecurityConfig[RequestT]") -> None:
    if config.enable_agent and not config.agent_api_key:
        raise ValueError("agent_api_key is required when enable_agent is True")

    if config.enable_dynamic_rules and not config.enable_agent:
        raise ValueError("enable_agent must be True when enable_dynamic_rules is True")

    if config.enable_enrichment and not config.enable_agent:
        raise ValueError(
            "enable_enrichment requires enable_agent=True; enrichment is "
            "the guard-agent-gated tier. Either enable guard-agent or set "
            "enable_enrichment=False."
        )
