import logging
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING

from pydantic import BaseModel

from guard_core._config_capabilities import (
    _extra_installed,
    cloud_blocking_enabled,
    require_cloud_extra,
    require_geo_extra,
    require_redis_extra,
)
from guard_core._redis_enablement import (
    REDIS_CONNECTION_FIELDS,
    resolve_enable_redis,
)
from guard_core._security_config_blocked_user_agents import (
    _redact_invalid_blocked_user_agents_input,
    _reject_redos_unsafe_blocked_user_agents,
    _reject_redos_unsafe_blocked_user_agents_at_field,
    _validate_blocked_user_agents_structure,
    _validate_blocked_user_agents_value,
)
from guard_core._security_config_field_validators import (
    _FIELD_REVALIDATORS,
    _GLOBAL_BEHAVIOR_RULE_FIELDS,
    THREAT_BAN_CONFIG_CATEGORIES,
    VALID_CLOUD_PROVIDERS,
    BehaviorRuleConfig,
    CloudProvider,
    ThreatBanConfig,
    _is_prefix_zero_network_entry,
    _revalidate_global_behavior_rules,
    _validate_blacklist_value,
    _validate_block_cloud_providers_value,
    _validate_cors_field_value,
    _validate_dynamic_rules_cache_path_value,
    _validate_emergency_whitelist_value,
    _validate_enabled_detection_categories_value,
    _validate_exclude_paths_value,
    _validate_excluded_detection_params_value,
    _validate_global_behavior_rule_assignment,
    _validate_ip_or_cidr_list,
    _validate_muted_check_logs_value,
    _validate_muted_event_types_value,
    _validate_muted_metric_types_value,
    _validate_return_pattern_body_scan,
    _validate_return_pattern_requires_scan,
    _validate_security_headers_value,
    _validate_sensitive_name_set_value,
    _validate_threat_ban_config_value,
    _validate_trusted_proxies_value,
    _validate_whitelist_value,
    _warn_empty_enabled_detection_categories,
    _warn_exclude_all_paths,
    _warn_exempt_ips_prefix_zero,
    _warn_trusted_proxies_prefix_zero,
    _warn_whitelist_prefix_zero,
    return_pattern_requires_response_body,
)
from guard_core._security_config_geo_validators import (
    _COUNTRY_RULE_FIELDS,
    _GEO_STATE_FIELDS,
    _apply_geo_ip_handler_assignment,
    _apply_geo_ip_handler_copy,
    _country_shadow_should_warn,
    _geo_state_candidates,
    _normalized_country_value,
    _resolve_geo_ip_handler,
    _validate_country_set_value,
    _warn_country_allowlist_shadows_blocklist,
)

if TYPE_CHECKING:
    from guard_core._security_config_fields import RequestT
    from guard_core.models import SecurityConfig


logger = logging.getLogger("guard_core.models")

__all__ = [
    "VALID_CLOUD_PROVIDERS",
    "BehaviorRuleConfig",
    "CloudProvider",
    "THREAT_BAN_CONFIG_CATEGORIES",
    "ThreatBanConfig",
    "_FIELD_REVALIDATORS",
    "_GEO_STATE_FIELDS",
    "_GLOBAL_BEHAVIOR_RULE_FIELDS",
    "_apply_geo_ip_handler_assignment",
    "_assign_checking_optional_extras",
    "_country_shadow_should_warn",
    "_extra_installed",
    "_geo_state_candidates",
    "_is_prefix_zero_network_entry",
    "_normalized_country_value",
    "_reject_redos_unsafe_blocked_user_agents",
    "_redact_blocked_user_agents_in_input",
    "_reject_redos_unsafe_blocked_user_agents_at_field",
    "_require_optional_extras",
    "_resolve_geo_ip_handler",
    "_revalidate_copied_config",
    "_revalidate_field_value",
    "_validate_blacklist_value",
    "_validate_block_cloud_providers_value",
    "_validate_blocked_user_agents_structure",
    "_validate_blocked_user_agents_value",
    "_validate_country_set_value",
    "_validate_cors_field_value",
    "_validate_dynamic_rules_cache_path_value",
    "_validate_emergency_whitelist_value",
    "_validate_enabled_detection_categories_value",
    "_validate_excluded_detection_params_value",
    "_validate_exclude_paths_value",
    "_validate_global_behavior_rule_assignment",
    "_validate_ip_or_cidr_list",
    "_validate_muted_check_logs_value",
    "_validate_muted_event_types_value",
    "_validate_muted_metric_types_value",
    "_validate_return_pattern_body_scan",
    "_validate_return_pattern_requires_scan",
    "_validate_security_headers_value",
    "_validate_sensitive_name_set_value",
    "_validate_threat_ban_config_value",
    "_validate_trusted_proxies_value",
    "_validate_whitelist_value",
    "_warn_country_allowlist_shadows_blocklist",
    "_warn_empty_enabled_detection_categories",
    "_warn_exempt_ips_prefix_zero",
    "_warn_exclude_all_paths",
    "_warn_trusted_proxies_prefix_zero",
    "_warn_whitelist_prefix_zero",
    "cloud_blocking_enabled",
    "return_pattern_requires_response_body",
]


_SENSITIVE_NAME_FIELDS = (
    "log_sensitive_headers",
    "log_sensitive_params",
    "log_sensitive_body_fields",
)


class _InputSensitiveNames:
    def __init__(self, names: Mapping[str, frozenset[str]]) -> None:
        self._sensitive_headers_union = names["log_sensitive_headers"]
        self._sensitive_params_union = names["log_sensitive_params"]
        self._sensitive_body_fields_union = names["log_sensitive_body_fields"]


def _redact_blocked_user_agents_in_input(
    data: object, field_defaults: Callable[[], Mapping[str, object]]
) -> object:
    if not isinstance(data, Mapping) or "blocked_user_agents" not in data:
        return data
    from guard_core._utils.detection_scan import _redact_pattern_source

    def redact_everything(pattern: str) -> str:
        return "[REDACTED]"

    redact = redact_everything
    defaults = field_defaults()
    try:
        names = {
            field: _validate_sensitive_name_set_value(
                data.get(field, defaults[field]), field
            )
            for field in _SENSITIVE_NAME_FIELDS
        }
    except (TypeError, ValueError):
        pass
    else:
        sensitive = _InputSensitiveNames(names)

        def redact(pattern: str) -> str:
            return _redact_pattern_source(pattern, sensitive)

    return {
        **data,
        "blocked_user_agents": _redact_invalid_blocked_user_agents_input(
            data["blocked_user_agents"], redact
        ),
    }


def _revalidate_field_value(
    config: "SecurityConfig[RequestT]",
    name: str,
    value: object,
    pending: Mapping[str, object] | None = None,
) -> object:
    if name != "blocked_user_agents":
        return _FIELD_REVALIDATORS[name](value)
    from guard_core._utils.pattern_source_redaction import _ConfigSensitiveNames

    names = {
        field: _validate_sensitive_name_set_value(pending[field], field)
        for field in _SENSITIVE_NAME_FIELDS
        if pending is not None and field in pending
    }
    return _validate_blocked_user_agents_value(
        value, _ConfigSensitiveNames(config, **names)
    )


def _revalidate_exclude_paths_field(
    copied: "SecurityConfig[RequestT]", update: Mapping[str, object]
) -> None:
    if "exclude_paths" in update:
        _validate_exclude_paths_value(copied.exclude_paths)


def _revalidate_country_shadow_fields(
    copied: "SecurityConfig[RequestT]", update: Mapping[str, object]
) -> None:
    if (
        _COUNTRY_RULE_FIELDS & update.keys()
        and copied.whitelist_countries
        and copied.blocked_countries
    ):
        _warn_country_allowlist_shadows_blocklist(stacklevel=5)


def _revalidate_global_behavior_rule_fields(
    copied: "SecurityConfig[RequestT]", update: Mapping[str, object]
) -> None:
    if _GLOBAL_BEHAVIOR_RULE_FIELDS & update.keys():
        _revalidate_global_behavior_rules(copied)


def _revalidate_geo_state_fields(
    copied: "SecurityConfig[RequestT]", update: Mapping[str, object]
) -> None:
    if _GEO_STATE_FIELDS & update.keys():
        _apply_geo_ip_handler_copy(copied)


_FIELDS_WITH_DEDICATED_COPY_REVALIDATION = frozenset({"exclude_paths"})


def _revalidate_changed_fields(
    copied: "SecurityConfig[RequestT]", update: Mapping[str, object]
) -> None:
    fields = _FIELD_REVALIDATORS.keys() & update.keys()
    fields -= _FIELDS_WITH_DEDICATED_COPY_REVALIDATION
    for field_name in fields:
        BaseModel.__setattr__(
            copied,
            field_name,
            _revalidate_field_value(copied, field_name, getattr(copied, field_name)),
        )


def _revalidate_copied_config(
    copied: "SecurityConfig[RequestT]", update: Mapping[str, object]
) -> None:
    resolve_enable_redis(copied)
    _revalidate_exclude_paths_field(copied, update)
    _revalidate_country_shadow_fields(copied, update)
    _revalidate_geo_state_fields(copied, update)
    _revalidate_changed_fields(copied, update)
    _revalidate_global_behavior_rule_fields(copied, update)
    _require_optional_extras(copied)


def _require_recidive_cap_covers_auto_ban(config: "SecurityConfig[RequestT]") -> None:
    if (
        config.enable_recidive
        and config.recidive_max_duration < config.auto_ban_duration
    ):
        raise ValueError(
            "recidive_max_duration must be >= auto_ban_duration when "
            "enable_recidive is True"
        )


_EXTRA_GATED_FIELDS = frozenset(
    {
        *REDIS_CONNECTION_FIELDS,
        "enable_redis",
        "block_cloud_providers",
        "enable_dynamic_rules",
    }
)


def _assign_checking_optional_extras(
    config: "SecurityConfig[RequestT]", name: str, assign: Callable[[], None]
) -> None:
    if name not in _EXTRA_GATED_FIELDS:
        assign()
        return
    previous = {key: config.__dict__[key] for key in {name, "enable_redis"}}
    fields_set = set(config.__pydantic_fields_set__)
    assign()
    try:
        resolve_enable_redis(config)
        _require_optional_extras(config)
    except ValueError:
        config.__dict__.update(previous)
        config.__pydantic_fields_set__.clear()
        config.__pydantic_fields_set__.update(fields_set)
        raise


def _require_optional_extras(config: "SecurityConfig[RequestT]") -> None:
    if config.enable_redis and config.redis_url:
        require_redis_extra()

    if config.block_cloud_providers or config.enable_dynamic_rules:
        require_cloud_extra()

    has_country_rules = bool(config.blocked_countries or config.whitelist_countries)
    if config.geo_ip_handler is None and has_country_rules:
        require_geo_extra()
