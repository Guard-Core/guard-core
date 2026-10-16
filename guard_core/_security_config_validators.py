import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from guard_core._config_capabilities import _extra_installed, cloud_blocking_enabled
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
    _validate_blocked_user_agents_value,
    _validate_dynamic_rules_cache_path_value,
    _validate_enabled_detection_categories_value,
    _validate_exclude_paths_value,
    _validate_global_behavior_rule_assignment,
    _validate_ip_or_cidr_list,
    _validate_muted_check_logs_value,
    _validate_muted_event_types_value,
    _validate_muted_metric_types_value,
    _validate_return_pattern_body_scan,
    _validate_return_pattern_requires_scan,
    _validate_sensitive_name_set_value,
    _validate_threat_ban_config_value,
    _validate_trusted_proxies_value,
    _validate_whitelist_value,
    _warn_empty_enabled_detection_categories,
    _warn_exempt_ips_prefix_zero,
    _warn_hostile_signal_bans_default_off,
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
    "_country_shadow_should_warn",
    "_extra_installed",
    "_geo_state_candidates",
    "_is_prefix_zero_network_entry",
    "_normalized_country_value",
    "_resolve_geo_ip_handler",
    "_revalidate_copied_config",
    "_validate_blacklist_value",
    "_validate_block_cloud_providers_value",
    "_validate_blocked_user_agents_value",
    "_validate_country_set_value",
    "_validate_dynamic_rules_cache_path_value",
    "_validate_enabled_detection_categories_value",
    "_validate_exclude_paths_value",
    "_validate_global_behavior_rule_assignment",
    "_validate_ip_or_cidr_list",
    "_validate_muted_check_logs_value",
    "_validate_muted_event_types_value",
    "_validate_muted_metric_types_value",
    "_validate_return_pattern_body_scan",
    "_validate_return_pattern_requires_scan",
    "_validate_sensitive_name_set_value",
    "_validate_threat_ban_config_value",
    "_validate_trusted_proxies_value",
    "_validate_whitelist_value",
    "_warn_country_allowlist_shadows_blocklist",
    "_warn_empty_enabled_detection_categories",
    "_warn_exempt_ips_prefix_zero",
    "_warn_hostile_signal_bans_default_off",
    "_warn_trusted_proxies_prefix_zero",
    "_warn_whitelist_prefix_zero",
    "cloud_blocking_enabled",
    "return_pattern_requires_response_body",
]


def _revalidate_exclude_paths_field(
    copied: "SecurityConfig", update: Mapping[str, Any]
) -> None:
    if "exclude_paths" in update:
        _validate_exclude_paths_value(copied.exclude_paths, stacklevel=5)


def _revalidate_country_shadow_fields(
    copied: "SecurityConfig", update: Mapping[str, Any]
) -> None:
    if (
        _COUNTRY_RULE_FIELDS & update.keys()
        and copied.whitelist_countries
        and copied.blocked_countries
    ):
        _warn_country_allowlist_shadows_blocklist(stacklevel=5)


def _revalidate_global_behavior_rule_fields(
    copied: "SecurityConfig", update: Mapping[str, Any]
) -> None:
    if _GLOBAL_BEHAVIOR_RULE_FIELDS & update.keys():
        _revalidate_global_behavior_rules(copied)


def _revalidate_geo_state_fields(
    copied: "SecurityConfig", update: Mapping[str, Any]
) -> None:
    if _GEO_STATE_FIELDS & update.keys():
        _apply_geo_ip_handler_copy(copied)


_FIELDS_WITH_DEDICATED_COPY_REVALIDATION = frozenset({"exclude_paths"})


def _revalidate_changed_fields(
    copied: "SecurityConfig", update: Mapping[str, Any]
) -> None:
    fields = _FIELD_REVALIDATORS.keys() & update.keys()
    fields -= _FIELDS_WITH_DEDICATED_COPY_REVALIDATION
    for field_name in fields:
        BaseModel.__setattr__(
            copied,
            field_name,
            _FIELD_REVALIDATORS[field_name](getattr(copied, field_name)),
        )


def _revalidate_copied_config(
    copied: "SecurityConfig", update: Mapping[str, Any]
) -> None:
    _revalidate_exclude_paths_field(copied, update)
    _revalidate_country_shadow_fields(copied, update)
    _revalidate_geo_state_fields(copied, update)
    _revalidate_changed_fields(copied, update)
    _revalidate_global_behavior_rule_fields(copied, update)
