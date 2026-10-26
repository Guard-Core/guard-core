import contextvars
import difflib
import logging
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import (
    ConfigDict,
    ModelWrapValidatorHandler,
    PrivateAttr,
    ValidationInfo,
    field_validator,
    model_validator,
)
from typing_extensions import Self

from guard_core import __version__
from guard_core._config_capabilities import _extra_installed as _extra_installed
from guard_core._config_capabilities import (
    cloud_blocking_enabled as cloud_blocking_enabled,
)
from guard_core._dynamic_rules import DynamicRules as DynamicRules
from guard_core._misconfiguration import report_config_misconfigurations
from guard_core._security_config_fields import RequestT, _SecurityConfigFields
from guard_core._security_config_validators import (
    _FIELD_REVALIDATORS,
    _GEO_STATE_FIELDS,
    _GLOBAL_BEHAVIOR_RULE_FIELDS,
    _SENSITIVE_NAME_FIELDS,
    _apply_geo_ip_handler_assignment,
    _assign_checking_optional_extras,
    _country_shadow_should_warn,
    _is_prefix_zero_network_entry,
    _redact_blocked_user_agents_in_input,
    _reject_redos_unsafe_blocked_user_agents_at_field,
    _require_optional_extras,
    _require_recidive_cap_covers_auto_ban,
    _resolve_geo_ip_handler,
    _revalidate_copied_config,
    _revalidate_field_value,
    _validate_block_cloud_providers_value,
    _validate_blocked_user_agents_structure,
    _validate_country_set_value,
    _validate_dynamic_rules_cache_path_value,
    _validate_enabled_detection_categories_value,
    _validate_exclude_paths_value,
    _validate_global_behavior_rule_assignment,
    _validate_ip_or_cidr_list,
    _validate_muted_check_logs_value,
    _validate_muted_event_types_value,
    _validate_muted_metric_types_value,
    _validate_return_pattern_body_scan,
    _validate_sensitive_name_set_value,
    _validate_threat_ban_config_value,
    _warn_country_allowlist_shadows_blocklist,
    _warn_empty_enabled_detection_categories,
    _warn_exclude_all_paths,
    _warn_exempt_ips_prefix_zero,
    _warn_trusted_proxies_prefix_zero,
    _warn_whitelist_prefix_zero,
)
from guard_core._security_config_validators import (
    VALID_CLOUD_PROVIDERS as VALID_CLOUD_PROVIDERS,
)
from guard_core._security_config_validators import (
    BehaviorRuleConfig as BehaviorRuleConfig,
)
from guard_core._security_config_validators import CloudProvider as CloudProvider
from guard_core._security_config_validators import (
    ThreatBanConfig as ThreatBanConfig,
)
from guard_core._security_config_validators import (
    return_pattern_requires_response_body as return_pattern_requires_response_body,
)
from guard_core._staged_defaults import (
    signal_changed_defaults,
    warn_redis_prefix_left_default,
)
from guard_core._utils.pattern_source_redaction import _ConfigSensitiveNames
from guard_core.exceptions import AgentPackageNotInstalledError
from guard_core.handlers.suspatterns_handler import (
    ALL_DETECTION_CATEGORIES as ALL_DETECTION_CATEGORIES,
)
from guard_core.protocols.cloud_ip_store_protocol import (
    CloudIpStoreFactory as CloudIpStoreFactory,
)
from guard_core.protocols.cloud_ip_store_protocol import (
    CloudIpStoreProtocol as CloudIpStoreProtocol,
)
from guard_core.protocols.geo_ip_protocol import GeoIPHandler as GeoIPHandler
from guard_core.protocols.request_protocol import GuardRequest as GuardRequest
from guard_core.protocols.response_protocol import GuardResponse as GuardResponse
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

if TYPE_CHECKING:
    from guard_agent import AgentConfig


VALID_BYPASS_CHECKS: frozenset[str] = frozenset(
    {"all", "ip_ban", "ip", "clouds", "rate_limit", "penetration"}
)

logger = logging.getLogger("guard_core.models")

_skip_revalidation: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "guard_core_security_config_skip_revalidation", default=False
)


class _NoPatternManager:
    _config = None


class SecurityConfig(_SecurityConfigFields[RequestT]):
    model_config = ConfigDict(arbitrary_types_allowed=True, hide_input_in_errors=True)

    _revision: int = PrivateAttr(default=0)
    # The app's pattern manager, parked on the instance by sus_patterns_manager_for
    # so the request path reads it as an attribute, without a registry lookup.
    _guard_pattern_manager: ClassVar[Any] = _NoPatternManager()

    def _current_revision(self) -> int:
        private = self.__pydantic_private__
        fallback = private.get("_revision", 0) if private is not None else 0
        stored = self.__dict__.get("_revision", fallback)
        return stored if isinstance(stored, int) else 0

    def __setattr__(self, name: str, value: Any) -> None:
        if name in _GEO_STATE_FIELDS:
            value = _apply_geo_ip_handler_assignment(self, name, value)
        if name in _FIELD_REVALIDATORS and not _skip_revalidation.get():
            value = _revalidate_field_value(self, name, value)
        if name in _GLOBAL_BEHAVIOR_RULE_FIELDS:
            _validate_global_behavior_rule_assignment(self, name, value)

        should_warn = _country_shadow_should_warn(self, name, value)

        _assign_checking_optional_extras(
            self, name, lambda: super(SecurityConfig, self).__setattr__(name, value)
        )
        if name != "_revision":
            object.__setattr__(self, "_revision", self._current_revision() + 1)
        if should_warn:
            _warn_country_allowlist_shadows_blocklist(stacklevel=3)

    def _set_prevalidated(self, name: str, value: Any) -> None:
        token = _skip_revalidation.set(True)
        try:
            setattr(self, name, value)
        finally:
            _skip_revalidation.reset(token)

    @property
    def revision(self) -> int:
        return self._current_revision()

    def __getstate__(self) -> dict[Any, Any]:
        # threat_ban_config is a read-only mappingproxy, which neither pickle nor
        # deepcopy can handle: it travels as a dict and is frozen again on load.
        state = super().__getstate__()
        state["__dict__"] = {
            **state["__dict__"],
            "threat_ban_config": dict(self.threat_ban_config),
        }
        return state

    def __setstate__(self, state: dict[Any, Any]) -> None:
        frozen = MappingProxyType(state["__dict__"]["threat_ban_config"])
        state["__dict__"] = {**state["__dict__"], "threat_ban_config": frozen}
        super().__setstate__(state)

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        clone = self.__class__.__new__(self.__class__)
        clone.__setstate__(deepcopy(self.__getstate__(), memo))
        return clone

    def model_copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False
    ) -> Self:
        copied = super().model_copy(update=update, deep=deep)
        if update:
            _revalidate_copied_config(copied, update)
        return copied

    @model_validator(mode="before")
    @classmethod
    def warn_unknown_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        known = set(cls.model_fields)
        known.update(field.alias for field in cls.model_fields.values() if field.alias)

        unknown = set(data) - known
        for key in sorted(unknown):
            match = difflib.get_close_matches(str(key), known, n=1)
            hint = f" Did you mean '{match[0]}'?" if match else ""
            logger.warning(
                "SecurityConfig received unknown field '%s'; it was ignored "
                "and had no effect.%s",
                key,
                hint,
            )
        return data

    @field_validator("whitelist", "blacklist", "exempt_ips", mode="before")
    def validate_ip_lists(cls, v: Any) -> Any:
        return _validate_ip_or_cidr_list(v, invalid_message="Invalid IP or CIDR range")

    @field_validator("emergency_whitelist", mode="before")
    def validate_emergency_whitelist(cls, v: Any) -> list[str]:
        validated: list[str] = _FIELD_REVALIDATORS["emergency_whitelist"](v)
        return validated

    @field_validator("trusted_proxies", mode="before")
    def validate_trusted_proxies(cls, v: Any) -> Any:
        return _validate_ip_or_cidr_list(
            v, invalid_message="Invalid proxy IP or CIDR range", allow_unix=True
        )

    @field_validator("trusted_proxy_depth")
    def validate_proxy_depth(cls, v: int) -> int:
        if v < 1:
            raise ValueError("trusted_proxy_depth must be at least 1")
        return v

    @field_validator("whitelist_countries", "blocked_countries", mode="before")
    def coerce_country_set(cls, v: Any) -> frozenset[str]:
        return _validate_country_set_value(v)

    @field_validator(
        "cors_allow_origins",
        "cors_allow_methods",
        "cors_allow_headers",
        "cors_expose_headers",
        mode="before",
    )
    def validate_cors_values(cls, v: object, info: ValidationInfo) -> list[str]:
        validated: list[str] = _FIELD_REVALIDATORS[str(info.field_name)](v)
        return validated

    @field_validator("block_cloud_providers", mode="before")
    def validate_cloud_providers(cls, v: Any) -> frozenset[str] | None:
        return _validate_block_cloud_providers_value(v)

    @field_validator("blocked_user_agents", mode="before")
    def validate_blocked_user_agents(cls, v: Any) -> list[str]:
        return _validate_blocked_user_agents_structure(v)

    @model_validator(mode="wrap")
    @classmethod
    def reject_redos_unsafe_blocked_user_agents(
        cls, data: object, handler: ModelWrapValidatorHandler[Self]
    ) -> Self:
        config = handler(
            _redact_blocked_user_agents_in_input(
                data,
                {
                    f: cls.model_fields[f].get_default(call_default_factory=True)
                    for f in _SENSITIVE_NAME_FIELDS
                },
            )
        )
        _reject_redos_unsafe_blocked_user_agents_at_field(
            cls.__name__, config.blocked_user_agents, _ConfigSensitiveNames(config)
        )
        return config

    @model_validator(mode="after")
    def validate_optional_extras_installed(self) -> Self:
        _require_optional_extras(self)
        return self

    @model_validator(mode="after")
    def validate_geo_ip_handler_exists(self) -> Self:
        resolved = _resolve_geo_ip_handler(
            blocked_countries=self.blocked_countries,
            whitelist_countries=self.whitelist_countries,
            geo_ip_handler=self.geo_ip_handler,
            ipinfo_token=self.ipinfo_token,
            ipinfo_db_path=self.ipinfo_db_path,
            ipinfo_download_url=self.ipinfo_download_url,
            geo_ip_db_max_age=self.geo_ip_db_max_age,
        )
        if resolved is not self.geo_ip_handler:
            self.geo_ip_handler = resolved

        return self

    @model_validator(mode="after")
    def warn_country_allowlist_shadows_blocklist(self) -> Self:
        if self.whitelist_countries and self.blocked_countries:
            _warn_country_allowlist_shadows_blocklist(stacklevel=4)
        return self

    @model_validator(mode="after")
    def validate_agent_config(self) -> Self:
        if self.enable_agent and not self.agent_api_key:
            raise ValueError("agent_api_key is required when enable_agent is True")

        if self.enable_dynamic_rules and not self.enable_agent:
            raise ValueError(
                "enable_agent must be True when enable_dynamic_rules is True"
            )

        if self.enable_enrichment and not self.enable_agent:
            raise ValueError(
                "enable_enrichment requires enable_agent=True; enrichment is "
                "the guard-agent-gated tier. Either enable guard-agent or set "
                "enable_enrichment=False."
            )

        return self

    @model_validator(mode="after")
    def validate_recidive_cap(self) -> Self:
        _require_recidive_cap_covers_auto_ban(self)
        return self

    @model_validator(mode="after")
    def validate_global_return_pattern_body_scan(self) -> Self:
        for rule in self.global_behavior_rules:
            if rule.rule_type != "return_pattern" or not rule.pattern:
                continue
            _validate_return_pattern_body_scan(rule.pattern, self)
        return self

    @model_validator(mode="after")
    def warn_trusted_proxies_prefix_zero(self) -> Self:
        if any(_is_prefix_zero_network_entry(entry) for entry in self.trusted_proxies):
            _warn_trusted_proxies_prefix_zero()
        return self

    @model_validator(mode="after")
    def warn_whitelist_prefix_zero(self) -> Self:
        if any(_is_prefix_zero_network_entry(entry) for entry in self.whitelist or ()):
            _warn_whitelist_prefix_zero()
        return self

    @model_validator(mode="after")
    def warn_exempt_ips_prefix_zero(self) -> Self:
        _warn_exempt_ips_prefix_zero(self.exempt_ips)
        return self

    @model_validator(mode="after")
    def warn_exclude_all_paths(self) -> Self:
        if self.exclude_all_paths:
            _warn_exclude_all_paths(stacklevel=4)
        return self

    @model_validator(mode="after")
    def report_misconfigurations(self) -> Self:
        report_config_misconfigurations(self, stacklevel=4)
        return self

    @model_validator(mode="after")
    def warn_changed_defaults(self) -> Self:
        signal_changed_defaults(self)
        warn_redis_prefix_left_default(self)
        return self

    @model_validator(mode="after")
    def warn_empty_enabled_detection_categories(self) -> Self:
        if self.enable_penetration_detection and not self.enabled_detection_categories:
            _warn_empty_enabled_detection_categories()
        return self

    @field_validator("muted_event_types", mode="before")
    def validate_muted_event_types(cls, v: Any) -> frozenset[str]:
        return _validate_muted_event_types_value(v)

    @field_validator("muted_metric_types", mode="before")
    def validate_muted_metric_types(cls, v: Any) -> frozenset[str]:
        return _validate_muted_metric_types_value(v)

    @field_validator("enabled_detection_categories", mode="before")
    def validate_enabled_detection_categories(cls, v: Any) -> frozenset[str]:
        return _validate_enabled_detection_categories_value(v)

    @field_validator("threat_ban_config", mode="before")
    def validate_threat_ban_config(cls, v: Any) -> MappingProxyType[str, Any]:
        return _validate_threat_ban_config_value(v)

    @field_validator("muted_check_logs", mode="before")
    def validate_muted_check_logs(cls, v: Any) -> frozenset[str]:
        return _validate_muted_check_logs_value(v)

    @field_validator("log_sensitive_headers", mode="before")
    def validate_log_sensitive_headers(cls, v: Any) -> frozenset[str]:
        return _validate_sensitive_name_set_value(v, "log_sensitive_headers")

    @field_validator("log_sensitive_params", mode="before")
    def validate_log_sensitive_params(cls, v: Any) -> frozenset[str]:
        return _validate_sensitive_name_set_value(v, "log_sensitive_params")

    @field_validator("log_sensitive_body_fields", mode="before")
    def validate_log_sensitive_body_fields(cls, v: Any) -> frozenset[str]:
        return _validate_sensitive_name_set_value(v, "log_sensitive_body_fields")

    @field_validator("exclude_paths")
    def validate_exclude_paths(cls, v: list[str]) -> list[str]:
        return _validate_exclude_paths_value(v)

    @field_validator("dynamic_rules_cache_path", mode="before")
    def validate_dynamic_rules_cache_path(cls, v: Any) -> Path | None:
        return _validate_dynamic_rules_cache_path_value(v)

    def to_agent_config(self) -> "AgentConfig | None":
        if not self.enable_agent or not self.agent_api_key:
            return None

        from guard_core._pydantic_plugin_mute import (
            _mute_pydantic_plugin_instrumentation,
        )

        _mute_pydantic_plugin_instrumentation()

        try:
            from guard_agent import AgentConfig

            kwargs: dict[str, Any] = {
                "api_key": self.agent_api_key,
                "endpoint": self.agent_endpoint,
                "project_id": self.agent_project_id,
                "buffer_size": self.agent_buffer_size,
                "flush_interval": self.agent_flush_interval,
                "dynamic_rule_interval": self.dynamic_rule_interval,
                "status_interval": self.agent_status_interval,
                "high_watermark_ratio": self.agent_high_watermark_ratio,
                "max_concurrent_flushes": self.agent_max_concurrent_flushes,
                "buffer_overflow_policy": self.agent_buffer_overflow_policy,
                "enable_events": self.agent_enable_events,
                "enable_metrics": self.agent_enable_metrics,
                "timeout": self.agent_timeout,
                "retry_attempts": self.agent_retry_attempts,
                "backoff_factor": self.agent_backoff_factor,
                "sensitive_headers": self.agent_sensitive_headers,
                "max_payload_size": self.agent_max_payload_size,
                "project_encryption_key": self.agent_project_encryption_key,
                "guard_version": self.agent_guard_version,
                "guard_core_version": __version__,
                "compression_enabled": self.agent_compression_enabled,
                "compression_threshold": self.agent_compression_threshold,
                "install_id": self.agent_install_id,
                "payload_signing_secret": self.agent_payload_signing_secret,
                "on_error": self.on_error,
            }

            return AgentConfig(
                **{key: value for key, value in kwargs.items() if value is not None}
            )
        except ImportError as e:
            raise AgentPackageNotInstalledError(
                "guard-agent is not installed but enable_agent=True. "
                "Install it with: pip install guard-agent"
            ) from e


# Parametrized here, at import time, so pydantic registers the class in this module:
# a pickled SecurityConfig[SyncGuardRequest] then loads in an interpreter that has only
# imported guard_core (a spawn-started process unpickles its arguments).
SyncSecurityConfig = SecurityConfig[SyncGuardRequest]
