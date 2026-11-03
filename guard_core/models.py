import contextvars
import difflib
import logging
import threading as _threading
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

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
from guard_core._detection_constants import (
    ALL_DETECTION_CATEGORIES as ALL_DETECTION_CATEGORIES,
)
from guard_core._dynamic_rules import DynamicRules as DynamicRules
from guard_core._misconfiguration import (
    CHECKED_FIELDS_BESIDES_RATE_LIMIT as _CHECKED_FIELDS_BESIDES_RATE_LIMIT,
)
from guard_core._misconfiguration import (
    report_config_misconfigurations,
)
from guard_core._security_config_field_validators import (
    require_agent_config,
    warn_agent_endpoint_in_clear,
)
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
    _validate_cors_field_value,
    _validate_country_set_value,
    _validate_dynamic_rules_cache_path_value,
    _validate_emergency_whitelist_value,
    _validate_enabled_detection_categories_value,
    _validate_exclude_paths_value,
    _validate_global_behavior_rule_assignment,
    _validate_ip_or_cidr_list,
    _validate_muted_check_logs_value,
    _validate_muted_event_types_value,
    _validate_muted_metric_types_value,
    _validate_return_pattern_body_scan,
    _validate_security_headers_value,
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
    _ALWAYS_LISTED_FIELDS,
    signal_changed_defaults,
    warn_redis_prefix_left_default,
)
from guard_core._utils.pattern_source_redaction import _ConfigSensitiveNames
from guard_core.exceptions import AgentPackageNotInstalledError
from guard_core.protocols.cloud_ip_store_protocol import (
    CloudIpStoreFactory as CloudIpStoreFactory,
)
from guard_core.protocols.cloud_ip_store_protocol import (
    CloudIpStoreProtocol as CloudIpStoreProtocol,
)
from guard_core.protocols.geo_ip_protocol import GeoIPHandler as GeoIPHandler
from guard_core.protocols.request_protocol import GuardRequest as GuardRequest
from guard_core.protocols.response_protocol import GuardResponse as GuardResponse

if TYPE_CHECKING:
    from guard_agent import AgentConfig

    from guard_core._security_config_assignment_checks import (
        changed_copy_fields,
        misconfigurations_now,
        require_cross_field_rules,
        require_field_constraints,
    )
    from guard_core.handlers.suspatterns_handler import SusPatternsManager
    from guard_core.sync.protocols.request_protocol import SyncGuardRequest


VALID_BYPASS_CHECKS: frozenset[str] = frozenset(
    {"all", "ip_ban", "ip", "clouds", "rate_limit", "penetration"}
)

logger = logging.getLogger("guard_core.models")

_skip_revalidation: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "guard_core_security_config_skip_revalidation", default=False
)


def _pickled_mapping(value: object, what: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"the pickled state of a SecurityConfig lacks its {what}")
    return value


def _snapshot_field(
    config: "SecurityConfig[RequestT]", name: str
) -> tuple[object, set[str]]:
    return config.__dict__[name], set(config.__pydantic_fields_set__)


def _restore_field(
    config: "SecurityConfig[RequestT]", name: str, kept: tuple[object, set[str]]
) -> None:
    value, fields_set = kept
    config.__dict__[name] = value
    config.__pydantic_fields_set__.clear()
    config.__pydantic_fields_set__.update(fields_set)


class SecurityConfig(_SecurityConfigFields[RequestT]):
    model_config = ConfigDict(arbitrary_types_allowed=True, hide_input_in_errors=True)

    _revision: int = PrivateAttr(default=0)
    # The app's pattern manager, parked on the instance by sus_patterns_manager_for
    # so the request path reads it as an attribute, without a registry lookup.
    _guard_pattern_manager: ClassVar["SusPatternsManager | None"] = None

    def _current_revision(self) -> int:
        private = self.__pydantic_private__
        fallback = private.get("_revision", 0) if private is not None else 0
        stored = self.__dict__.get("_revision", fallback)
        return stored if isinstance(stored, int) else 0

    def __setattr__(self, name: str, value: object) -> None:
        if name in _GEO_STATE_FIELDS:
            value = _apply_geo_ip_handler_assignment(self, name, value)
        if name in _FIELD_REVALIDATORS and not _skip_revalidation.get():
            value = _revalidate_field_value(self, name, value)
        if name in _GLOBAL_BEHAVIOR_RULE_FIELDS:
            _validate_global_behavior_rule_assignment(self, name, value)

        should_warn = _country_shadow_should_warn(self, name, value)

        self._assign_held_to_construction_rules(name, value)
        if name != "_revision":
            object.__setattr__(self, "_revision", self._current_revision() + 1)
        if should_warn:
            _warn_country_allowlist_shadows_blocklist(stacklevel=3)

    def _assign_held_to_construction_rules(self, name: str, value: object) -> None:
        def assign(assigned: object) -> None:
            _assign_checking_optional_extras(
                self,
                name,
                lambda: super(SecurityConfig, self).__setattr__(name, assigned),
            )

        if name not in type(self).model_fields or _skip_revalidation.get():
            assign(value)
            return
        from guard_core._security_config_assignment_checks import (
            misconfigurations_now,
            require_cross_field_rules,
            require_field_constraints,
        )

        value = require_field_constraints(self, name, value)
        problems_before = misconfigurations_now(self)
        kept = _snapshot_field(self, name)
        assign(value)
        try:
            require_cross_field_rules(
                self, frozenset({name}), problems_before, stacklevel=4
            )
        except ValueError:
            _restore_field(self, name, kept)
            raise

    def _set_prevalidated(self, name: str, value: object) -> None:
        token = _skip_revalidation.set(True)
        try:
            setattr(self, name, value)
        finally:
            _skip_revalidation.reset(token)

    @property
    def revision(self) -> int:
        return self._current_revision()

    def __getstate__(self) -> dict[str, object]:
        # threat_ban_config is a read-only mappingproxy, which neither pickle nor
        # deepcopy can handle: it travels as a dict and is frozen again on load.
        state = super().__getstate__()
        state["__dict__"] = {
            **state["__dict__"],
            "threat_ban_config": dict(self.threat_ban_config),
        }
        return state

    def __setstate__(self, state: dict[str, object]) -> None:
        pickled_fields = _pickled_mapping(state["__dict__"], "fields")
        frozen = MappingProxyType(
            _pickled_mapping(pickled_fields["threat_ban_config"], "threat_ban_config")
        )
        state["__dict__"] = {**pickled_fields, "threat_ban_config": frozen}
        super().__setstate__(state)

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        clone = self.__class__.__new__(self.__class__)
        clone.__setstate__(deepcopy(self.__getstate__(), memo))
        return clone

    def model_copy(
        self, *, update: Mapping[str, object] | None = None, deep: bool = False
    ) -> Self:
        copied = super().model_copy(update=update, deep=deep)
        if update:
            from guard_core._security_config_assignment_checks import (
                changed_copy_fields,
                misconfigurations_now,
                require_cross_field_rules,
            )

            _revalidate_copied_config(copied, update)
            changed_copy_fields(copied, update)
            require_cross_field_rules(
                copied, frozenset(update), misconfigurations_now(self), stacklevel=3
            )
        return copied

    @model_validator(mode="before")
    @classmethod
    def warn_unknown_fields(cls, data: object) -> object:
        if not isinstance(data, dict) or not data:
            return data

        fields = cls.model_fields
        if data.keys() <= fields.keys():
            return data
        not_a_field_name = {key for key in data if key not in fields}
        known = set(fields)
        known.update(field.alias for field in fields.values() if field.alias)

        unknown = not_a_field_name - known
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
    def validate_ip_lists(cls, v: object) -> tuple[str, ...] | None:
        return _validate_ip_or_cidr_list(v, invalid_message="Invalid IP or CIDR range")

    @field_validator("emergency_whitelist", mode="before")
    def validate_emergency_whitelist(cls, v: object) -> list[str]:
        return _validate_emergency_whitelist_value(v)

    @field_validator("trusted_proxies", mode="before")
    def validate_trusted_proxies(cls, v: object) -> tuple[str, ...] | None:
        return _validate_ip_or_cidr_list(
            v, invalid_message="Invalid proxy IP or CIDR range", allow_unix=True
        )

    @field_validator("trusted_proxy_depth")
    def validate_proxy_depth(cls, v: int) -> int:
        if v < 1:
            raise ValueError("trusted_proxy_depth must be at least 1")
        return v

    @field_validator("whitelist_countries", "blocked_countries", mode="before")
    def coerce_country_set(cls, v: object) -> frozenset[str]:
        return _validate_country_set_value(v)

    @field_validator(
        "cors_allow_origins",
        "cors_allow_methods",
        "cors_allow_headers",
        "cors_expose_headers",
        mode="before",
    )
    def validate_cors_values(
        cls, v: object, info: "ValidationInfo[object]"
    ) -> list[str]:
        return _validate_cors_field_value(str(info.field_name), v)

    @field_validator("security_headers", mode="before")
    def validate_security_headers(cls, v: object) -> dict[str, object] | None:
        return _validate_security_headers_value(v)

    @field_validator("block_cloud_providers", mode="before")
    def validate_cloud_providers(cls, v: object) -> frozenset[str] | None:
        return _validate_block_cloud_providers_value(v)

    @field_validator("blocked_user_agents", mode="before")
    def validate_blocked_user_agents(cls, v: object) -> list[str]:
        return _validate_blocked_user_agents_structure(v)

    @model_validator(mode="before")
    @classmethod
    def redact_blocked_user_agents_in_input(cls, data: object) -> object:
        if type(data) is dict and "blocked_user_agents" not in data:
            return data
        return _redact_blocked_user_agents_in_input(
            data,
            lambda: {
                f: cls.model_fields[f].get_default(call_default_factory=True)
                for f in _SENSITIVE_NAME_FIELDS
            },
        )

    # The after validators below read fields from __dict__: the first read of a
    # name through the instance walks the class MRO, which costs more than the
    # check itself on the first construction of a process (LEDGER 6.494).
    @model_validator(mode="after")
    def reject_redos_unsafe_blocked_user_agents_after_validation(self) -> Self:
        if self.__dict__["blocked_user_agents"]:
            _reject_redos_unsafe_blocked_user_agents_at_field(
                type(self).__name__,
                self.blocked_user_agents,
                _ConfigSensitiveNames(self),
            )
        return self

    @classmethod
    def reject_redos_unsafe_blocked_user_agents(
        cls, data: object, handler: ModelWrapValidatorHandler[Self]
    ) -> Self:
        """The wrap validator of landing-6e-stack10, kept callable by name and
        signature (LEDGER 6.540): the registered validators are the before
        validator above and the after validator it pairs with, which give the
        same verdict on construction without a wrap frame."""
        config = handler(
            _redact_blocked_user_agents_in_input(
                data,
                lambda: {
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
        values = self.__dict__
        if values["geo_ip_handler"] is not None or not (
            values["blocked_countries"] or values["whitelist_countries"]
        ):
            return self
        self.geo_ip_handler = _resolve_geo_ip_handler(
            blocked_countries=self.blocked_countries,
            whitelist_countries=self.whitelist_countries,
            geo_ip_handler=self.geo_ip_handler,
            ipinfo_token=self.ipinfo_token,
            ipinfo_db_path=self.ipinfo_db_path,
            ipinfo_download_url=self.ipinfo_download_url,
            geo_ip_db_max_age=self.geo_ip_db_max_age,
        )
        return self

    @model_validator(mode="after")
    def warn_country_allowlist_shadows_blocklist(self) -> Self:
        values = self.__dict__
        if values["whitelist_countries"] and values["blocked_countries"]:
            _warn_country_allowlist_shadows_blocklist(stacklevel=4)
        return self

    @model_validator(mode="after")
    def validate_agent_config(self) -> Self:
        require_agent_config(self)
        return self

    @model_validator(mode="after")
    def warn_agent_endpoint_in_clear_text(self) -> Self:
        warn_agent_endpoint_in_clear(self)
        return self

    @model_validator(mode="after")
    def validate_recidive_cap(self) -> Self:
        if self.__dict__["enable_recidive"]:
            _require_recidive_cap_covers_auto_ban(self)
        return self

    @model_validator(mode="after")
    def validate_global_return_pattern_body_scan(self) -> Self:
        for rule in self.__dict__["global_behavior_rules"]:
            if rule.rule_type != "return_pattern" or not rule.pattern:
                continue
            _validate_return_pattern_body_scan(rule.pattern, self)
        return self

    @model_validator(mode="after")
    def warn_trusted_proxies_prefix_zero(self) -> Self:
        trusted_proxies = self.__dict__["trusted_proxies"]
        if trusted_proxies and any(
            _is_prefix_zero_network_entry(entry) for entry in trusted_proxies
        ):
            _warn_trusted_proxies_prefix_zero()
        return self

    @model_validator(mode="after")
    def warn_whitelist_prefix_zero(self) -> Self:
        whitelist = self.__dict__["whitelist"]
        if whitelist and any(
            _is_prefix_zero_network_entry(entry) for entry in whitelist
        ):
            _warn_whitelist_prefix_zero()
        return self

    @model_validator(mode="after")
    def warn_exempt_ips_prefix_zero(self) -> Self:
        exempt_ips = self.__dict__["exempt_ips"]
        if exempt_ips:
            _warn_exempt_ips_prefix_zero(exempt_ips)
        return self

    @model_validator(mode="after")
    def warn_exclude_all_paths(self) -> Self:
        if self.__dict__["exclude_all_paths"]:
            _warn_exclude_all_paths(stacklevel=4)
        return self

    @model_validator(mode="after")
    def report_misconfigurations(self) -> Self:
        stated = self.__pydantic_fields_set__
        values = self.__dict__
        if (
            values["emergency_mode"]
            or not stated.isdisjoint(_CHECKED_FIELDS_BESIDES_RATE_LIMIT)
            or ("rate_limit" in stated and values["rate_limit"] < 1)
        ):
            report_config_misconfigurations(self, stacklevel=4)
        return self

    @model_validator(mode="after")
    def warn_changed_defaults(self) -> Self:
        values = self.__dict__
        if not (
            self.__pydantic_fields_set__ >= _ALWAYS_LISTED_FIELDS
            and not values["whitelist"]
            and "/" not in values["exclude_paths"]
        ):
            signal_changed_defaults(self)
        if values["enable_redis"] and values["redis_url"]:
            warn_redis_prefix_left_default(self)
        return self

    @model_validator(mode="after")
    def warn_empty_enabled_detection_categories(self) -> Self:
        values = self.__dict__
        if (
            values["enable_penetration_detection"]
            and not values["enabled_detection_categories"]
        ):
            _warn_empty_enabled_detection_categories()
        return self

    @field_validator("muted_event_types", mode="before")
    def validate_muted_event_types(cls, v: object) -> frozenset[str]:
        return _validate_muted_event_types_value(v)

    @field_validator("muted_metric_types", mode="before")
    def validate_muted_metric_types(cls, v: object) -> frozenset[str]:
        return _validate_muted_metric_types_value(v)

    @field_validator("enabled_detection_categories", mode="before")
    def validate_enabled_detection_categories(cls, v: object) -> frozenset[str]:
        return _validate_enabled_detection_categories_value(v)

    @field_validator("threat_ban_config", mode="before")
    def validate_threat_ban_config(
        cls, v: object
    ) -> MappingProxyType[str, ThreatBanConfig]:
        return _validate_threat_ban_config_value(v)

    @field_validator("muted_check_logs", mode="before")
    def validate_muted_check_logs(cls, v: object) -> frozenset[str]:
        return _validate_muted_check_logs_value(v)

    @field_validator("log_sensitive_headers", mode="before")
    def validate_log_sensitive_headers(cls, v: object) -> frozenset[str]:
        return _validate_sensitive_name_set_value(v, "log_sensitive_headers")

    @field_validator("log_sensitive_params", mode="before")
    def validate_log_sensitive_params(cls, v: object) -> frozenset[str]:
        return _validate_sensitive_name_set_value(v, "log_sensitive_params")

    @field_validator("log_sensitive_body_fields", mode="before")
    def validate_log_sensitive_body_fields(cls, v: object) -> frozenset[str]:
        return _validate_sensitive_name_set_value(v, "log_sensitive_body_fields")

    @field_validator("exclude_paths")
    def validate_exclude_paths(cls, v: list[str]) -> list[str]:
        return _validate_exclude_paths_value(v)

    @field_validator("dynamic_rules_cache_path", mode="before")
    def validate_dynamic_rules_cache_path(cls, v: object) -> Path | None:
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

            kwargs: dict[str, object] = {
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


def _start_private_state(self: SecurityConfig[RequestT], context: object, /) -> None:
    """pydantic's initializer of the private attributes, for the one this class
    declares: it reads the attribute's default through five Python calls, which
    cost more on the first construction of a process than the validators do. A
    subclass with private attributes of its own gets pydantic's initializer first
    (its metaclass wraps this one), so the state is already there and is kept."""
    # pydantic 2.12.0 calls this from model_construct before it sets the slot at all
    if getattr(self, "__pydantic_private__", None) is None:
        object.__setattr__(self, "__pydantic_private__", {"_revision": 0})


type.__setattr__(SecurityConfig, "model_post_init", _start_private_state)

if TYPE_CHECKING:
    SyncSecurityConfig = SecurityConfig[SyncGuardRequest]

_LAZY_NAMES = (
    "SyncSecurityConfig",
    "SecurityConfig[SyncGuardRequest]",
    "SyncGuardRequest",
)
_ASSIGNMENT_CHECK_NAMES = (
    "changed_copy_fields",
    "misconfigurations_now",
    "require_cross_field_rules",
    "require_field_constraints",
)
_build_lock = _threading.Lock()


def __getattr__(name: str) -> object:
    # Resolved on first use and registered in this module, as pydantic does for a
    # module-level parametrization: a pickled SecurityConfig[SyncGuardRequest] still
    # loads in an interpreter that has only imported guard_core (a spawn-started
    # process unpickles its arguments). The import runs outside the lock and the
    # build inside it, only while the name is still missing: pydantic's generic
    # cache is not thread-safe, so two threads would build two classes.
    if name in _ASSIGNMENT_CHECK_NAMES:
        from guard_core import _security_config_assignment_checks

        value = getattr(_security_config_assignment_checks, name)
        globals()[name] = value
        return value
    if name not in _LAZY_NAMES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from guard_core.sync.protocols.request_protocol import SyncGuardRequest

    with _build_lock:
        if name not in globals():
            # defer_build: pydantic builds the parametrized class's validator on its
            # first instance, not here (about 5 ms of an import of the sync tree,
            # LEDGER 6.333); the key is taken off again so the class reports the
            # configuration of SecurityConfig.
            SecurityConfig.model_config["defer_build"] = True
            try:
                parametrized = SecurityConfig[SyncGuardRequest]
            finally:
                del SecurityConfig.model_config["defer_build"]
            parametrized.model_config.pop("defer_build", None)
            globals().update(
                {
                    "SyncSecurityConfig": parametrized,
                    "SecurityConfig[SyncGuardRequest]": parametrized,
                    "SyncGuardRequest": SyncGuardRequest,
                }
            )
    return globals()[name]


def __dir__() -> list[str]:
    return sorted({*globals(), *_LAZY_NAMES, *_ASSIGNMENT_CHECK_NAMES})


# What a star import exported at 7025a112 (every public global, imported ones
# included) except the unusable name 'SecurityConfig[SyncGuardRequest]', which ruff
# F822 refuses in __all__; getattr still resolves it.
__all__ = [
    "ALL_DETECTION_CATEGORIES",
    "AgentPackageNotInstalledError",
    "BehaviorRuleConfig",
    "ClassVar",
    "CloudIpStoreFactory",
    "CloudIpStoreProtocol",
    "CloudProvider",
    "ConfigDict",
    "DynamicRules",
    "GeoIPHandler",
    "GuardRequest",
    "GuardResponse",
    "Mapping",
    "MappingProxyType",
    "ModelWrapValidatorHandler",
    "Path",
    "PrivateAttr",
    "RequestT",
    "SecurityConfig",
    "Self",
    "SyncGuardRequest",
    "SyncSecurityConfig",
    "TYPE_CHECKING",
    "ThreatBanConfig",
    "VALID_BYPASS_CHECKS",
    "VALID_CLOUD_PROVIDERS",
    "ValidationInfo",
    "changed_copy_fields",
    "cloud_blocking_enabled",
    "contextvars",
    "deepcopy",
    "difflib",
    "field_validator",
    "logger",
    "logging",
    "misconfigurations_now",
    "model_validator",
    "report_config_misconfigurations",
    "require_agent_config",
    "require_cross_field_rules",
    "require_field_constraints",
    "return_pattern_requires_response_body",
    "signal_changed_defaults",
    "warn_agent_endpoint_in_clear",
    "warn_redis_prefix_left_default",
]
