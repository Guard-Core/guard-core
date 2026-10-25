from collections.abc import Collection, Mapping
from copy import deepcopy
from typing import TYPE_CHECKING, Any

from guard_core._config_capabilities import (
    cloud_blocking_requested,
    require_cloud_extra,
)
from guard_core._security_config_validators import (
    _FIELD_REVALIDATORS,
    _resolve_geo_ip_handler,
    _revalidate_field_value,
    _warn_country_allowlist_shadows_blocklist,
)

if TYPE_CHECKING:
    from guard_core._security_config_fields import RequestT
    from guard_core.models import SecurityConfig


def _require_cloud_extra_for_batch(
    config: "SecurityConfig[RequestT]", prepared: Mapping[str, Any]
) -> None:
    if cloud_blocking_requested(
        prepared.get("block_cloud_providers", config.block_cloud_providers),
        prepared.get("enable_dynamic_rules", config.enable_dynamic_rules),
    ):
        require_cloud_extra()


def prepare_config_batch(
    config: "SecurityConfig[RequestT]",
    values: Mapping[str, Any],
    validated: Collection[str],
) -> dict[str, Any]:
    prepared = {name: deepcopy(value) for name, value in values.items()}
    for name in validated:
        if name in _FIELD_REVALIDATORS:
            prepared[name] = _revalidate_field_value(
                config, name, prepared[name], prepared
            )
    _require_cloud_extra_for_batch(config, prepared)
    blocked = prepared.get("blocked_countries", config.blocked_countries)
    allowed = prepared.get("whitelist_countries", config.whitelist_countries)
    resolved = _resolve_geo_ip_handler(
        blocked_countries=blocked,
        whitelist_countries=allowed,
        geo_ip_handler=config.geo_ip_handler,
        ipinfo_token=config.ipinfo_token,
        ipinfo_db_path=config.ipinfo_db_path,
        geo_ip_db_max_age=config.geo_ip_db_max_age,
    )
    if resolved is not config.geo_ip_handler:
        prepared["geo_ip_handler"] = resolved
    if (
        blocked
        and allowed
        and (
            blocked != config.blocked_countries or allowed != config.whitelist_countries
        )
    ):
        _warn_country_allowlist_shadows_blocklist(stacklevel=4)
    return prepared


def apply_config_batch(
    config: "SecurityConfig[RequestT]", prepared: Mapping[str, Any]
) -> None:
    config.__dict__.update(prepared)
    config.__pydantic_fields_set__.update(prepared)
    object.__setattr__(config, "_revision", config._current_revision() + 1)
