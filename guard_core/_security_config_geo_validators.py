import warnings
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from guard_core._config_capabilities import require_geo_extra

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig

_COUNTRY_RULE_FIELDS = frozenset({"blocked_countries", "whitelist_countries"})


def _warn_country_allowlist_shadows_blocklist(*, stacklevel: int) -> None:
    warnings.warn(
        "blocked_countries is ignored when whitelist_countries is "
        "non-empty: a non-empty whitelist_countries is restrictive "
        "(only listed countries pass), so blocked_countries has no "
        "effect. Use one or the other.",
        UserWarning,
        stacklevel=stacklevel,
    )


def _normalized_country_value(value: Any) -> frozenset[str]:
    return frozenset(str(item).upper() for item in value)


def _validate_country_set_value(v: Any) -> frozenset[str]:
    if v is None:
        return frozenset()
    if isinstance(v, list | tuple | set | frozenset):
        return frozenset(str(item).upper() for item in v)
    raise ValueError("Country list must be list/tuple/set/frozenset of country codes")


def _country_shadow_should_warn(
    config: "SecurityConfig", name: str, value: Any
) -> bool:
    if name not in _COUNTRY_RULE_FIELDS:
        return False
    new_whitelist = (
        value if name == "whitelist_countries" else config.whitelist_countries
    )
    new_blocked = value if name == "blocked_countries" else config.blocked_countries
    if not (new_whitelist and new_blocked):
        return False
    return bool(
        _normalized_country_value(value)
        != _normalized_country_value(getattr(config, name, None))
    )


_GEO_STATE_FIELDS = frozenset(
    {"blocked_countries", "whitelist_countries", "geo_ip_handler", "ipinfo_token"}
)


def _geo_state_candidates(
    config: "SecurityConfig", name: str, value: Any
) -> tuple[Any, Any, Any, Any]:
    return (
        value if name == "blocked_countries" else config.blocked_countries,
        value if name == "whitelist_countries" else config.whitelist_countries,
        value if name == "geo_ip_handler" else config.geo_ip_handler,
        value if name == "ipinfo_token" else config.ipinfo_token,
    )


def _resolve_geo_ip_handler(
    *,
    blocked_countries: Any,
    whitelist_countries: Any,
    geo_ip_handler: Any,
    ipinfo_token: str | None,
    ipinfo_db_path: Path | None,
    geo_ip_db_max_age: int,
) -> Any:
    has_country_rules = bool(blocked_countries or whitelist_countries)

    if geo_ip_handler is None and has_country_rules:
        if not ipinfo_token:
            raise ValueError(
                "geo_ip_handler is required "
                "if blocked_countries or whitelist_countries is set"
            )
        require_geo_extra()
        from guard_core.handlers.ipinfo_handler import IPInfoManager

        return IPInfoManager(
            token=ipinfo_token,
            db_path=ipinfo_db_path,
            max_age=geo_ip_db_max_age,
        )

    return geo_ip_handler


def _apply_geo_ip_handler_assignment(
    config: "SecurityConfig", name: str, value: Any
) -> Any:
    blocked, whitelist, handler, token = _geo_state_candidates(config, name, value)
    resolved = _resolve_geo_ip_handler(
        blocked_countries=blocked,
        whitelist_countries=whitelist,
        geo_ip_handler=handler,
        ipinfo_token=token,
        ipinfo_db_path=config.ipinfo_db_path,
        geo_ip_db_max_age=config.geo_ip_db_max_age,
    )
    if name == "geo_ip_handler":
        return resolved
    if resolved is not handler:
        BaseModel.__setattr__(config, "geo_ip_handler", resolved)
    return value


def _apply_geo_ip_handler_copy(config: "SecurityConfig") -> None:
    resolved = _resolve_geo_ip_handler(
        blocked_countries=config.blocked_countries,
        whitelist_countries=config.whitelist_countries,
        geo_ip_handler=config.geo_ip_handler,
        ipinfo_token=config.ipinfo_token,
        ipinfo_db_path=config.ipinfo_db_path,
        geo_ip_db_max_age=config.geo_ip_db_max_age,
    )
    if resolved is not config.geo_ip_handler:
        BaseModel.__setattr__(config, "geo_ip_handler", resolved)
