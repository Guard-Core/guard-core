import re
import warnings
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, TypeGuard, TypeVar

from pydantic import BaseModel
from pydantic_core import PydanticCustomError

from guard_core._config_capabilities import require_geo_extra
from guard_core.protocols.geo_ip_protocol import GeoIPHandler
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler

if TYPE_CHECKING:
    from guard_core._security_config_fields import RequestT
    from guard_core.models import SecurityConfig

_HandlerT = TypeVar("_HandlerT")

_COUNTRY_RULE_FIELDS = frozenset({"blocked_countries", "whitelist_countries"})
_GEO_IP_HANDLER_MEMBERS = tuple(
    name for name in vars(GeoIPHandler) if not name.startswith("_")
)


def _geo_ip_handler_has_member(value: object, name: str) -> bool:
    if not hasattr(value, name):
        return False
    return not callable(getattr(GeoIPHandler, name)) or getattr(value, name) is not None


def _has_every_geo_ip_handler_member(
    value: object,
) -> TypeGuard[GeoIPHandler | SyncGeoIPHandler]:
    # The isinstance check of a runtime_checkable Protocol looks members up with
    # hasattr on 3.10 and 3.11 and with getattr_static from 3.12, which rejects a
    # Mock. One hasattr check keeps every interpreter on the 3.10 verdict.
    return all(_geo_ip_handler_has_member(value, n) for n in _GEO_IP_HANDLER_MEMBERS)


def _validate_geo_ip_handler_value(value: object) -> GeoIPHandler | SyncGeoIPHandler:
    if not _has_every_geo_ip_handler_member(value):
        raise PydanticCustomError(
            "is_instance_of", "Input should be an instance of GeoIPHandler"
        )
    return value


def _warn_country_allowlist_shadows_blocklist(*, stacklevel: int) -> None:
    warnings.warn(
        "blocked_countries is ignored when whitelist_countries is "
        "non-empty: a non-empty whitelist_countries is restrictive "
        "(only listed countries pass), so blocked_countries has no "
        "effect. Use one or the other.",
        UserWarning,
        stacklevel=stacklevel,
    )


_COUNTRY_CODE = re.compile(r"[A-Za-z]{2}")


def _two_letter_country_codes(items: Iterable[object]) -> frozenset[str]:
    codes = []
    for item in items:
        if not isinstance(item, str) or not _COUNTRY_CODE.fullmatch(item):
            raise ValueError(f"{item!r} is not a two-letter country code")
        codes.append(item.upper())
    return frozenset(codes)


def _normalized_country_value(value: object) -> frozenset[str]:
    if not isinstance(value, Iterable):
        raise TypeError("a country value must be an iterable of country codes")
    return _two_letter_country_codes(value)


def _validate_country_set_value(v: object) -> frozenset[str]:
    if v is None:
        return frozenset()
    if isinstance(v, list | tuple | set | frozenset):
        return _two_letter_country_codes(v)
    raise ValueError("Country list must be list/tuple/set/frozenset of country codes")


def _country_shadow_should_warn(
    config: "SecurityConfig[RequestT]", name: str, value: object
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
    config: "SecurityConfig[RequestT]", name: str, value: object
) -> tuple[object, object, object, object]:
    return (
        value if name == "blocked_countries" else config.blocked_countries,
        value if name == "whitelist_countries" else config.whitelist_countries,
        value if name == "geo_ip_handler" else config.geo_ip_handler,
        value if name == "ipinfo_token" else config.ipinfo_token,
    )


def _resolve_geo_ip_handler(
    *,
    blocked_countries: object,
    whitelist_countries: object,
    geo_ip_handler: _HandlerT,
    ipinfo_token: object,
    ipinfo_db_path: Path | None,
    ipinfo_download_url: str,
    geo_ip_db_max_age: int,
) -> _HandlerT | GeoIPHandler:
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
            token=str(ipinfo_token),
            db_path=ipinfo_db_path,
            max_age=geo_ip_db_max_age,
            download_url=ipinfo_download_url,
        )

    return geo_ip_handler


def _apply_geo_ip_handler_assignment(
    config: "SecurityConfig[RequestT]", name: str, value: object
) -> object:
    blocked, whitelist, handler, token = _geo_state_candidates(config, name, value)
    resolved = _resolve_geo_ip_handler(
        blocked_countries=blocked,
        whitelist_countries=whitelist,
        geo_ip_handler=handler,
        ipinfo_token=token,
        ipinfo_db_path=config.ipinfo_db_path,
        ipinfo_download_url=config.ipinfo_download_url,
        geo_ip_db_max_age=config.geo_ip_db_max_age,
    )
    if name == "geo_ip_handler":
        return resolved
    if resolved is not handler:
        BaseModel.__setattr__(config, "geo_ip_handler", resolved)
    return value


def _apply_geo_ip_handler_copy(config: "SecurityConfig[RequestT]") -> None:
    resolved = _resolve_geo_ip_handler(
        blocked_countries=config.blocked_countries,
        whitelist_countries=config.whitelist_countries,
        geo_ip_handler=config.geo_ip_handler,
        ipinfo_token=config.ipinfo_token,
        ipinfo_db_path=config.ipinfo_db_path,
        ipinfo_download_url=config.ipinfo_download_url,
        geo_ip_db_max_age=config.geo_ip_db_max_age,
    )
    if resolved is not config.geo_ip_handler:
        BaseModel.__setattr__(config, "geo_ip_handler", resolved)
