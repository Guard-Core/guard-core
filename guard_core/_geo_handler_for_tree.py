import inspect
from collections.abc import Iterable
from typing import TYPE_CHECKING, Protocol

from guard_core._config_capabilities import require_geo_extra

if TYPE_CHECKING:
    from guard_core._security_config_fields import RequestT
    from guard_core.models import SecurityConfig
    from guard_core.protocols.geo_ip_protocol import GeoIPHandler
    from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler

_LIFECYCLE_MEMBERS = ("initialize", "initialize_redis", "initialize_agent", "refresh")


class GeoRuleRoute(Protocol):
    @property
    def blocked_countries(self) -> object: ...

    @property
    def whitelist_countries(self) -> object: ...

    @property
    def geo_rate_limits(self) -> object: ...


def _is_built_from_the_token(
    config: "SecurityConfig[RequestT]", handler: object
) -> bool:
    from guard_core.handlers.ipinfo_handler import IPInfoManager as AsyncIPInfoManager

    token = config.ipinfo_token
    return bool(token) and (
        isinstance(handler, AsyncIPInfoManager)
        and getattr(handler, "token", None) == token
    )


def _sync_ipinfo_manager(
    config: "SecurityConfig[RequestT]", token: str
) -> "GeoIPHandler | SyncGeoIPHandler":
    from guard_core.sync.handlers.ipinfo_handler import IPInfoManager

    return IPInfoManager(
        token=token,
        db_path=config.ipinfo_db_path,
        max_age=config.geo_ip_db_max_age,
        download_url=config.ipinfo_download_url,
    )


def build_geo_ip_handler_from_token(
    config: "SecurityConfig[RequestT]", *, tree_awaits: bool
) -> "GeoIPHandler | SyncGeoIPHandler":
    require_geo_extra()
    token = config.ipinfo_token or ""
    if not tree_awaits:
        return _sync_ipinfo_manager(config, token)
    from guard_core.handlers.ipinfo_handler import IPInfoManager

    return IPInfoManager(
        token=token,
        db_path=config.ipinfo_db_path,
        max_age=config.geo_ip_db_max_age,
        download_url=config.ipinfo_download_url,
    )


def geo_ip_handler_for_tree(
    config: "SecurityConfig[RequestT]",
    handler: "GeoIPHandler | SyncGeoIPHandler | None",
    *,
    tree_awaits: bool,
) -> "GeoIPHandler | SyncGeoIPHandler | None":
    if handler is None or tree_awaits:
        return handler
    if _is_built_from_the_token(config, handler):
        return _sync_ipinfo_manager(config, config.ipinfo_token or "")
    awaited = [
        name
        for name in _LIFECYCLE_MEMBERS
        if inspect.iscoroutinefunction(getattr(handler, name, None))
    ]
    if awaited:
        raise ValueError(
            f"geo_ip_handler {type(handler).__name__} is async ({', '.join(awaited)} "
            "must be awaited) but this engine is synchronous and never awaits. "
            "Use the synchronous handler: "
            "guard_core.sync.handlers.ipinfo_handler.IPInfoManager, or set "
            "ipinfo_token and leave geo_ip_handler unset."
        )
    return handler


def routes_need_geo_ip_handler(route_configs: Iterable[GeoRuleRoute]) -> bool:
    return any(
        rc.blocked_countries or rc.whitelist_countries or rc.geo_rate_limits
        for rc in route_configs
    )
