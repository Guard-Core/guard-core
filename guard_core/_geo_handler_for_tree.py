import inspect
from collections.abc import Iterable
from typing import TYPE_CHECKING, Literal, Protocol, TypeAlias, TypeGuard, overload

from guard_core._config_capabilities import require_geo_extra

if TYPE_CHECKING:
    from guard_core._security_config_fields import RequestT
    from guard_core.models import SecurityConfig
    from guard_core.protocols.geo_ip_protocol import GeoIPHandler
    from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler

GeoIPHandlerOfEitherTree: TypeAlias = "GeoIPHandler | SyncGeoIPHandler"

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


def _lifecycle_members_of(handler: object) -> list[tuple[str, object]]:
    return [
        (name, member)
        for name in _LIFECYCLE_MEMBERS
        if (member := getattr(handler, name, None)) is not None
    ]


def _awaited_lifecycle_members(handler: object) -> list[str]:
    return [
        name
        for name, member in _lifecycle_members_of(handler)
        if inspect.iscoroutinefunction(member)
    ]


def _synchronous_lifecycle_members(handler: object) -> list[str]:
    return [
        name
        for name, member in _lifecycle_members_of(handler)
        if inspect.isroutine(member) and not inspect.iscoroutinefunction(member)
    ]


def _is_synchronous_handler(
    handler: "GeoIPHandler | SyncGeoIPHandler",
) -> TypeGuard["SyncGeoIPHandler"]:
    return not _awaited_lifecycle_members(handler)


def _is_awaited_handler(
    handler: "GeoIPHandler | SyncGeoIPHandler",
) -> TypeGuard["GeoIPHandler"]:
    return not _synchronous_lifecycle_members(handler)


@overload
def geo_ip_handler_for_tree(
    config: "SecurityConfig[RequestT]",
    handler: "GeoIPHandler | SyncGeoIPHandler | None",
    *,
    tree_awaits: Literal[True],
) -> "GeoIPHandler | None": ...


@overload
def geo_ip_handler_for_tree(
    config: "SecurityConfig[RequestT]",
    handler: "GeoIPHandler | SyncGeoIPHandler | None",
    *,
    tree_awaits: Literal[False],
) -> "SyncGeoIPHandler | None": ...


def geo_ip_handler_for_tree(
    config: "SecurityConfig[RequestT]",
    handler: "GeoIPHandler | SyncGeoIPHandler | None",
    *,
    tree_awaits: bool,
) -> "GeoIPHandler | SyncGeoIPHandler | None":
    if handler is None:
        return None
    if tree_awaits:
        if _is_awaited_handler(handler):
            return handler
        raise ValueError(
            f"geo_ip_handler {type(handler).__name__} is synchronous "
            f"({', '.join(_synchronous_lifecycle_members(handler))} "
            "are not coroutine functions) but this engine awaits them. "
            "Use the asynchronous handler: "
            "guard_core.handlers.ipinfo_handler.IPInfoManager, or set "
            "ipinfo_token and leave geo_ip_handler unset."
        )
    if _is_built_from_the_token(config, handler):
        return _sync_ipinfo_manager(config, config.ipinfo_token or "")
    if _is_synchronous_handler(handler):
        return handler
    raise ValueError(
        f"geo_ip_handler {type(handler).__name__} is async "
        f"({', '.join(_awaited_lifecycle_members(handler))} "
        "must be awaited) but this engine is synchronous and never awaits. "
        "Use the synchronous handler: "
        "guard_core.sync.handlers.ipinfo_handler.IPInfoManager, or set "
        "ipinfo_token and leave geo_ip_handler unset."
    )


def routes_need_geo_ip_handler(route_configs: Iterable[GeoRuleRoute]) -> bool:
    return any(
        rc.blocked_countries or rc.whitelist_countries or rc.geo_rate_limits
        for rc in route_configs
    )
