import logging
from typing import TYPE_CHECKING

from guard_core._geo_source import lacks_geo_source
from guard_core._misconfiguration import report_misconfigurations
from guard_core._misconfiguration_kinds import (
    K_ROUTE_COUNTRY_RULE_WITHOUT_GEOIP,
    Problem,
)

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.decorators.base import BaseSecurityDecorator
    from guard_core.sync.decorators.route_config import RouteConfig
    from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler


def _country_decorators_without_geoip(route_config: "RouteConfig") -> list[str]:
    decorators = []
    if route_config.blocked_countries or route_config.whitelist_countries:
        decorators.append("block_countries or allow_countries")
    if route_config.geo_rate_limits:
        decorators.append("geo_rate_limit")
    return decorators


def report_country_decorators_without_geoip(
    config: "SyncSecurityConfig",
    guard_decorator: "BaseSecurityDecorator | None",
    geo_ip_handler: "SyncGeoIPHandler | SyncGeoIPHandler | None",
    logger: logging.Logger,
) -> None:
    if guard_decorator is None or not lacks_geo_source(
        geo_ip_handler, config.ipinfo_token
    ):
        return
    route_configs = getattr(guard_decorator, "_route_configs", {})
    rule_owner = guard_decorator.config
    problems = [
        Problem(
            f"Route {route_id!r} uses {decorator} but no GeoIP database "
            "is configured (geo_ip_handler is None; set ipinfo_token or "
            "geo_ip_handler), so the country rule is ignored.",
            kind=K_ROUTE_COUNTRY_RULE_WITHOUT_GEOIP,
            subject=route_id,
        )
        for route_id, route_config in route_configs.items()
        for decorator in _country_decorators_without_geoip(route_config)
    ]
    report_misconfigurations(rule_owner, problems, logger=logger, stacklevel=4)
