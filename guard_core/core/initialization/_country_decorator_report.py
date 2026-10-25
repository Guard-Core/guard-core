import logging
from typing import Any

from guard_core._geo_source import lacks_geo_source
from guard_core._misconfiguration import report_misconfiguration


def _country_decorators_without_geoip(route_config: Any) -> list[str]:
    decorators = []
    if route_config.blocked_countries or route_config.whitelist_countries:
        decorators.append("block_countries or allow_countries")
    if route_config.geo_rate_limits:
        decorators.append("geo_rate_limit")
    return decorators


def report_country_decorators_without_geoip(
    config: Any,
    guard_decorator: Any,
    geo_ip_handler: Any,
    logger: logging.Logger,
) -> None:
    if guard_decorator is None or not lacks_geo_source(
        geo_ip_handler, config.ipinfo_token
    ):
        return
    route_configs = getattr(guard_decorator, "_route_configs", {})
    for route_id, route_config in route_configs.items():
        for decorator in _country_decorators_without_geoip(route_config):
            report_misconfiguration(
                config,
                f"Route {route_id!r} uses {decorator} but no GeoIP database "
                "is configured (geo_ip_handler is None; set ipinfo_token or "
                "geo_ip_handler), so the country rule is ignored.",
                logger=logger,
                stacklevel=4,
            )
