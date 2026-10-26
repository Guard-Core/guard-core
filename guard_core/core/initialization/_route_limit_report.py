import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.decorators.route_config import RouteConfig
    from guard_core.models import SecurityConfig


def _has_own_rate_limit(route_config: "RouteConfig") -> bool:
    return route_config.rate_limit is not None or bool(route_config.geo_rate_limits)


def _routes_with_own_rate_limits(guard_decorator: object) -> list[str]:
    route_configs = getattr(guard_decorator, "_route_configs", {})
    return sorted(
        route_id
        for route_id, route_config in route_configs.items()
        if _has_own_rate_limit(route_config)
    )


def report_route_limits_with_global_switch_off(
    config: "SecurityConfig", guard_decorator: object, logger: logging.Logger
) -> None:
    if config.enable_rate_limiting or guard_decorator is None:
        return
    limited = _routes_with_own_rate_limits(guard_decorator)
    if not limited:
        return
    logger.info(
        "enable_rate_limiting is False, so the global rate limit is off; the "
        "rate limits of these routes stay on: %s",
        ", ".join(limited),
    )
