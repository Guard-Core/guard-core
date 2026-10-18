import logging
from typing import Any


def report_route_limits_with_global_switch_off(
    config: Any, guard_decorator: Any, logger: logging.Logger
) -> None:
    if config.enable_rate_limiting or guard_decorator is None:
        return
    route_configs = getattr(guard_decorator, "_route_configs", {})
    limited = sorted(
        route_id
        for route_id, route_config in route_configs.items()
        if route_config.rate_limit is not None or route_config.geo_rate_limits
    )
    if not limited:
        return
    logger.info(
        "enable_rate_limiting is False, so the global rate limit is off; the "
        "rate limits of these routes stay on: %s",
        ", ".join(limited),
    )
