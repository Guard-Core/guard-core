from typing import Any, NamedTuple

from guard_core._utils.request_logging import redact_endpoint_for_display
from guard_core.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_DYNAMIC_RULE_VIOLATION,
)
from guard_core.handlers.ratelimit_handler import RateLimitTier
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest


class TierPlan(NamedTuple):
    tier: RateLimitTier
    event_type: str | None
    event_kwargs: dict[str, Any]
    trigger_info: str


def route_bucket_key(request: GuardRequest) -> str:
    # A pluggable route resolver can return a route config without a route id.
    route_id = getattr(request.state, "guard_route_id", None)
    return route_id if isinstance(route_id, str) and route_id else request.url_path


def endpoint_plan(
    config: SecurityConfig, endpoint_key: str, limit: tuple[int, int]
) -> TierPlan:
    rate_limit, window = limit
    safe_endpoint = redact_endpoint_for_display(
        endpoint_key,
        config.log_sensitive_params,
        config.log_sensitive_body_fields,
        config.log_sensitive_headers,
    )
    reason = (
        f"Endpoint-specific rate limit exceeded: {rate_limit} "
        f"requests per {window}s for {safe_endpoint}"
    )
    return TierPlan(
        RateLimitTier("endpoint", rate_limit, window, endpoint_key),
        EVENT_DYNAMIC_RULE_VIOLATION,
        {
            "reason": reason,
            "rule_type": "endpoint_rate_limit",
            "endpoint": safe_endpoint,
            "rate_limit": rate_limit,
            "window": window,
        },
        reason,
    )


def route_plan(request: GuardRequest, route_config: Any) -> TierPlan | None:
    if not route_config or route_config.rate_limit is None:
        return None

    window = route_config.rate_limit_window or 60
    reason = (
        f"Route-specific rate limit exceeded: "
        f"{route_config.rate_limit} requests per {window}s"
    )
    return TierPlan(
        RateLimitTier(
            "route", route_config.rate_limit, window, route_bucket_key(request)
        ),
        EVENT_DECORATOR_VIOLATION,
        {
            "reason": reason,
            "decorator_type": "rate_limiting",
            "violation_type": "rate_limit",
            "rate_limit": route_config.rate_limit,
            "window": window,
        },
        reason,
    )


def geo_plan(
    middleware: Any, request: GuardRequest, client_ip: str, route_config: Any
) -> TierPlan | None:
    if not route_config or not route_config.geo_rate_limits:
        return None

    geo_handler = middleware.geo_ip_handler
    if not geo_handler:
        return None

    country = geo_handler.get_country(client_ip)
    limits = route_config.geo_rate_limits

    if country and country in limits:
        rate_limit, window = limits[country]
    elif "*" in limits:
        rate_limit, window = limits["*"]
    else:
        return None

    reason = (
        f"Geo rate limit exceeded for {country or 'unknown'}: "
        f"{rate_limit} requests per {window}s"
    )
    return TierPlan(
        RateLimitTier("geo", rate_limit, window, route_bucket_key(request)),
        EVENT_DECORATOR_VIOLATION,
        {
            "reason": reason,
            "decorator_type": "geo_rate_limiting",
            "violation_type": "geo_rate_limit",
            "rate_limit": rate_limit,
            "window": window,
        },
        reason,
    )


def global_plan(config: SecurityConfig) -> TierPlan | None:
    if not config.enable_rate_limiting:
        return None
    return TierPlan(
        RateLimitTier("global", config.rate_limit, config.rate_limit_window),
        None,
        {},
        "Global rate limit exceeded",
    )
