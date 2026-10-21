from collections.abc import Sequence
from typing import Any

from guard_core.core.behavioral._throttle import (
    can_build_error_response,
    is_throttle_rule,
    warn_throttle_needs_middleware,
)
from guard_core.core.behavioral.processor import BehavioralProcessor
from guard_core.core.checks.base import SecurityCheck
from guard_core.handlers.behavior_handler import config_to_rule
from guard_core.handlers.cors_handler import is_preflight
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

_ROUTE_NOT_RESOLVED = object()


async def enforce_usage_rules(
    checks: Sequence[SecurityCheck], request: GuardRequest
) -> GuardResponse | None:
    route_config: Any = getattr(request.state, "route_config", _ROUTE_NOT_RESOLVED)
    if route_config is _ROUTE_NOT_RESOLVED or not checks:
        return None
    middleware = checks[0].middleware
    processor = getattr(middleware, "behavioral_processor", None)
    if not isinstance(processor, BehavioralProcessor):
        return None
    config = middleware.config
    if not config.global_behavior_rules and not (
        route_config is not None and route_config.behavior_rules
    ):
        return None
    if config.enable_cors and is_preflight(request.method, request.headers):
        return None
    client_ip = getattr(request.state, "client_ip", None)
    if not client_ip:
        return None
    refused: GuardResponse | None = await processor.process_usage_rules(
        request, client_ip, route_config, middleware
    )
    return refused


def warn_at_startup_if_throttle_cannot_refuse(checks: Sequence[SecurityCheck]) -> None:
    if not checks:
        return
    middleware: Any = getattr(checks[0], "middleware", None)
    configured = getattr(
        getattr(middleware, "config", None), "global_behavior_rules", ()
    )
    rules = [
        rule
        for rule in map(
            config_to_rule, configured if isinstance(configured, tuple) else ()
        )
        if is_throttle_rule(rule)
    ]
    if not rules:
        return
    processor = getattr(middleware, "behavioral_processor", None)
    reachable = getattr(getattr(processor, "context", None), "middleware", None)
    if can_build_error_response(middleware) or can_build_error_response(reachable):
        return
    warn_throttle_needs_middleware(rules)
