from collections.abc import Sequence
from typing import Any

from guard_core.core.behavioral._throttle import (
    can_build_error_response,
    is_throttle_rule,
    warn_throttle_needs_middleware,
)
from guard_core.core.behavioral.processor import BehavioralProcessor
from guard_core.core.checks.base import SecurityCheck
from guard_core.handlers.behavior_handler import BehaviorRule, config_to_rule
from guard_core.handlers.cors_handler import is_preflight
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

_ROUTE_NOT_RESOLVED = object()


def _shared_middleware(checks: Sequence[SecurityCheck]) -> Any:
    return checks[0].middleware


def _has_processor(middleware: Any) -> bool:
    return isinstance(
        getattr(middleware, "behavioral_processor", None), BehavioralProcessor
    )


def _rules_configured(config: Any, route_config: Any) -> bool:
    return bool(config.global_behavior_rules) or bool(
        route_config is not None and route_config.behavior_rules
    )


def _is_cors_preflight(config: Any, request: GuardRequest) -> bool:
    return bool(config.enable_cors and is_preflight(request.method, request.headers))


def _step_applies(middleware: Any, request: GuardRequest, route_config: Any) -> bool:
    config = middleware.config
    return (
        _has_processor(middleware)
        and _rules_configured(config, route_config)
        and not _is_cors_preflight(config, request)
        and bool(getattr(request.state, "client_ip", None))
    )


async def enforce_usage_rules(
    checks: Sequence[SecurityCheck], request: GuardRequest
) -> GuardResponse | None:
    route_config: Any = getattr(request.state, "route_config", _ROUTE_NOT_RESOLVED)
    if route_config is _ROUTE_NOT_RESOLVED or not checks:
        return None
    middleware = _shared_middleware(checks)
    if not _step_applies(middleware, request, route_config):
        return None
    refused: (
        GuardResponse | None
    ) = await middleware.behavioral_processor.process_usage_rules(
        request, request.state.client_ip, route_config, middleware
    )
    return refused


def _configured_throttle_rules(middleware: Any) -> list[BehaviorRule]:
    configured = getattr(
        getattr(middleware, "config", None), "global_behavior_rules", ()
    )
    if not isinstance(configured, tuple):
        return []
    return [rule for rule in map(config_to_rule, configured) if is_throttle_rule(rule)]


def _reachable_error_builder(middleware: Any) -> bool:
    processor = getattr(middleware, "behavioral_processor", None)
    context_middleware = getattr(
        getattr(processor, "context", None), "middleware", None
    )
    return can_build_error_response(middleware) or can_build_error_response(
        context_middleware
    )


def warn_at_startup_if_throttle_cannot_refuse(checks: Sequence[SecurityCheck]) -> None:
    if not checks:
        return
    middleware: Any = getattr(checks[0], "middleware", None)
    rules = _configured_throttle_rules(middleware)
    if rules and not _reachable_error_builder(middleware):
        warn_throttle_needs_middleware(rules)
