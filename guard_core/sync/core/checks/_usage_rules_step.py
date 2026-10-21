from collections.abc import Callable, Sequence
from typing import Any

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.behavioral._throttle import (
    can_build_error_response,
    is_throttle_rule,
    warn_throttle_needs_middleware,
)
from guard_core.sync.core.behavioral.processor import BehavioralProcessor
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.handlers.behavior_handler import BehaviorRule, config_to_rule
from guard_core.sync.handlers.cors_handler import is_preflight
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

_ROUTE_NOT_RESOLVED = object()

CheckErrorHandler = Callable[
    [SecurityCheck, SyncGuardRequest, Exception], GuardResponse | None
]


class UsageRulesStepCheck(SecurityCheck):
    """Names the usage-rules step in the pipeline's error handling and logs."""

    @property
    def check_name(self) -> str:
        return "behavior_usage_rules"

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        return None


def enforce_usage_rules(
    checks: Sequence[Any],
    request: SyncGuardRequest,
    state: Any,
    handle_check_error: CheckErrorHandler,
) -> GuardResponse | None:
    # One function, and the request state is passed in rather than read again:
    # this runs on every request of a pipeline that resolved a route, and each
    # extra helper call or state access is cost on the hot path.
    route_config: Any = getattr(state, "route_config", _ROUTE_NOT_RESOLVED)
    if route_config is _ROUTE_NOT_RESOLVED or not checks:
        return None
    middleware = checks[0].middleware
    config = middleware.config
    if not (
        config.global_behavior_rules or getattr(route_config, "behavior_rules", None)
    ):
        return None
    processor = getattr(middleware, "behavioral_processor", None)
    client_ip = getattr(state, "client_ip", None)
    if not (isinstance(processor, BehavioralProcessor) and client_ip):
        return None
    if config.enable_cors and is_preflight(request.method, request.headers):
        return None
    try:
        refused: GuardResponse | None = processor.evaluate_usage_rules(
            request, state, client_ip, route_config, middleware
        )
    except Exception as error:
        return handle_check_error(UsageRulesStepCheck(middleware), request, error)
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
