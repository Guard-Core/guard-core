from collections.abc import Awaitable, Callable, Sequence
from enum import Enum
from functools import partial
from typing import TYPE_CHECKING, Final

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

if TYPE_CHECKING:
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol


class _Unresolved(Enum):
    ROUTE_NOT_RESOLVED = object()


_ROUTE_NOT_RESOLVED: Final = _Unresolved.ROUTE_NOT_RESOLVED

CheckErrorHandler = Callable[
    [SecurityCheck, GuardRequest, Exception], Awaitable[GuardResponse | None]
]


class UsageRulesStepCheck(SecurityCheck):
    """Names the usage-rules step in the pipeline's error handling and logs."""

    @property
    def check_name(self) -> str:
        return "behavior_usage_rules"

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        return None


async def _no_usage_step() -> GuardResponse | None:
    return None


async def _handle_usage_step_error(
    handle_check_error: CheckErrorHandler,
    middleware: "GuardMiddlewareProtocol",
    request: GuardRequest,
    error: Exception,
) -> GuardResponse | None:
    return await handle_check_error(UsageRulesStepCheck(middleware), request, error)


def enforce_usage_rules(
    checks: Sequence[SecurityCheck],
    request: GuardRequest,
    state: object,
    handle_check_error: CheckErrorHandler,
) -> Awaitable[GuardResponse | None]:
    # Plain function returning the processor's coroutine: the pipeline awaits it
    # directly, so the step adds no coroutine layer of its own. The request state
    # is passed in, not read again. Both matter because this runs on every
    # request of a pipeline that resolved a route.
    route_config = getattr(state, "route_config", _ROUTE_NOT_RESOLVED)
    if route_config is _ROUTE_NOT_RESOLVED or not checks:
        return _no_usage_step()
    middleware = checks[0].middleware
    config = middleware.config
    if not (
        config.global_behavior_rules
        or (route_config is not None and route_config.behavior_rules)
    ):
        return _no_usage_step()
    processor = getattr(middleware, "behavioral_processor", None)
    client_ip = getattr(state, "client_ip", None)
    if not (isinstance(processor, BehavioralProcessor) and client_ip):
        return _no_usage_step()
    if config.enable_cors and is_preflight(request.method, request.headers):
        return _no_usage_step()
    return processor.evaluate_usage_rules(
        request,
        state,
        client_ip,
        route_config,
        middleware,
        partial(_handle_usage_step_error, handle_check_error, middleware, request),
    )


def _configured_throttle_rules(middleware: object) -> list[BehaviorRule]:
    configured = getattr(
        getattr(middleware, "config", None), "global_behavior_rules", ()
    )
    if not isinstance(configured, tuple):
        return []
    return [rule for rule in map(config_to_rule, configured) if is_throttle_rule(rule)]


def _reachable_error_builder(middleware: object) -> bool:
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
    middleware = getattr(checks[0], "middleware", None)
    rules = _configured_throttle_rules(middleware)
    if rules and not _reachable_error_builder(middleware):
        warn_throttle_needs_middleware(rules)
