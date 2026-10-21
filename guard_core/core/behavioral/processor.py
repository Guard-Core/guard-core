from collections.abc import Awaitable, Callable, Sequence
from functools import partial
from typing import Any

from guard_core._utils.request_logging import redact_endpoint_for_display
from guard_core.core.behavioral._throttle import (
    BehavioralThrottleMixin,
    correlated_return_threshold,
    first_of_rule_id,
    global_scope_id,
    is_throttle_rule,
)
from guard_core.core.behavioral._usage_marks import (
    USAGE_MARKS_ATTR,
    UsageMarks,
    usage_marks_of,
)
from guard_core.core.behavioral.context import BehavioralContext
from guard_core.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.decorators.base import RouteConfig
from guard_core.handlers._behavior_throttle import ReturnCorrelation
from guard_core.handlers.behavior_handler import BehaviorRule
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


def _counts_in_response_phase(
    rule: BehaviorRule, recorded_before_handler: frozenset[str] = frozenset()
) -> bool:
    if rule.rule_type == "return_pattern":
        return True
    return not is_throttle_rule(rule) and (
        not recorded_before_handler
        or rule.discriminator() not in recorded_before_handler
    )


class BehavioralProcessor(BehavioralThrottleMixin):
    def __init__(self, context: BehavioralContext) -> None:
        self.context = context
        self._init_throttle_state()

    def _behavior_tracker(self, request: GuardRequest, state: Any = None) -> Any | None:
        state = request.state if state is None else state
        if getattr(state, "guard_exclusion_scoped", False) is True:
            return None
        if self.context.behavior_tracker is not None:
            return self.context.behavior_tracker
        guard_decorator = self.context.guard_decorator
        if guard_decorator is None:
            guard_decorator = getattr(state, "guard_decorator", None)
        if guard_decorator is not None:
            return getattr(guard_decorator, "behavior_tracker", None)
        return None

    async def process_usage_rules(
        self,
        request: GuardRequest,
        client_ip: str,
        route_config: RouteConfig | None = None,
        middleware: Any = None,
    ) -> GuardResponse | None:
        state = request.state
        marks = getattr(state, USAGE_MARKS_ATTR, None)
        if isinstance(marks, UsageMarks):
            return marks.result
        return await self.evaluate_usage_rules(
            request, state, client_ip, route_config, middleware
        )

    async def evaluate_usage_rules(
        self,
        request: GuardRequest,
        state: Any,
        client_ip: str,
        route_config: RouteConfig | None,
        middleware: Any,
    ) -> GuardResponse | None:
        behavior_tracker = self._behavior_tracker(request, state)
        if behavior_tracker is None:
            return None

        endpoint_id = self.get_endpoint_id(request, state)
        route_rules = route_config.behavior_rules if route_config is not None else []
        route_throttles = (
            await self._evaluate_route_usage_rules(
                behavior_tracker, request, client_ip, endpoint_id, route_rules
            )
            if route_rules
            else []
        )
        global_rules = self.context.config.global_behavior_rules
        global_usage_rule_ids = (
            await self._evaluate_global_usage_rules(
                behavior_tracker, request, client_ip, endpoint_id
            )
            if global_rules
            else frozenset()
        )
        refused = None
        # _evaluate_global_usage_rules has refreshed the global rule caches.
        if route_throttles or (global_rules and self._global_throttle_cache):
            refused = await self._enforce_throttle(
                behavior_tracker,
                request,
                client_ip,
                endpoint_id,
                route_throttles,
                self._recorded_route_rule_ids(route_rules),
                middleware,
            )
        setattr(state, USAGE_MARKS_ATTR, UsageMarks(refused, global_usage_rule_ids))
        return refused

    @staticmethod
    def _recorded_route_rule_ids(route_rules: Sequence[BehaviorRule]) -> frozenset[str]:
        # A custom_action copy of a throttle rule shares its hit list and has
        # already recorded this request's hit in the route rule loop.
        return frozenset(
            rule.discriminator()
            for rule in route_rules
            if rule.rule_type != "return_pattern" and not is_throttle_rule(rule)
        )

    async def _evaluate_global_usage_rules(
        self, tracker: Any, request: GuardRequest, client_ip: str, endpoint_id: str
    ) -> frozenset[str]:
        seen: set[str] = set()
        rules = self._global_rules()
        throttles = self._global_throttle_cache
        for rule in rules:
            if rule.rule_type != "return_pattern" and rule not in throttles:
                await self._evaluate_global_usage_rule(
                    tracker,
                    request,
                    client_ip,
                    endpoint_id,
                    rule,
                    first_of_rule_id(seen, rule),
                )
        return frozenset(seen)

    async def _evaluate_route_usage_rules(
        self,
        behavior_tracker: Any,
        request: GuardRequest,
        client_ip: str,
        endpoint_id: str,
        route_rules: Sequence[BehaviorRule],
    ) -> list[BehaviorRule]:
        route_throttles: list[BehaviorRule] = []
        seen: set[str] = set()
        for rule in route_rules:
            if is_throttle_rule(rule):
                route_throttles.append(rule)
            elif rule.rule_type in ["usage", "frequency"]:
                threshold_exceeded = await behavior_tracker.track_endpoint_usage(
                    endpoint_id, client_ip, rule, first_of_rule_id(seen, rule)
                )
                if threshold_exceeded:
                    details = f"{rule.threshold} calls in {rule.window}s"
                    message = f"Behavioral {rule.rule_type}"
                    reason = "threshold exceeded"
                    await self._report_decorator_violation(
                        request,
                        rule,
                        endpoint_id,
                        f"{message} {reason}: {details}",
                        "behavioral",
                    )
                    await behavior_tracker.apply_action(
                        rule,
                        client_ip,
                        endpoint_id,
                        f"Usage threshold exceeded: {details}",
                    )
        return route_throttles

    async def process_return_rules(
        self,
        request: GuardRequest,
        response: GuardResponse,
        client_ip: str,
        route_config: RouteConfig,
    ) -> None:
        return_rules = [
            rule
            for rule in route_config.behavior_rules
            if rule.rule_type == "return_pattern"
        ]
        if not return_rules:
            return
        behavior_tracker = self._behavior_tracker(request)
        if behavior_tracker is None:
            return

        endpoint_id = self.get_endpoint_id(request)
        seen: set[str] = set()
        for rule in return_rules:
            pattern_detected = await behavior_tracker.track_return_pattern(
                endpoint_id,
                client_ip,
                response,
                rule,
                record=first_of_rule_id(seen, rule),
            )
            if pattern_detected and not is_throttle_rule(rule):
                details = f"{rule.threshold} for '{rule.pattern}' in {rule.window}s"
                await self._report_decorator_violation(
                    request,
                    rule,
                    endpoint_id,
                    f"Return pattern threshold exceeded: {details}",
                    "behavioral",
                    pattern=rule.pattern,
                )
                await behavior_tracker.apply_action(
                    rule,
                    client_ip,
                    endpoint_id,
                    f"Return pattern threshold exceeded: {details}",
                )

    async def process_global_rules(
        self,
        request: GuardRequest,
        response: GuardResponse,
        client_ip: str,
        rules: Sequence[BehaviorRule],
    ) -> None:
        state = request.state
        marks = usage_marks_of(state)
        pending = list(
            filter(
                partial(
                    _counts_in_response_phase,
                    recorded_before_handler=(
                        marks.global_usage_rule_ids
                        if marks is not None
                        else frozenset()
                    ),
                ),
                rules,
            )
        )
        tracker = self._behavior_tracker(request, state) if pending else None
        if tracker is None:
            return

        endpoint_id = self.get_endpoint_id(request, state)
        lookup = self._lookup_correlated_categories(tracker, client_ip)

        seen: set[str] = set()
        for rule in pending:
            record = first_of_rule_id(seen, rule)
            if rule.rule_type == "return_pattern":
                await self._evaluate_global_return_rule(
                    tracker,
                    request,
                    response,
                    client_ip,
                    endpoint_id,
                    rule,
                    lookup,
                    record,
                )
            else:
                await self._evaluate_global_usage_rule(
                    tracker, request, client_ip, endpoint_id, rule, record
                )

    process_global_return_rules = process_global_rules

    async def _evaluate_global_usage_rule(
        self,
        tracker: Any,
        request: GuardRequest,
        client_ip: str,
        endpoint_id: str,
        rule: BehaviorRule,
        record: bool = True,
    ) -> None:
        if not await tracker.track_endpoint_usage(
            global_scope_id(rule), client_ip, rule, record
        ):
            return

        details = f"{rule.threshold} calls in {rule.window}s"
        await self._report_decorator_violation(
            request,
            rule,
            endpoint_id,
            f"Global behavioral {rule.rule_type} threshold exceeded: {details}",
            "behavioral_global",
        )
        await tracker.apply_action(
            rule,
            client_ip,
            endpoint_id,
            f"Global usage threshold exceeded: {details}",
        )

    async def _evaluate_global_return_rule(
        self,
        tracker: Any,
        request: GuardRequest,
        response: GuardResponse,
        client_ip: str,
        endpoint_id: str,
        rule: BehaviorRule,
        lookup: Callable[[], Awaitable[list[str]]],
        record: bool = True,
    ) -> None:
        correlation = (
            ReturnCorrelation(correlated_return_threshold(rule), lookup)
            if rule.correlate_with_detection
            else None
        )
        pattern_detected = await tracker.track_return_pattern(
            global_scope_id(rule),
            client_ip,
            response,
            rule,
            record=record,
            correlation=correlation,
        )
        if not pattern_detected or is_throttle_rule(rule):
            return

        correlated = (
            correlation if correlation is not None and correlation.active else None
        )
        effective_threshold = correlated.threshold if correlated else rule.threshold
        details = (
            f"{effective_threshold} for '{rule.pattern}' in {rule.window}s"
            f"{' (correlated)' if correlated else ''}"
        )

        await self._report_decorator_violation(
            request,
            rule,
            endpoint_id,
            f"Global return pattern threshold exceeded: {details}",
            "behavioral_global",
            pattern=rule.pattern,
            threshold=effective_threshold,
            correlation=correlated is not None,
            correlated_categories=correlated.categories if correlated else [],
        )
        await tracker.apply_action(
            rule,
            client_ip,
            endpoint_id,
            f"Global return pattern threshold exceeded: {details}",
        )

    async def _report_decorator_violation(
        self,
        request: GuardRequest,
        rule: BehaviorRule,
        endpoint_id: str,
        reason: str,
        decorator_type: str,
        action_taken: str | None = None,
        **overrides: Any,
    ) -> None:
        fields: dict[str, Any] = {
            "violation_type": rule.rule_type,
            "threshold": rule.threshold,
            "window": rule.window,
            "action": rule.action,
            "endpoint_id": endpoint_id,
        }
        fields.update(overrides)
        guard_decorator = self.context.guard_decorator
        if decorator_type == "behavioral" and guard_decorator is not None:
            if action_taken is None:
                await guard_decorator.send_decorator_violation_event(
                    request,
                    violation_type=fields.pop("violation_type"),
                    reason=reason,
                    **fields,
                )
                return
            await guard_decorator.send_decorator_event(
                event_type=EVENT_DECORATOR_VIOLATION,
                request=request,
                action_taken=action_taken,
                reason=reason,
                decorator_type=fields.pop("violation_type"),
                **fields,
            )
            return
        await self.context.event_bus.send_middleware_event(
            event_type=EVENT_DECORATOR_VIOLATION,
            request=request,
            action_taken=action_taken or "behavioral_action_triggered",
            reason=reason,
            decorator_type=decorator_type,
            **fields,
        )

    def get_endpoint_id(self, request: GuardRequest, state: Any = None) -> str:
        state = request.state if state is None else state
        route_id: str | None = getattr(state, "guard_route_id", None)
        if route_id:
            return route_id
        endpoint_id: str | None = getattr(state, "guard_endpoint_id", None)
        if endpoint_id:
            return endpoint_id
        safe_path = redact_endpoint_for_display(
            str(request.url_path),
            self.context.config.log_sensitive_params,
            self.context.config.log_sensitive_body_fields,
            self.context.config.log_sensitive_headers,
        )
        return f"{request.method}:{safe_path}"
