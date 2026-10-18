from collections.abc import Callable, Sequence
from typing import Any

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.request_logging import redact_endpoint_for_display
from guard_core.sync.core.behavioral._throttle import (
    BehavioralThrottleMixin,
    correlated_return_threshold,
    first_of_rule_id,
    global_scope_id,
    is_throttle_rule,
)
from guard_core.sync.core.behavioral.context import BehavioralContext
from guard_core.sync.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers._behavior_throttle import ReturnCorrelation
from guard_core.sync.handlers.behavior_handler import BehaviorRule
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


def _counts_in_response_phase(rule: BehaviorRule) -> bool:
    return rule.rule_type == "return_pattern" or not is_throttle_rule(rule)


class BehavioralProcessor(BehavioralThrottleMixin):
    def __init__(self, context: BehavioralContext) -> None:
        self.context = context
        self._init_throttle_state()

    def _behavior_tracker(self, request: SyncGuardRequest) -> Any | None:
        if getattr(request.state, "guard_exclusion_scoped", False) is True:
            return None
        if self.context.behavior_tracker is not None:
            return self.context.behavior_tracker
        guard_decorator = self.context.guard_decorator
        if guard_decorator is None:
            guard_decorator = getattr(request.state, "guard_decorator", None)
        if guard_decorator is not None:
            return getattr(guard_decorator, "behavior_tracker", None)
        return None

    def process_usage_rules(
        self,
        request: SyncGuardRequest,
        client_ip: str,
        route_config: RouteConfig | None = None,
    ) -> GuardResponse | None:
        behavior_tracker = self._behavior_tracker(request)
        if behavior_tracker is None:
            return None

        endpoint_id = self.get_endpoint_id(request)
        route_rules = route_config.behavior_rules if route_config is not None else []
        route_throttles = self._evaluate_route_usage_rules(
            behavior_tracker, request, client_ip, endpoint_id, route_rules
        )
        if not route_throttles and not self._global_throttle_rules():
            return None
        # A custom_action copy of a throttle rule shares its hit list and has
        # already recorded this request's hit in the loop above.
        recorded_rule_ids = frozenset(
            rule.discriminator()
            for rule in route_rules
            if rule.rule_type != "return_pattern" and not is_throttle_rule(rule)
        )
        return self._enforce_throttle(
            behavior_tracker,
            request,
            client_ip,
            endpoint_id,
            route_throttles,
            recorded_rule_ids,
        )

    def _evaluate_route_usage_rules(
        self,
        behavior_tracker: Any,
        request: SyncGuardRequest,
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
                threshold_exceeded = behavior_tracker.track_endpoint_usage(
                    endpoint_id, client_ip, rule, first_of_rule_id(seen, rule)
                )
                if threshold_exceeded:
                    details = f"{rule.threshold} calls in {rule.window}s"
                    message = f"Behavioral {rule.rule_type}"
                    reason = "threshold exceeded"
                    self._report_decorator_violation(
                        request,
                        rule,
                        endpoint_id,
                        f"{message} {reason}: {details}",
                        "behavioral",
                    )
                    behavior_tracker.apply_action(
                        rule,
                        client_ip,
                        endpoint_id,
                        f"Usage threshold exceeded: {details}",
                    )
        return route_throttles

    def process_return_rules(
        self,
        request: SyncGuardRequest,
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
            pattern_detected = behavior_tracker.track_return_pattern(
                endpoint_id,
                client_ip,
                response,
                rule,
                record=first_of_rule_id(seen, rule),
            )
            if pattern_detected and not is_throttle_rule(rule):
                details = f"{rule.threshold} for '{rule.pattern}' in {rule.window}s"
                self._report_decorator_violation(
                    request,
                    rule,
                    endpoint_id,
                    f"Return pattern threshold exceeded: {details}",
                    "behavioral",
                    pattern=rule.pattern,
                )
                behavior_tracker.apply_action(
                    rule,
                    client_ip,
                    endpoint_id,
                    f"Return pattern threshold exceeded: {details}",
                )

    def process_global_rules(
        self,
        request: SyncGuardRequest,
        response: GuardResponse,
        client_ip: str,
        rules: Sequence[BehaviorRule],
    ) -> None:
        tracker = self._behavior_tracker(request)
        if tracker is None:
            return

        endpoint_id = self.get_endpoint_id(request)
        lookup = self._lookup_correlated_categories(tracker, client_ip)

        seen: set[str] = set()
        for rule in filter(_counts_in_response_phase, rules):
            record = first_of_rule_id(seen, rule)
            if rule.rule_type == "return_pattern":
                self._evaluate_global_return_rule(
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
                self._evaluate_global_usage_rule(
                    tracker, request, client_ip, endpoint_id, rule, record
                )

    process_global_return_rules = process_global_rules

    def _evaluate_global_usage_rule(
        self,
        tracker: Any,
        request: SyncGuardRequest,
        client_ip: str,
        endpoint_id: str,
        rule: BehaviorRule,
        record: bool = True,
    ) -> None:
        if not tracker.track_endpoint_usage(
            global_scope_id(rule), client_ip, rule, record
        ):
            return

        details = f"{rule.threshold} calls in {rule.window}s"
        self._report_decorator_violation(
            request,
            rule,
            endpoint_id,
            f"Global behavioral {rule.rule_type} threshold exceeded: {details}",
            "behavioral_global",
        )
        tracker.apply_action(
            rule,
            client_ip,
            endpoint_id,
            f"Global usage threshold exceeded: {details}",
        )

    def _evaluate_global_return_rule(
        self,
        tracker: Any,
        request: SyncGuardRequest,
        response: GuardResponse,
        client_ip: str,
        endpoint_id: str,
        rule: BehaviorRule,
        lookup: Callable[[], list[str]],
        record: bool = True,
    ) -> None:
        correlation = (
            ReturnCorrelation(correlated_return_threshold(rule), lookup)
            if rule.correlate_with_detection
            else None
        )
        pattern_detected = tracker.track_return_pattern(
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

        self._report_decorator_violation(
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
        tracker.apply_action(
            rule,
            client_ip,
            endpoint_id,
            f"Global return pattern threshold exceeded: {details}",
        )

    def _report_decorator_violation(
        self,
        request: SyncGuardRequest,
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
                guard_decorator.send_decorator_violation_event(
                    request,
                    violation_type=fields.pop("violation_type"),
                    reason=reason,
                    **fields,
                )
                return
            guard_decorator.send_decorator_event(
                event_type=EVENT_DECORATOR_VIOLATION,
                request=request,
                action_taken=action_taken,
                reason=reason,
                decorator_type=fields.pop("violation_type"),
                **fields,
            )
            return
        self.context.event_bus.send_middleware_event(
            event_type=EVENT_DECORATOR_VIOLATION,
            request=request,
            action_taken=action_taken or "behavioral_action_triggered",
            reason=reason,
            decorator_type=decorator_type,
            **fields,
        )

    def get_endpoint_id(self, request: SyncGuardRequest) -> str:
        route_id: str | None = getattr(request.state, "guard_route_id", None)
        if route_id:
            return route_id
        endpoint_id: str | None = getattr(request.state, "guard_endpoint_id", None)
        if endpoint_id:
            return endpoint_id
        safe_path = redact_endpoint_for_display(
            str(request.url_path),
            self.context.config.log_sensitive_params,
            self.context.config.log_sensitive_body_fields,
            self.context.config.log_sensitive_headers,
        )
        return f"{request.method}:{safe_path}"
