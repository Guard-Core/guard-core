from typing import Any

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.request_logging import redact_endpoint_for_display
from guard_core.sync.core.behavioral.context import BehavioralContext
from guard_core.sync.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.behavior_handler import BehaviorRule
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class BehavioralProcessor:
    def __init__(self, context: BehavioralContext) -> None:
        self.context = context

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
        self, request: SyncGuardRequest, client_ip: str, route_config: RouteConfig
    ) -> None:
        behavior_tracker = self._behavior_tracker(request)
        if behavior_tracker is None:
            return

        endpoint_id = self.get_endpoint_id(request)
        for rule in route_config.behavior_rules:
            if rule.rule_type in ["usage", "frequency"]:
                threshold_exceeded = behavior_tracker.track_endpoint_usage(
                    endpoint_id, client_ip, rule
                )
                if threshold_exceeded:
                    details = f"{rule.threshold} calls in {rule.window}s"
                    message = f"Behavioral {rule.rule_type}"
                    reason = "threshold exceeded"
                    violation_reason = f"{message} {reason}: {details}"

                    guard_decorator = self.context.guard_decorator
                    if guard_decorator is not None:
                        guard_decorator.send_decorator_violation_event(
                            request,
                            violation_type=rule.rule_type,
                            reason=violation_reason,
                            threshold=rule.threshold,
                            window=rule.window,
                            action=rule.action,
                            endpoint_id=endpoint_id,
                        )
                    else:
                        self.context.event_bus.send_middleware_event(
                            event_type=EVENT_DECORATOR_VIOLATION,
                            request=request,
                            action_taken="behavioral_action_triggered",
                            reason=violation_reason,
                            decorator_type="behavioral",
                            violation_type=rule.rule_type,
                            threshold=rule.threshold,
                            window=rule.window,
                            action=rule.action,
                            endpoint_id=endpoint_id,
                        )

                    behavior_tracker.apply_action(
                        rule,
                        client_ip,
                        endpoint_id,
                        f"Usage threshold exceeded: {details}",
                    )

    def process_return_rules(
        self,
        request: SyncGuardRequest,
        response: GuardResponse,
        client_ip: str,
        route_config: RouteConfig,
    ) -> None:
        behavior_tracker = self._behavior_tracker(request)
        if behavior_tracker is None:
            return

        endpoint_id = self.get_endpoint_id(request)
        for rule in route_config.behavior_rules:
            if rule.rule_type == "return_pattern":
                pattern_detected = behavior_tracker.track_return_pattern(
                    endpoint_id, client_ip, response, rule
                )
                if pattern_detected:
                    details = f"{rule.threshold} for '{rule.pattern}' in {rule.window}s"
                    violation_reason = f"Return pattern threshold exceeded: {details}"

                    guard_decorator = self.context.guard_decorator
                    if guard_decorator is not None:
                        guard_decorator.send_decorator_violation_event(
                            request,
                            violation_type="return_pattern",
                            reason=violation_reason,
                            threshold=rule.threshold,
                            window=rule.window,
                            pattern=rule.pattern,
                            action=rule.action,
                            endpoint_id=endpoint_id,
                        )
                    else:
                        self.context.event_bus.send_middleware_event(
                            event_type=EVENT_DECORATOR_VIOLATION,
                            request=request,
                            action_taken="behavioral_action_triggered",
                            reason=violation_reason,
                            decorator_type="behavioral",
                            violation_type="return_pattern",
                            threshold=rule.threshold,
                            window=rule.window,
                            pattern=rule.pattern,
                            action=rule.action,
                            endpoint_id=endpoint_id,
                        )

                    behavior_tracker.apply_action(
                        rule,
                        client_ip,
                        endpoint_id,
                        f"Return pattern threshold exceeded: {details}",
                    )

    def process_global_return_rules(
        self,
        request: SyncGuardRequest,
        response: GuardResponse,
        client_ip: str,
        rules: list[BehaviorRule],
    ) -> None:
        tracker = self._behavior_tracker(request)
        if tracker is None:
            return

        endpoint_id = self.get_endpoint_id(request)
        correlated_categories = self._collect_correlated_categories(client_ip)

        for rule in rules:
            if rule.rule_type != "return_pattern":
                continue
            self._evaluate_global_return_rule(
                tracker,
                request,
                response,
                client_ip,
                endpoint_id,
                rule,
                correlated_categories,
            )

    def _collect_correlated_categories(self, client_ip: str) -> list[str]:
        if self.context.middleware is None:
            return []
        counts = getattr(self.context.middleware, "suspicious_request_counts", {})
        ip_counts = dict(counts.get(client_ip, {}))
        return sorted(cat for cat, n in ip_counts.items() if n > 0)

    def _evaluate_global_return_rule(
        self,
        tracker: Any,
        request: SyncGuardRequest,
        response: GuardResponse,
        client_ip: str,
        endpoint_id: str,
        rule: BehaviorRule,
        correlated_categories: list[str],
    ) -> None:
        correlation_active = rule.correlate_with_detection and bool(
            correlated_categories
        )
        effective_threshold = (
            max(1, rule.threshold // 2) if correlation_active else rule.threshold
        )

        pattern_detected = tracker.track_return_pattern(
            endpoint_id,
            client_ip,
            response,
            rule,
            effective_threshold=effective_threshold,
        )
        if not pattern_detected:
            return

        details = (
            f"{effective_threshold} for '{rule.pattern}' in {rule.window}s"
            f"{' (correlated)' if correlation_active else ''}"
        )

        self.context.event_bus.send_middleware_event(
            event_type=EVENT_DECORATOR_VIOLATION,
            request=request,
            action_taken="behavioral_action_triggered",
            reason=f"Global return pattern threshold exceeded: {details}",
            decorator_type="behavioral_global",
            violation_type="return_pattern",
            threshold=effective_threshold,
            window=rule.window,
            pattern=rule.pattern,
            action=rule.action,
            endpoint_id=endpoint_id,
            correlation=correlation_active,
            correlated_categories=correlated_categories if correlation_active else [],
        )

        tracker.apply_action(
            rule,
            client_ip,
            endpoint_id,
            f"Global return pattern threshold exceeded: {details}",
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
