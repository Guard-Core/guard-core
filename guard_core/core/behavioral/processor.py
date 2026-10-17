from typing import Any

from guard_core._utils.request_logging import redact_endpoint_for_display
from guard_core.core.behavioral.context import BehavioralContext
from guard_core.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.decorators.base import RouteConfig
from guard_core.handlers.behavior_handler import BehaviorRule
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

_RECENT_RECORDED_STATE_FLAG = "guard_behavior_request_recorded"


def _global_tracking_endpoint_id(rule: BehaviorRule) -> str:
    return f"global|{rule.discriminator()}"


class BehavioralProcessor:
    def __init__(self, context: BehavioralContext) -> None:
        self.context = context

    def _behavior_tracker(self, request: GuardRequest) -> Any | None:
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

    async def process_usage_rules(
        self, request: GuardRequest, client_ip: str, route_config: RouteConfig
    ) -> None:
        behavior_tracker = self._behavior_tracker(request)
        if behavior_tracker is None:
            return

        endpoint_id = self.get_endpoint_id(request)
        await self._record_recent_request_once(
            behavior_tracker, request, client_ip, route_config.behavior_rules
        )
        for rule in route_config.behavior_rules:
            if rule.rule_type in ["usage", "frequency"]:
                threshold_exceeded = await behavior_tracker.track_endpoint_usage(
                    endpoint_id, client_ip, rule
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

    async def process_return_rules(
        self,
        request: GuardRequest,
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
                pattern_detected = await behavior_tracker.track_return_pattern(
                    endpoint_id, client_ip, response, rule
                )
                if pattern_detected:
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
        rules: list[BehaviorRule],
    ) -> None:
        tracker = self._behavior_tracker(request)
        if tracker is None:
            return

        endpoint_id = self.get_endpoint_id(request)
        correlated_categories = self._collect_correlated_categories(client_ip)
        await self._record_recent_request_once(tracker, request, client_ip, rules)

        for rule in rules:
            if rule.rule_type == "return_pattern":
                await self._evaluate_global_return_rule(
                    tracker,
                    request,
                    response,
                    client_ip,
                    endpoint_id,
                    rule,
                    correlated_categories,
                )
            else:
                await self._evaluate_global_usage_rule(
                    tracker, request, client_ip, endpoint_id, rule
                )

    process_global_return_rules = process_global_rules

    async def _evaluate_global_usage_rule(
        self,
        tracker: Any,
        request: GuardRequest,
        client_ip: str,
        endpoint_id: str,
        rule: BehaviorRule,
    ) -> None:
        if not await tracker.track_endpoint_usage(
            _global_tracking_endpoint_id(rule), client_ip, rule
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

    def _collect_correlated_categories(self, client_ip: str) -> list[str]:
        if self.context.middleware is None:
            return []
        counts = getattr(self.context.middleware, "suspicious_request_counts", {})
        ip_counts = dict(counts.get(client_ip, {}))
        return sorted(cat for cat, n in ip_counts.items() if n > 0)

    async def _evaluate_global_return_rule(
        self,
        tracker: Any,
        request: GuardRequest,
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

        pattern_detected = await tracker.track_return_pattern(
            _global_tracking_endpoint_id(rule),
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

        await self._report_decorator_violation(
            request,
            rule,
            endpoint_id,
            f"Global return pattern threshold exceeded: {details}",
            "behavioral_global",
            pattern=rule.pattern,
            threshold=effective_threshold,
            correlation=correlation_active,
            correlated_categories=correlated_categories if correlation_active else [],
        )
        await tracker.apply_action(
            rule,
            client_ip,
            endpoint_id,
            f"Global return pattern threshold exceeded: {details}",
        )

    async def _record_recent_request_once(
        self,
        tracker: Any,
        request: GuardRequest,
        client_ip: str,
        rules: list[BehaviorRule],
    ) -> None:
        if not any(rule.rule_type in ("usage", "frequency") for rule in rules):
            return
        if getattr(request.state, _RECENT_RECORDED_STATE_FLAG, False) is True:
            return
        setattr(request.state, _RECENT_RECORDED_STATE_FLAG, True)
        await tracker.record_recent_request(client_ip)

    async def _report_decorator_violation(
        self,
        request: GuardRequest,
        rule: BehaviorRule,
        endpoint_id: str,
        reason: str,
        decorator_type: str,
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
            await guard_decorator.send_decorator_violation_event(
                request,
                violation_type=fields.pop("violation_type"),
                reason=reason,
                **fields,
            )
            return
        await self.context.event_bus.send_middleware_event(
            event_type=EVENT_DECORATOR_VIOLATION,
            request=request,
            action_taken="behavioral_action_triggered",
            reason=reason,
            decorator_type=decorator_type,
            **fields,
        )

    def get_endpoint_id(self, request: GuardRequest) -> str:
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
