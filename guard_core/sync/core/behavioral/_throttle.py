import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from typing import Any

from guard_core.exceptions import GuardRedisError
from guard_core.models import BehaviorRuleConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.request_logging import redact_header_value_for_display
from guard_core.sync._utils.sampling import observe_sampled_key
from guard_core.sync.core.behavioral.context import BehavioralContext
from guard_core.sync.handlers._behavior_throttle import (
    ThrottleCheck,
    ThrottleTrip,
    trip_marker_key,
)
from guard_core.sync.handlers.behavior_handler import BehaviorRule, config_to_rule
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

THROTTLE_EVENT_SAMPLE_SECONDS = 60
MAX_SAMPLED_THROTTLE_KEYS = 10_000

_logger = logging.getLogger("guard_core.sync.core.behavioral")
_missing_middleware_warned = False


def _warn_throttle_needs_middleware() -> None:
    global _missing_middleware_warned
    if _missing_middleware_warned:
        return
    _missing_middleware_warned = True
    _logger.warning(
        "Behavior throttle rules are only logged: this adapter does not pass "
        "its middleware to the behavioral processor, so the engine cannot "
        "answer 429. Upgrade the adapter to enforce throttle rules."
    )


def global_scope_id(rule: BehaviorRule) -> str:
    return f"global|{rule.discriminator()}"


def is_throttle_rule(rule: BehaviorRule) -> bool:
    return rule.action == "throttle" and rule.custom_action is None


def effective_return_threshold(
    rule: BehaviorRule, correlated_categories: list[str]
) -> tuple[int, bool]:
    correlation_active = rule.correlate_with_detection and bool(correlated_categories)
    if correlation_active:
        return max(1, rule.threshold // 2), True
    return rule.threshold, False


def _route_check(rule: BehaviorRule, endpoint_id: str) -> ThrottleCheck:
    if rule.rule_type == "return_pattern":
        return ThrottleCheck(rule, endpoint_id, False, rule.threshold + 1)
    return ThrottleCheck(rule, endpoint_id, True, rule.threshold)


def _global_check(
    rule: BehaviorRule, correlated_categories: list[str]
) -> ThrottleCheck:
    scope_id = global_scope_id(rule)
    if rule.rule_type == "return_pattern":
        threshold, _ = effective_return_threshold(rule, correlated_categories)
        return ThrottleCheck(rule, scope_id, False, threshold + 1)
    return ThrottleCheck(rule, scope_id, True, rule.threshold)


def _trip_limit(check: ThrottleCheck) -> int:
    return check.refuse_at if check.records else check.refuse_at - 1


class BehavioralThrottleMixin:
    context: BehavioralContext
    _global_rules_source: tuple[BehaviorRuleConfig, ...] | None
    _global_rules_cache: tuple[BehaviorRule, ...]
    _throttle_sampled: "OrderedDict[str, float]"
    _throttle_sample_lock: threading.Lock
    _throttle_refusals: "OrderedDict[str, int]"
    _throttle_count_lock: threading.Lock
    _report_decorator_violation: Callable[..., None]
    _evaluate_global_usage_rule: Callable[..., None]

    def _init_throttle_state(self) -> None:
        self._global_rules_source = None
        self._global_rules_cache = ()
        self._throttle_sampled = OrderedDict()
        self._throttle_sample_lock = threading.Lock()
        self._throttle_refusals = OrderedDict()
        self._throttle_count_lock = threading.Lock()

    def _global_rules(self) -> tuple[BehaviorRule, ...]:
        configs = self.context.config.global_behavior_rules
        if configs is not self._global_rules_source:
            self._global_rules_cache = tuple(config_to_rule(cfg) for cfg in configs)
            self._global_rules_source = configs
        return self._global_rules_cache

    def _collect_correlated_categories(self, client_ip: str) -> list[str]:
        if self.context.middleware is None:
            return []
        counts = getattr(self.context.middleware, "suspicious_request_counts", {})
        ip_counts = dict(counts.get(client_ip, {}))
        return sorted(cat for cat, n in ip_counts.items() if n > 0)

    def _throttle_checks(
        self, client_ip: str, endpoint_id: str, route_rules: Sequence[BehaviorRule]
    ) -> list[ThrottleCheck]:
        checks = [
            _route_check(rule, endpoint_id)
            for rule in route_rules
            if is_throttle_rule(rule)
        ]
        global_throttles = [r for r in self._global_rules() if is_throttle_rule(r)]
        if global_throttles:
            correlated = self._collect_correlated_categories(client_ip)
            checks += [_global_check(rule, correlated) for rule in global_throttles]
        return checks

    def _throttle_enforced(self) -> bool:
        if self.context.config.passive_mode:
            return False
        if self.context.middleware is not None:
            return True
        _warn_throttle_needs_middleware()
        return False

    def _enforce_throttle(
        self,
        tracker: Any,
        request: SyncGuardRequest,
        client_ip: str,
        endpoint_id: str,
        route_rules: Sequence[BehaviorRule],
    ) -> GuardResponse | None:
        checks = self._throttle_checks(client_ip, endpoint_id, route_rules)
        if not checks:
            return None
        enforced = self._throttle_enforced()
        try:
            trips: list[ThrottleTrip] = tracker.check_throttle(
                client_ip, checks, time.time(), record_when_over=not enforced
            )
        except GuardRedisError as error:
            return self._throttle_check_failed(error)
        if not trips:
            return None
        for trip in trips:
            self._report_throttle_trip(
                tracker, request, client_ip, endpoint_id, trip, enforced
            )
        if not enforced:
            return None
        self._count_refused_request_in_global_rules(
            tracker, request, client_ip, endpoint_id
        )
        response: GuardResponse = self.context.middleware.create_error_response(
            429, "Too many requests"
        )
        response.headers["Retry-After"] = str(max(t.retry_after for t in trips))
        return response

    def _throttle_check_failed(self, error: GuardRedisError) -> GuardResponse | None:
        config = self.context.config
        safe_message = redact_header_value_for_display(
            str(error),
            config.log_sensitive_params,
            config.log_sensitive_body_fields,
            config.log_sensitive_headers,
        )
        self.context.logger.error(
            f"Error in behavior throttle ({type(error).__name__}): {safe_message}"
        )
        if not config.fail_secure or self.context.middleware is None:
            return None
        self.context.logger.warning(
            "Blocking request due to check error in fail-secure mode: behavior throttle"
        )
        response: GuardResponse = self.context.middleware.create_error_response(
            500, "Security check failed"
        )
        return response

    def _refusals_to_report(self, key: str, first_of_episode: bool) -> int | None:
        sampled = observe_sampled_key(
            self._throttle_sampled,
            self._throttle_sample_lock,
            key,
            window=THROTTLE_EVENT_SAMPLE_SECONDS,
            max_tracked=MAX_SAMPLED_THROTTLE_KEYS,
        )
        with self._throttle_count_lock:
            refusals = self._throttle_refusals.pop(key, 0) + 1
            if first_of_episode or sampled:
                return refusals
            if len(self._throttle_refusals) >= MAX_SAMPLED_THROTTLE_KEYS:
                self._throttle_refusals.popitem(last=False)
            self._throttle_refusals[key] = refusals
            return None

    def _report_throttle_trip(
        self,
        tracker: Any,
        request: SyncGuardRequest,
        client_ip: str,
        endpoint_id: str,
        trip: ThrottleTrip,
        enforced: bool,
    ) -> None:
        check = trip.check
        rule = check.rule
        refusals = self._refusals_to_report(
            trip_marker_key(check.scope_id, client_ip, rule), trip.first_of_episode
        )
        if refusals is None:
            return
        limit = _trip_limit(check)
        is_global = check.scope_id == global_scope_id(rule)
        if rule.rule_type == "return_pattern":
            details = f"{limit} for '{rule.pattern}' in {rule.window}s"
            extra: dict[str, Any] = {"pattern": rule.pattern}
        else:
            details = f"{limit} calls in {rule.window}s"
            extra = {}
        scope = "Global behavioral" if is_global else "Behavioral"
        self._report_decorator_violation(
            request,
            rule,
            endpoint_id,
            f"{scope} {rule.rule_type} throttle threshold reached: {details}",
            "behavioral_global" if is_global else "behavioral",
            action_taken="throttle" if enforced else "logged_only",
            threshold=limit,
            **extra,
        )
        tracker.apply_action(
            rule,
            client_ip,
            endpoint_id,
            f"Throttle threshold reached: {details}",
            observe_only=not enforced,
            matched_rule_type="behavioral",
            matched_rule_id=rule.matched_rule_id(),
            refusals_since_last_event=refusals,
        )

    def _count_refused_request_in_global_rules(
        self, tracker: Any, request: SyncGuardRequest, client_ip: str, endpoint_id: str
    ) -> None:
        for rule in self._global_rules():
            if rule.rule_type != "return_pattern" and not is_throttle_rule(rule):
                self._evaluate_global_usage_rule(
                    tracker, request, client_ip, endpoint_id, rule
                )
