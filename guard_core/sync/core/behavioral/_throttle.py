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
    behavior_client_identity,
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


def first_of_rule_id(seen: set[str], rule: BehaviorRule) -> bool:
    # Rules sharing a rule_id share one hit list: only the first of them in a
    # request or response records the hit, each still evaluates its own threshold.
    rule_id = rule.discriminator()
    first = rule_id not in seen
    seen.add(rule_id)
    return first


def is_throttle_rule(rule: BehaviorRule) -> bool:
    return rule.action == "throttle" and rule.custom_action is None


def correlated_return_threshold(rule: BehaviorRule) -> int:
    return max(1, rule.threshold // 2)


def effective_return_threshold(
    rule: BehaviorRule, correlated_categories: list[str]
) -> tuple[int, bool]:
    correlation_active = rule.correlate_with_detection and bool(correlated_categories)
    if correlation_active:
        return correlated_return_threshold(rule), True
    return rule.threshold, False


def _route_check(
    rule: BehaviorRule, endpoint_id: str, recorded_rule_ids: frozenset[str]
) -> ThrottleCheck:
    if rule.rule_type == "return_pattern":
        return ThrottleCheck(rule, endpoint_id, False, rule.threshold + 1)
    if rule.discriminator() in recorded_rule_ids:
        return ThrottleCheck(rule, endpoint_id, True, rule.threshold + 1, True)
    return ThrottleCheck(rule, endpoint_id, True, rule.threshold)


def _global_check(rule: BehaviorRule) -> ThrottleCheck:
    scope_id = global_scope_id(rule)
    if rule.rule_type == "return_pattern":
        correlated_at = (
            correlated_return_threshold(rule) + 1
            if rule.correlate_with_detection
            else 0
        )
        return ThrottleCheck(
            rule,
            scope_id,
            False,
            rule.threshold + 1,
            correlated_refuse_at=correlated_at,
        )
    return ThrottleCheck(rule, scope_id, True, rule.threshold)


def _trip_limit(check: ThrottleCheck) -> int:
    return check.refuse_at if check.writes else check.refuse_at - 1


class BehavioralThrottleMixin:
    context: BehavioralContext
    _global_rules_source: tuple[BehaviorRuleConfig, ...] | None
    _global_rules_cache: tuple[BehaviorRule, ...]
    _global_throttle_cache: tuple[BehaviorRule, ...]
    _throttle_sampled: "OrderedDict[str, float]"
    _throttle_sample_lock: threading.Lock
    _throttle_refusals: "OrderedDict[str, int]"
    _throttle_count_lock: threading.Lock
    _report_decorator_violation: Callable[..., None]
    _evaluate_global_usage_rule: Callable[..., None]

    def _init_throttle_state(self) -> None:
        self._global_rules_source = None
        self._global_rules_cache = ()
        self._global_throttle_cache = ()
        self._throttle_sampled = OrderedDict()
        self._throttle_sample_lock = threading.Lock()
        self._throttle_refusals = OrderedDict()
        self._throttle_count_lock = threading.Lock()

    def _global_rules(self) -> tuple[BehaviorRule, ...]:
        configs = self.context.config.global_behavior_rules
        if configs is not self._global_rules_source:
            self._global_rules_cache = tuple(config_to_rule(cfg) for cfg in configs)
            self._global_throttle_cache = tuple(
                filter(is_throttle_rule, self._global_rules_cache)
            )
            self._global_rules_source = configs
        return self._global_rules_cache

    def _global_throttle_rules(self) -> tuple[BehaviorRule, ...]:
        if self.context.config.global_behavior_rules is not self._global_rules_source:
            self._global_rules()
        return self._global_throttle_cache

    def _collect_correlated_categories(self, client_ip: str) -> list[str]:
        if self.context.middleware is None:
            return []
        from guard_core.sync.core.checks.helpers import _strike_identity

        counts = getattr(self.context.middleware, "suspicious_request_counts", {})
        ip_counts = dict(
            counts.get(_strike_identity(self.context.config, client_ip), {})
        )
        return sorted(cat for cat, n in ip_counts.items() if n > 0)

    def _shared_or_process_categories(self, tracker: Any, client_ip: str) -> list[str]:
        from guard_core.sync.core.checks._shared_strikes import (
            read_shared_detection_categories,
        )
        from guard_core.sync.core.checks.helpers import (
            SUSPICIOUS_COUNT_WINDOW_SECONDS,
            _strike_identity,
        )

        redis_handler = getattr(tracker, "redis_handler", None)
        if self.context.middleware is not None and (
            redis_handler and redis_handler.config.enable_redis
        ):
            shared = read_shared_detection_categories(
                redis_handler,
                _strike_identity(self.context.config, client_ip),
                SUSPICIOUS_COUNT_WINDOW_SECONDS,
            )
            if shared is not None:
                return shared
        return self._collect_correlated_categories(client_ip)

    def _lookup_correlated_categories(
        self, tracker: Any, client_ip: str
    ) -> Callable[[], list[str]]:
        cached: list[list[str]] = []

        def lookup() -> list[str]:
            if not cached:
                cached.append(self._shared_or_process_categories(tracker, client_ip))
            return cached[0]

        return lookup

    def _throttle_checks(
        self,
        client_ip: str,
        endpoint_id: str,
        route_throttles: Sequence[BehaviorRule],
        recorded_rule_ids: frozenset[str],
    ) -> list[ThrottleCheck]:
        checks = [
            _route_check(rule, endpoint_id, recorded_rule_ids)
            for rule in route_throttles
        ]
        checks += [_global_check(rule) for rule in self._global_throttle_rules()]
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
        route_throttles: Sequence[BehaviorRule],
        recorded_rule_ids: frozenset[str] = frozenset(),
    ) -> GuardResponse | None:
        checks = self._throttle_checks(
            client_ip, endpoint_id, route_throttles, recorded_rule_ids
        )
        enforced = self._throttle_enforced()
        try:
            trips: list[ThrottleTrip] = tracker.check_throttle(
                client_ip,
                checks,
                time.time(),
                record_when_over=not enforced,
                process_categories=lambda: self._collect_correlated_categories(
                    client_ip
                ),
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
            trip_marker_key(
                check.scope_id,
                behavior_client_identity(self.context.config, client_ip),
                rule,
            ),
            trip.first_of_episode,
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
        seen: set[str] = set()
        for rule in self._global_rules():
            if rule.rule_type != "return_pattern" and not is_throttle_rule(rule):
                self._evaluate_global_usage_rule(
                    tracker,
                    request,
                    client_ip,
                    endpoint_id,
                    rule,
                    first_of_rule_id(seen, rule),
                )
