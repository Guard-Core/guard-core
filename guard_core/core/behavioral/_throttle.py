import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Sequence

from guard_core._redis_enablement import redis_is_configured
from guard_core._utils.block_events import fire_block_hook
from guard_core._utils.request_logging import redact_header_value_for_display
from guard_core._utils.sampling import observe_sampled_key
from guard_core.core.behavioral.context import BehavioralContext
from guard_core.exceptions import GuardRedisError
from guard_core.handlers._behavior_throttle import (
    ThrottleCheck,
    ThrottleTrip,
    behavior_client_identity,
    trip_marker_key,
)
from guard_core.handlers.behavior_handler import (
    BehaviorRule,
    BehaviorTracker,
    config_to_rule,
)
from guard_core.models import BehaviorRuleConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

ErrorResponder = Callable[[int, str], Awaitable[GuardResponse]]

THROTTLE_EVENT_SAMPLE_SECONDS = 60
MAX_SAMPLED_THROTTLE_KEYS = 10_000

_logger = logging.getLogger("guard_core.core.behavioral")
_missing_middleware_warned = False
_NEEDS_MIDDLEWARE_WARNING = (
    "Behavior throttle rules are only logged: this adapter does not pass "
    "its middleware to the behavioral processor, so the engine cannot "
    "answer 429. Upgrade the adapter to enforce throttle rules."
)


def can_build_error_response(middleware: object | None) -> bool:
    return callable(getattr(middleware, "create_error_response", None))


def _describe_rule(rule: BehaviorRule) -> str:
    return f"{rule.rule_type} threshold={rule.threshold} window={rule.window}s"


def warn_throttle_needs_middleware(rules: Sequence[BehaviorRule]) -> None:
    global _missing_middleware_warned
    if _missing_middleware_warned:
        return
    _missing_middleware_warned = True
    names = "; ".join(_describe_rule(rule) for rule in rules)
    _logger.warning(
        f"{_NEEDS_MIDDLEWARE_WARNING} Rules: {names}. Missing capability: a "
        "middleware with create_error_response, passed to the BehavioralContext "
        "or reachable through the pipeline's checks."
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

    async def _report_decorator_violation(
        self,
        request: GuardRequest,
        rule: BehaviorRule,
        endpoint_id: str,
        reason: str,
        decorator_type: str,
        action_taken: str | None = None,
        **overrides: object,
    ) -> None: ...

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

    def _collect_correlated_categories(
        self, client_ip: str, middleware: object | None = None
    ) -> list[str]:
        if self.context.middleware is not None:
            middleware = self.context.middleware
        if middleware is None:
            return []
        from guard_core.core.checks.helpers import _strike_identity

        counts = getattr(middleware, "suspicious_request_counts", {})
        ip_counts = dict(
            counts.get(_strike_identity(self.context.config, client_ip), {})
        )
        return sorted(cat for cat, n in ip_counts.items() if n > 0)

    async def _shared_or_process_categories(
        self, tracker: BehaviorTracker, client_ip: str
    ) -> list[str]:
        from guard_core.core.checks._shared_strikes import (
            read_shared_detection_categories,
        )
        from guard_core.core.checks.helpers import (
            SUSPICIOUS_COUNT_WINDOW_SECONDS,
            _strike_identity,
        )

        redis_handler = getattr(tracker, "redis_handler", None)
        if self.context.middleware is not None and (
            redis_handler and redis_is_configured(redis_handler.config)
        ):
            shared = await read_shared_detection_categories(
                redis_handler,
                _strike_identity(self.context.config, client_ip),
                SUSPICIOUS_COUNT_WINDOW_SECONDS,
            )
            if shared is not None:
                return shared
        return self._collect_correlated_categories(client_ip)

    def _lookup_correlated_categories(
        self, tracker: BehaviorTracker, client_ip: str
    ) -> Callable[[], Awaitable[list[str]]]:
        cached: list[list[str]] = []

        async def lookup() -> list[str]:
            if not cached:
                cached.append(
                    await self._shared_or_process_categories(tracker, client_ip)
                )
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

    def _error_response_builder(
        self, middleware: object | None
    ) -> ErrorResponder | None:
        # The context's middleware wins; a call argument stands in for it under
        # adapters that never set it. The shared processor is never written.
        builder = (
            self.context.middleware
            if self.context.middleware is not None
            else middleware
        )
        create_error_response: ErrorResponder | None = getattr(
            builder, "create_error_response", None
        )
        return create_error_response if callable(create_error_response) else None

    def _enforcing_builder(
        self, builder: ErrorResponder | None, checks: Sequence[ThrottleCheck]
    ) -> ErrorResponder | None:
        if self.context.config.passive_mode:
            return None
        if builder is not None:
            return builder
        warn_throttle_needs_middleware([check.rule for check in checks])
        return None

    async def _enforce_throttle(
        self,
        tracker: BehaviorTracker,
        request: GuardRequest,
        client_ip: str,
        endpoint_id: str,
        route_throttles: Sequence[BehaviorRule],
        recorded_rule_ids: frozenset[str] = frozenset(),
        middleware: object | None = None,
    ) -> GuardResponse | None:
        checks = self._throttle_checks(
            client_ip, endpoint_id, route_throttles, recorded_rule_ids
        )
        builder = self._error_response_builder(middleware)
        enforcing_builder = self._enforcing_builder(builder, checks)
        enforced = enforcing_builder is not None
        try:
            trips: list[ThrottleTrip] = await tracker.check_throttle(
                client_ip,
                checks,
                time.time(),
                record_when_over=not enforced,
                process_categories=lambda: self._collect_correlated_categories(
                    client_ip, middleware
                ),
            )
        except GuardRedisError as error:
            return await self._throttle_check_failed(error, builder)
        if not trips:
            return None
        for trip in trips:
            await self._report_throttle_trip(
                tracker, request, client_ip, endpoint_id, trip, enforced
            )
        if self.context.config.on_block is not None:
            await self._fire_throttle_block_hook(request, trips, enforced)
        if enforcing_builder is None:
            return None
        response: GuardResponse = await enforcing_builder(429, "Too many requests")
        response.headers["Retry-After"] = str(max(t.retry_after for t in trips))
        return response

    async def _throttle_check_failed(
        self, error: GuardRedisError, builder: ErrorResponder | None
    ) -> GuardResponse | None:
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
        if config.redis_fail_open or config.passive_mode:
            return None
        if not config.fail_secure or builder is None:
            return None
        from guard_core.core.checks.pipeline import REDIS_OUTAGE_RETRY_AFTER

        self.context.logger.warning(
            "Blocking request due to check error in fail-secure mode: behavior throttle"
        )
        response: GuardResponse = await builder(
            error.status_code, "Security check failed"
        )
        response.headers["Retry-After"] = str(REDIS_OUTAGE_RETRY_AFTER)
        return response

    async def _fire_throttle_block_hook(
        self, request: GuardRequest, trips: list[ThrottleTrip], enforced: bool
    ) -> None:
        config = self.context.config
        if not enforced and not config.passive_mode:
            return
        rule = trips[0].check.rule
        await fire_block_hook(
            config.on_block,
            request,
            "behavior_throttle",
            f"Behavior throttle threshold reached: {_describe_rule(rule)}",
            _describe_rule(rule),
            not enforced,
            429 if enforced else None,
            config.log_sensitive_params,
            config.log_sensitive_body_fields,
            config.log_sensitive_headers,
        )

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

    async def _report_throttle_trip(
        self,
        tracker: BehaviorTracker,
        request: GuardRequest,
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
            extra: dict[str, object] = {"pattern": rule.pattern}
        else:
            details = f"{limit} calls in {rule.window}s"
            extra = {}
        scope = "Global behavioral" if is_global else "Behavioral"
        await self._report_decorator_violation(
            request,
            rule,
            endpoint_id,
            f"{scope} {rule.rule_type} throttle threshold reached: {details}",
            "behavioral_global" if is_global else "behavioral",
            action_taken="throttle" if enforced else "logged_only",
            threshold=limit,
            **extra,
        )
        await tracker.apply_action(
            rule,
            client_ip,
            endpoint_id,
            f"Throttle threshold reached: {details}",
            observe_only=not enforced,
            **rule.matched_rule_metadata(),
            refusals_since_last_event=refusals,
        )
