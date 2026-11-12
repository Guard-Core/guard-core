from collections.abc import Callable
from typing import Literal

from guard_core._misconfiguration_kinds import (
    K_BEHAVIOR_RULE_NON_POSITIVE,
    K_SUSPICIOUS_FREQUENCY_PRODUCT_BELOW_ONE,
    Problem,
)
from guard_core.models import (
    SyncSecurityConfig,
    _validate_return_pattern_body_scan,
)
from guard_core.sync.decorators.base import (
    BaseSecurityMixin,
    GuardedParams,
    GuardedReturn,
)
from guard_core.sync.handlers.behavior_handler import BehaviorRule


class BehavioralMixin(BaseSecurityMixin):
    config: SyncSecurityConfig

    def _report_non_positive_behavior_rule(
        self, name: str, threshold: float, window: float
    ) -> None:
        if threshold < 1 or window < 1:
            self._report_misconfiguration(
                Problem(
                    f"@{name}(threshold={threshold}, window={window}): the "
                    "threshold and the window must both be at least 1.",
                    kind=K_BEHAVIOR_RULE_NON_POSITIVE,
                    subject=name,
                )
            )

    def usage_monitor(
        self,
        max_calls: int,
        window: int = 3600,
        action: Literal["ban", "log", "throttle", "alert"] = "ban",
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            self._report_non_positive_behavior_rule("usage_monitor", max_calls, window)
            route_config = self._ensure_route_config(func)

            rule = BehaviorRule(
                rule_type="usage", threshold=max_calls, window=window, action=action
            )
            route_config.behavior_rules.append(rule)
            return self._apply_route_config(func)

        return decorator

    def return_monitor(
        self,
        pattern: str,
        max_occurrences: int,
        window: int = 86400,
        action: Literal["ban", "log", "throttle", "alert"] = "ban",
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        _validate_return_pattern_body_scan(pattern, self.config)

        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            self._report_non_positive_behavior_rule(
                "return_monitor", max_occurrences, window
            )
            route_config = self._ensure_route_config(func)

            rule = BehaviorRule(
                rule_type="return_pattern",
                threshold=max_occurrences,
                window=window,
                pattern=pattern,
                action=action,
            )
            route_config.behavior_rules.append(rule)
            return self._apply_route_config(func)

        return decorator

    def behavior_analysis(
        self, rules: list[BehaviorRule]
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        for rule in rules:
            if rule.rule_type == "return_pattern" and rule.pattern:
                _validate_return_pattern_body_scan(rule.pattern, self.config)

        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            for rule in rules:
                self._report_non_positive_behavior_rule(
                    "behavior_analysis", rule.threshold, rule.window
                )
            route_config = self._ensure_route_config(func)
            route_config.behavior_rules.extend(rules)
            return self._apply_route_config(func)

        return decorator

    def suspicious_frequency(
        self,
        max_frequency: float,
        window: int = 300,
        action: Literal["ban", "log", "throttle", "alert"] = "ban",
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            if max_frequency * window < 1:
                self._report_misconfiguration(
                    Problem(
                        f"@suspicious_frequency(max_frequency={max_frequency}, "
                        f"window={window}): max_frequency times window is below "
                        "1, so the threshold becomes 0 and every request would "
                        "trip the rule.",
                        kind=K_SUSPICIOUS_FREQUENCY_PRODUCT_BELOW_ONE,
                    )
                )
            route_config = self._ensure_route_config(func)
            max_calls = int(max_frequency * window)

            rule = BehaviorRule(
                rule_type="frequency",
                threshold=max_calls,
                window=window,
                action=action,
            )
            route_config.behavior_rules.append(rule)
            return self._apply_route_config(func)

        return decorator
