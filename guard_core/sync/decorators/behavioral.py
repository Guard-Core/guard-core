from collections.abc import Callable
from typing import Any, Literal

from guard_core.models import (
    SyncSecurityConfig,
    _validate_return_pattern_body_scan,
)
from guard_core.sync.decorators.base import BaseSecurityMixin, DecoratedFunction
from guard_core.sync.handlers.behavior_handler import BehaviorRule


class BehavioralMixin(BaseSecurityMixin):
    config: SyncSecurityConfig

    def usage_monitor(
        self,
        max_calls: int,
        window: int = 3600,
        action: Literal["ban", "log", "throttle", "alert"] = "ban",
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
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
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        _validate_return_pattern_body_scan(pattern, self.config)

        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
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
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        for rule in rules:
            if rule.rule_type == "return_pattern" and rule.pattern:
                _validate_return_pattern_body_scan(rule.pattern, self.config)

        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
            route_config = self._ensure_route_config(func)
            route_config.behavior_rules.extend(rules)
            return self._apply_route_config(func)

        return decorator

    def suspicious_frequency(
        self,
        max_frequency: float,
        window: int = 300,
        action: Literal["ban", "log", "throttle", "alert"] = "ban",
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
            if max_frequency * window < 1:
                self._report_misconfiguration(
                    f"@suspicious_frequency(max_frequency={max_frequency}, "
                    f"window={window}): max_frequency times window is below 1, "
                    "so the threshold becomes 0 and every request would trip the "
                    "rule."
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
