import functools
import logging
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, cast

from guard_core._security_config_field_validators import (
    canonicalize_cloud_provider_selector,
)
from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync._utils.detection_scan import _redact_pattern_source


@dataclass
class DynamicRulePlan:
    state: dict[str, object]
    skipped: list[str] = field(default_factory=list)
    messages: list[tuple[int, str]] = field(default_factory=list)
    emergency_whitelist: list[str] | None = None
    validated: set[str] = field(default_factory=set)

    def set(self, name: str, value: object, *, validate: bool = True) -> None:
        self.state[name] = value
        if validate:
            self.validated.add(name)

    def note(self, message: str, level: int = logging.INFO) -> None:
        self.messages.append((level, message))

    def skip(self, description: str, message: str) -> None:
        self.skipped.append(description)
        self.note(message, logging.WARNING)


def _redact_rejected_patterns(
    rejected: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    return [(_redact_pattern_source(pattern), reason) for pattern, reason in rejected]


class DynamicRulePlanMixin:
    config: SecurityConfig
    logger: logging.Logger

    def _build_plan(
        self, rules: DynamicRules, base: dict[str, object]
    ) -> DynamicRulePlan:
        plan = DynamicRulePlan(state=dict(base))
        valid_user_agents = self._validate_user_agents(plan, rules)
        self._plan_countries(plan, rules)
        self._plan_cloud_providers(plan, rules)
        self._plan_user_agents(plan, valid_user_agents)
        self._plan_rate_limits(plan, rules)
        self._plan_feature_toggles(plan, rules)
        self._plan_emergency_mode(plan, rules)
        return plan

    def _swap_config(self, plan: DynamicRulePlan) -> None:
        for name, value in plan.state.items():
            if name not in plan.validated:
                self.config._set_prevalidated(name, deepcopy(value))
        for name in plan.validated:
            setattr(self.config, name, deepcopy(plan.state[name]))

    def _plan_countries(self, plan: DynamicRulePlan, rules: DynamicRules) -> None:
        blocked, allowed = rules.blocked_countries, rules.whitelist_countries
        if not (blocked or allowed):
            return
        if self.config.geo_ip_handler is None and not self.config.ipinfo_token:
            plan.skip(
                "blocked_countries and whitelist_countries: no geo_ip_handler or "
                "ipinfo_token to resolve IPs to countries",
                "Dynamic rule: country rules cannot take effect (blocked="
                f"{blocked}, allowed={allowed}); no geo_ip_handler or "
                "ipinfo_token is configured to resolve IPs to countries",
            )
            return
        if blocked:
            normalized_blocked = frozenset(c.upper() for c in blocked)
            plan.set("blocked_countries", normalized_blocked)
            plan.note(f"Dynamic rule: Blocked countries {sorted(normalized_blocked)}")
        if allowed:
            normalized_allowed = frozenset(c.upper() for c in allowed)
            plan.set("whitelist_countries", normalized_allowed)
            plan.note(
                f"Dynamic rule: Whitelisted countries {sorted(normalized_allowed)}"
            )

    def _plan_cloud_providers(self, plan: DynamicRulePlan, rules: DynamicRules) -> None:
        providers = rules.blocked_cloud_providers
        if not providers:
            return
        canonical = {p: canonicalize_cloud_provider_selector(p) for p in providers}
        valid = frozenset(name for name in canonical.values() if name is not None)
        plan.set("block_cloud_providers", valid)
        invalid = sorted(p for p, name in canonical.items() if name is None)
        if invalid:
            plan.note(
                f"Dynamic rule: ignored unknown cloud providers {invalid}",
                logging.WARNING,
            )
        plan.note(f"Dynamic rule: Blocked cloud providers {valid}")

    def _validate_user_agents(
        self, plan: DynamicRulePlan, rules: DynamicRules
    ) -> list[str] | None:
        user_agents = rules.blocked_user_agents
        if not user_agents:
            return None
        from guard_core.sync.detection_engine._validation_cache import (
            PatternValidationCache,
        )
        from guard_core.sync.detection_engine.compiler import PatternCompiler
        from guard_core.sync.utils import _MAX_USER_AGENT_MATCH_LENGTH

        cache_path = getattr(
            self.config, "detection_pattern_validation_cache_path", None
        )
        compiler = PatternCompiler(
            validation_cache=(
                PatternValidationCache(cache_path) if cache_path else None
            )
        )
        validate = functools.partial(
            compiler.validate_pattern_safety,
            max_content_length=_MAX_USER_AGENT_MATCH_LENGTH,
        )
        valid: list[str] = []
        rejected: list[tuple[str, str]] = []
        for pattern in user_agents:
            is_safe, reason = validate(pattern)
            if is_safe:
                valid.append(pattern)
            else:
                rejected.append((pattern, reason))
        if rejected:
            plan.note(
                f"Dynamic rule: rejected blocked_user_agents patterns failing the "
                f"ReDoS validator: {_redact_rejected_patterns(rejected)}",
                logging.WARNING,
            )
        return valid

    def _plan_user_agents(
        self, plan: DynamicRulePlan, valid_user_agents: list[str] | None
    ) -> None:
        if valid_user_agents is None:
            return
        plan.set("blocked_user_agents", valid_user_agents, validate=False)
        redacted = [_redact_pattern_source(p) for p in valid_user_agents]
        plan.note(f"Dynamic rule: Blocked user agents {redacted}")

    def _plan_rate_limits(self, plan: DynamicRulePlan, rules: DynamicRules) -> None:
        if not (rules.global_rate_limit or rules.endpoint_rate_limits):
            return
        if rules.global_rate_limit:
            plan.set("rate_limit", rules.global_rate_limit)
            if rules.global_rate_window:
                plan.set("rate_limit_window", rules.global_rate_window)
            message = f"Global rate limit {rules.global_rate_limit}"
            plan.note(f"Dynamic rule: {message} per {rules.global_rate_window}s")
        if rules.endpoint_rate_limits:
            plan.set("endpoint_rate_limits", rules.endpoint_rate_limits.copy())
            plan.note(
                f"Dynamic rule: Applied endpoint-specific rate limits for "
                f"{len(rules.endpoint_rate_limits)} endpoints: "
                f"{list(rules.endpoint_rate_limits.keys())}"
            )

    def _plan_feature_toggles(self, plan: DynamicRulePlan, rules: DynamicRules) -> None:
        toggles: tuple[tuple[str, str, Any], ...] = (
            (
                "enable_penetration_detection",
                "Penetration detection",
                rules.enable_penetration_detection,
            ),
            ("enable_ip_banning", "IP banning", rules.enable_ip_banning),
            ("enable_rate_limiting", "Rate limiting", rules.enable_rate_limiting),
            (
                "enable_rate_limit_auto_ban",
                "Rate-limit auto-ban",
                rules.enable_rate_limit_auto_ban,
            ),
            ("auto_ban_threshold", "Auto-ban threshold", rules.auto_ban_threshold),
            ("auto_ban_duration", "Auto-ban duration", rules.auto_ban_duration),
        )
        for name, label, value in toggles:
            if value is None:
                continue
            plan.set(name, value)
            plan.note(f"Dynamic rule: {label} {value}")

    def _plan_emergency_mode(self, plan: DynamicRulePlan, rules: DynamicRules) -> None:
        if not rules.emergency_mode:
            return
        plan.set("emergency_mode", True)
        plan.set("emergency_whitelist", rules.emergency_whitelist)
        plan.emergency_whitelist = rules.emergency_whitelist
        threshold = cast(int, plan.state["auto_ban_threshold"])
        plan.set("auto_ban_threshold", max(1, threshold // 2))
        plan.note(
            "[EMERGENCY MODE] Reduced auto-ban threshold "
            f"from {threshold} to {plan.state['auto_ban_threshold']}",
            logging.WARNING,
        )
