import functools
import ipaddress
import logging
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, cast

from guard_core._security_config_batch import apply_config_batch, prepare_config_batch
from guard_core._security_config_field_validators import (
    canonicalize_cloud_provider_selector,
)
from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync._utils.detection_scan import _redact_pattern_source
from guard_core.sync.handlers._cloud_provider_registry import merge_cloud_selectors
from guard_core.sync.handlers._dynamic_rule_validation import (
    MalformedDynamicRules,
    find_malformed_values,
)
from guard_core.sync.handlers._ipban_bans import _LOOPBACK_NETWORKS


@dataclass
class DynamicRulePlan:
    state: dict[str, Any]
    skipped: list[str] = field(default_factory=list)
    messages: list[tuple[int, str]] = field(default_factory=list)
    emergency_whitelist: list[str] | None = None
    exempt_ips: list[str] = field(default_factory=list)
    validated: set[str] = field(default_factory=set)
    prepared: dict[str, Any] = field(default_factory=dict)

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


def _classify_exempt_entry(entry: str) -> tuple[str | None, str | None]:
    network = ipaddress.ip_network(entry, strict=False)
    if any(
        network.version == loopback.version and network.overlaps(loopback)
        for loopback in _LOOPBACK_NETWORKS
    ):
        return None, "loopback"
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address), None
    return str(network), None


def _covered_by(entry: str, networks: list[Any]) -> bool:
    target = ipaddress.ip_network(entry, strict=False)
    return any(
        target.version == network.version and target.subnet_of(network)
        for network in networks
    )


def _merge_unique(static: Iterable[str] | None, dynamic: Iterable[str]) -> list[str]:
    return list(dict.fromkeys([*(static or ()), *dynamic]))


class DynamicRulePlanMixin:
    config: SyncSecurityConfig
    logger: logging.Logger

    _SNAPSHOT_FIELDS = (
        "blocked_countries",
        "whitelist_countries",
        "rate_limit",
        "rate_limit_window",
        "endpoint_rate_limits",
        "block_cloud_providers",
        "blocked_user_agents",
        "enable_penetration_detection",
        "enable_ip_banning",
        "enable_rate_limiting",
        "emergency_mode",
        "emergency_whitelist",
        "emergency_whitelist_only",
        "exempt_ips",
        "auto_ban_threshold",
        "auto_ban_duration",
        "enable_rate_limit_auto_ban",
    )

    def _build_plan(
        self, rules: DynamicRules, base: dict[str, object]
    ) -> DynamicRulePlan:
        problems = find_malformed_values(rules)
        if problems:
            raise MalformedDynamicRules(problems)
        plan = DynamicRulePlan(state=dict(base))
        valid_user_agents = self._validate_user_agents(plan, rules)
        self._plan_countries(plan, rules)
        self._plan_cloud_providers(plan, rules)
        self._plan_user_agents(plan, valid_user_agents)
        self._plan_exempt_ips(plan, rules)
        self._plan_rate_limits(plan, rules)
        self._plan_feature_toggles(plan, rules)
        self._plan_emergency_mode(plan, rules)
        plan.prepared = prepare_config_batch(self.config, plan.state, plan.validated)
        return plan

    def _swap_config(self, plan: DynamicRulePlan) -> None:
        apply_config_batch(self.config, plan.prepared)

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
        self._plan_blocked_countries(plan, blocked)
        self._plan_allowed_countries(plan, allowed)

    def _plan_blocked_countries(
        self, plan: DynamicRulePlan, blocked: list[str]
    ) -> None:
        if not blocked:
            return
        normalized = [code.upper() for code in blocked]
        merged = _merge_unique(plan.state.get("blocked_countries"), normalized)
        plan.set("blocked_countries", frozenset(merged))
        plan.note(f"Dynamic rule: Blocked countries {sorted(set(normalized))}")

    def _plan_allowed_countries(
        self, plan: DynamicRulePlan, allowed: list[str]
    ) -> None:
        if not allowed:
            return
        normalized = [code.upper() for code in allowed]
        plan.set("whitelist_countries", frozenset(normalized))
        plan.note(f"Dynamic rule: Whitelisted countries {sorted(set(normalized))}")

    def _plan_cloud_providers(self, plan: DynamicRulePlan, rules: DynamicRules) -> None:
        providers = rules.blocked_cloud_providers
        if not providers:
            return
        valid = [
            name
            for name in map(canonicalize_cloud_provider_selector, providers)
            if name is not None
        ]
        merged = frozenset(
            merge_cloud_selectors(plan.state.get("block_cloud_providers"), valid)
        )
        plan.set("block_cloud_providers", merged)
        plan.note(f"Dynamic rule: Blocked cloud providers {merged}")

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
            for pattern, _reason in rejected:
                plan.skipped.append(
                    "blocked_user_agents: pattern "
                    f"{_redact_pattern_source(pattern)!r} failed the ReDoS validator"
                )
            plan.note(
                f"Dynamic rule: rejected blocked_user_agents patterns failing the "
                f"ReDoS validator: {_redact_rejected_patterns(rejected)}",
                logging.WARNING,
            )
        return valid

    def _plan_user_agents(
        self, plan: DynamicRulePlan, valid_user_agents: list[str] | None
    ) -> None:
        if not valid_user_agents:
            return
        merged = _merge_unique(plan.state.get("blocked_user_agents"), valid_user_agents)
        plan.set("blocked_user_agents", merged, validate=False)
        redacted = [_redact_pattern_source(p) for p in merged]
        plan.note(f"Dynamic rule: Blocked user agents {redacted}")

    def _plan_exempt_ips(self, plan: DynamicRulePlan, rules: DynamicRules) -> None:
        exempt: list[str] = []
        for entry in rules.ip_whitelist:
            canonical, problem = _classify_exempt_entry(entry)
            if canonical is None:
                plan.skip(
                    f"ip_whitelist: {entry} ({problem})",
                    f"Dynamic rule: skipped ip_whitelist entry {entry!r} ({problem})",
                )
            else:
                exempt.append(canonical)
        networks = [ipaddress.ip_network(entry) for entry in exempt]
        for entry in rules.ip_blacklist:
            if _covered_by(entry, networks):
                plan.skip(
                    f"ip_blacklist: {entry} (overridden by ip_whitelist)",
                    f"Dynamic rule: ip_blacklist entry {entry} is also in "
                    "ip_whitelist; the whitelist wins",
                )
        plan.exempt_ips = list(dict.fromkeys(exempt))
        if plan.exempt_ips:
            merged = _merge_unique(plan.state.get("exempt_ips"), plan.exempt_ips)
            plan.set("exempt_ips", tuple(merged), validate=False)
            plan.note(f"Dynamic rule: Exempt IPs {plan.exempt_ips}")

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
        plan.set("emergency_whitelist_only", rules.emergency_whitelist_only)
        plan.emergency_whitelist = rules.emergency_whitelist
        threshold = cast(int, plan.state["auto_ban_threshold"])
        plan.set("auto_ban_threshold", max(1, threshold // 2))
        plan.note(
            "[EMERGENCY MODE] Reduced auto-ban threshold "
            f"from {threshold} to {plan.state['auto_ban_threshold']}",
            logging.WARNING,
        )

    def _snapshot_config(self) -> dict[str, object]:
        return {
            name: deepcopy(getattr(self.config, name))
            for name in self._SNAPSHOT_FIELDS
            if hasattr(self.config, name)
        }

    def _restore_config(self, snapshot: dict[str, object]) -> None:
        apply_config_batch(self.config, deepcopy(snapshot))
