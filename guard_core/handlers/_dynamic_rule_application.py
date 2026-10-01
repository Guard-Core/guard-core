from typing import Any

from guard_core._utils.detection_scan import _redact_pattern_source
from guard_core.handlers._dynamic_rule_events import DynamicRuleEventSenderMixin
from guard_core.models import VALID_CLOUD_PROVIDERS, DynamicRules, SecurityConfig


def _redact_pattern_list(patterns: list[str]) -> list[str]:
    return [_redact_pattern_source(pattern) for pattern in patterns]


def _redact_rejected_patterns(
    rejected: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    return [(_redact_pattern_source(pattern), reason) for pattern, reason in rejected]


class DynamicRuleApplicationMixin(DynamicRuleEventSenderMixin):
    config: SecurityConfig
    agent_handler: Any

    async def _apply_ip_rules(self, rules: DynamicRules) -> None:
        if rules.ip_blacklist:
            await self._apply_ip_bans(rules.ip_blacklist, rules.ip_ban_duration)

        if rules.ip_whitelist:
            await self._apply_ip_whitelist(rules.ip_whitelist)

    async def _apply_blocking_rules(self, rules: DynamicRules) -> None:
        if rules.blocked_countries or rules.whitelist_countries:
            await self._apply_country_rules(
                rules.blocked_countries, rules.whitelist_countries
            )

        if rules.blocked_cloud_providers:
            await self._apply_cloud_provider_rules(rules.blocked_cloud_providers)

        if rules.blocked_user_agents:
            await self._apply_user_agent_rules(rules.blocked_user_agents)

        if rules.suspicious_patterns:
            await self._apply_pattern_rules(rules.suspicious_patterns)

    async def _apply_ip_bans(self, ip_list: list[str], duration: int) -> None:
        from guard_core.handlers.ipban_handler import ip_ban_manager

        for ip in ip_list:
            try:
                applied = await ip_ban_manager.ban_ip(ip, duration, "dynamic_rule")
                if applied:
                    self.logger.info(f"Dynamic rule: Banned IP {ip} for {duration}s")
            except Exception as e:
                self.logger.error(f"Failed to ban IP {ip}: {e}")

    async def _apply_ip_whitelist(self, ip_list: list[str]) -> None:
        from guard_core.handlers.ipban_handler import ip_ban_manager

        for ip in ip_list:
            try:
                await ip_ban_manager.unban_ip(ip)
                self.logger.info(f"Dynamic rule: Whitelisted IP {ip}")
            except Exception as e:
                self.logger.error(f"Failed to whitelist IP {ip}: {e}")

    async def _apply_country_rules(
        self, blocked: list[str], allowed: list[str]
    ) -> None:
        if (
            (blocked or allowed)
            and self.config.geo_ip_handler is None
            and not self.config.ipinfo_token
        ):
            self.logger.warning(
                "Dynamic rule: country rules cannot take effect (blocked="
                f"{blocked}, allowed={allowed}); no geo_ip_handler or "
                "ipinfo_token is configured to resolve IPs to countries"
            )
            return

        if blocked:
            normalized_blocked = frozenset(c.upper() for c in blocked)
            self.config.blocked_countries = normalized_blocked
            self.logger.info(
                f"Dynamic rule: Blocked countries {sorted(normalized_blocked)}"
            )

        if allowed:
            normalized_allowed = frozenset(c.upper() for c in allowed)
            self.config.whitelist_countries = normalized_allowed
            self.logger.info(
                f"Dynamic rule: Whitelisted countries {sorted(normalized_allowed)}"
            )

    async def _apply_rate_limit_rules(self, rules: DynamicRules) -> None:
        if rules.global_rate_limit:
            self.config.rate_limit = rules.global_rate_limit
            if rules.global_rate_window:
                self.config.rate_limit_window = rules.global_rate_window
            message = f"Global rate limit {rules.global_rate_limit}"
            details = f"per {rules.global_rate_window}s"
            self.logger.info(f"Dynamic rule: {message} {details}")

        if rules.endpoint_rate_limits:
            self.config.endpoint_rate_limits = rules.endpoint_rate_limits.copy()
            self.logger.info(
                f"Dynamic rule: Applied endpoint-specific rate limits for "
                f"{len(rules.endpoint_rate_limits)} endpoints: "
                f"{list(rules.endpoint_rate_limits.keys())}"
            )

    async def _apply_cloud_provider_rules(self, providers: set[str]) -> None:
        valid = frozenset(
            p for p in providers if p.partition(":!")[0] in VALID_CLOUD_PROVIDERS
        )
        self.config.block_cloud_providers = valid
        invalid = providers - valid
        if invalid:
            self.logger.warning(
                f"Dynamic rule: ignored unknown cloud providers {sorted(invalid)}"
            )
        self.logger.info(f"Dynamic rule: Blocked cloud providers {valid}")

    async def _apply_user_agent_rules(self, user_agents: list[str]) -> None:
        from guard_core.detection_engine._validation_cache import (
            PatternValidationCache,
        )
        from guard_core.detection_engine.compiler import PatternCompiler
        from guard_core.utils import _MAX_USER_AGENT_MATCH_LENGTH

        cache_path = getattr(
            self.config, "detection_pattern_validation_cache_path", None
        )
        compiler = PatternCompiler(
            validation_cache=(
                PatternValidationCache(cache_path) if cache_path else None
            )
        )
        valid: list[str] = []
        rejected: list[tuple[str, str]] = []
        for pattern in user_agents:
            is_safe, reason = compiler.validate_pattern_safety(
                pattern, max_content_length=_MAX_USER_AGENT_MATCH_LENGTH
            )
            if is_safe:
                valid.append(pattern)
            else:
                rejected.append((pattern, reason))

        self.config._set_prevalidated("blocked_user_agents", valid)
        if rejected:
            self.logger.warning(
                f"Dynamic rule: rejected blocked_user_agents patterns failing the "
                f"ReDoS validator: {_redact_rejected_patterns(rejected)}"
            )
        self.logger.info(
            f"Dynamic rule: Blocked user agents {_redact_pattern_list(valid)}"
        )

    async def _apply_pattern_rules(self, patterns: list[str]) -> None:
        from guard_core.handlers.suspatterns_handler import sus_patterns_handler

        added = [p for p in patterns if await sus_patterns_handler.add_pattern(p)]
        if added:
            self.logger.info(
                f"Dynamic rule: Added suspicious patterns {_redact_pattern_list(added)}"
            )

        rejected = [p for p in patterns if p not in added]
        if rejected:
            self.logger.warning(
                f"Dynamic rule: rejected patterns {_redact_pattern_list(rejected)}"
            )

    async def _apply_feature_toggles(self, rules: DynamicRules) -> None:
        if rules.enable_penetration_detection is not None:
            self.config.enable_penetration_detection = (
                rules.enable_penetration_detection
            )
            details = f"Penetration detection {rules.enable_penetration_detection}"
            self.logger.info(f"Dynamic rule: {details}")

        if rules.enable_ip_banning is not None:
            self.config.enable_ip_banning = rules.enable_ip_banning
            self.logger.info(f"Dynamic rule: IP banning {rules.enable_ip_banning}")

        if rules.enable_rate_limiting is not None:
            self.config.enable_rate_limiting = rules.enable_rate_limiting
            self.logger.info(
                f"Dynamic rule: Rate limiting {rules.enable_rate_limiting}"
            )

        if rules.enable_rate_limit_auto_ban is not None:
            self.config.enable_rate_limit_auto_ban = rules.enable_rate_limit_auto_ban
            self.logger.info(
                f"Dynamic rule: Rate-limit auto-ban {rules.enable_rate_limit_auto_ban}"
            )

        if rules.auto_ban_threshold is not None:
            self.config.auto_ban_threshold = rules.auto_ban_threshold
            self.logger.info(
                f"Dynamic rule: Auto-ban threshold {rules.auto_ban_threshold}"
            )

        if rules.auto_ban_duration is not None:
            self.config.auto_ban_duration = rules.auto_ban_duration
            self.logger.info(
                f"Dynamic rule: Auto-ban duration {rules.auto_ban_duration}"
            )

    async def _activate_emergency_mode(self, emergency_whitelist: list[str]) -> None:
        self.logger.critical(
            "[EMERGENCY MODE] ACTIVATED - Enhanced security posture enabled"
        )

        self.config.emergency_mode = True
        self.config.emergency_whitelist = emergency_whitelist

        original_threshold = self.config.auto_ban_threshold
        self.config.auto_ban_threshold = max(1, original_threshold // 2)
        message = "Reduced auto-ban threshold"
        details = f"from {original_threshold} to {self.config.auto_ban_threshold}"
        self.logger.warning(f"[EMERGENCY MODE] {message} {details}")

        if self.agent_handler:
            await self._send_emergency_event(emergency_whitelist)
