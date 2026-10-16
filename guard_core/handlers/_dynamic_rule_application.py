from typing import Any

from guard_core._utils.detection_scan import _redact_pattern_source
from guard_core.handlers._dynamic_rule_events import DynamicRuleEventSenderMixin
from guard_core.models import DynamicRules, SecurityConfig


def _redact_pattern_list(patterns: list[str]) -> list[str]:
    return [_redact_pattern_source(pattern) for pattern in patterns]


class DynamicRuleApplicationMixin(DynamicRuleEventSenderMixin):
    config: SecurityConfig
    agent_handler: Any

    async def _apply_side_effects(self, rules: DynamicRules) -> None:
        if rules.ip_blacklist:
            await self._apply_ip_bans(rules.ip_blacklist, rules.ip_ban_duration)

        if rules.ip_whitelist:
            await self._apply_ip_whitelist(rules.ip_whitelist)

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

    async def _apply_pattern_rules(self, patterns: list[str]) -> None:
        from guard_core.handlers.suspatterns_handler import sus_patterns_handler

        known = set(sus_patterns_handler.patterns)
        patterns = [p for p in patterns if p not in known]
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

    async def _announce_emergency_mode(self, whitelist: list[str]) -> None:
        self.logger.critical(
            "[EMERGENCY MODE] ACTIVATED - Enhanced security posture enabled"
        )
        if self.agent_handler:
            await self._send_emergency_event(whitelist)
