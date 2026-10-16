from typing import Any

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync._utils.detection_scan import _redact_pattern_source
from guard_core.sync.handlers._dynamic_rule_events import DynamicRuleEventSenderMixin


def _redact_pattern_list(patterns: list[str]) -> list[str]:
    return [_redact_pattern_source(pattern) for pattern in patterns]


class DynamicRuleApplicationMixin(DynamicRuleEventSenderMixin):
    config: SecurityConfig
    agent_handler: Any

    def _apply_side_effects(self, rules: DynamicRules) -> None:
        if rules.ip_blacklist:
            self._apply_ip_bans(rules.ip_blacklist, rules.ip_ban_duration)

        if rules.ip_whitelist:
            self._apply_ip_whitelist(rules.ip_whitelist)

        if rules.suspicious_patterns:
            self._apply_pattern_rules(rules.suspicious_patterns)

    def _apply_ip_bans(self, ip_list: list[str], duration: int) -> None:
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager

        for ip in ip_list:
            try:
                applied = ip_ban_manager.ban_ip(ip, duration, "dynamic_rule")
                if applied:
                    self.logger.info(f"Dynamic rule: Banned IP {ip} for {duration}s")
            except Exception as e:
                self.logger.error(f"Failed to ban IP {ip}: {e}")

    def _apply_ip_whitelist(self, ip_list: list[str]) -> None:
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager

        for ip in ip_list:
            try:
                ip_ban_manager.unban_ip(ip)
                self.logger.info(f"Dynamic rule: Whitelisted IP {ip}")
            except Exception as e:
                self.logger.error(f"Failed to whitelist IP {ip}: {e}")

    def _apply_pattern_rules(self, patterns: list[str]) -> None:
        from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

        known = set(sus_patterns_handler.patterns)
        patterns = [p for p in patterns if p not in known]
        added = [p for p in patterns if sus_patterns_handler.add_pattern(p)]
        if added:
            self.logger.info(
                f"Dynamic rule: Added suspicious patterns {_redact_pattern_list(added)}"
            )

        rejected = [p for p in patterns if p not in added]
        if rejected:
            self.logger.warning(
                f"Dynamic rule: rejected patterns {_redact_pattern_list(rejected)}"
            )

    def _announce_emergency_mode(self, whitelist: list[str]) -> None:
        self.logger.critical(
            "[EMERGENCY MODE] ACTIVATED - Enhanced security posture enabled"
        )
        if self.agent_handler:
            self._send_emergency_event(whitelist)
