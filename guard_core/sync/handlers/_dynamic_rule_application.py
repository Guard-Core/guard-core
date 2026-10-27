from collections.abc import Callable
from dataclasses import dataclass, field

from guard_core._emergency_exemptions import warn_unexempted_probe_paths
from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.pattern_source_redaction import (
    _redact_pattern_source_of_app,
)
from guard_core.sync.handlers._dynamic_rule_events import DynamicRuleEventSenderMixin
from guard_core.sync.handlers._dynamic_rule_plan import DynamicRulePlan
from guard_core.sync.handlers._ipban_rule_exempt import (
    DYNAMIC_RULE_BAN_REASON,
    rule_ban_target,
)
from guard_core.sync.handlers._ipban_rule_revoke import _LIFTED, REVOKE_REWRITTEN
from guard_core.sync.protocols.agent_protocol import (
    DynamicRulesProtocol,
    SyncAgentHandlerProtocol,
)


def _redact_pattern_list(patterns: list[str], config: SyncSecurityConfig) -> list[str]:
    return [_redact_pattern_source_of_app(pattern, config) for pattern in patterns]


@dataclass
class RuleSideEffects:
    created_bans: list[str] = field(default_factory=list)
    created_patterns: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


class DynamicRuleApplicationMixin(DynamicRuleEventSenderMixin):
    config: SyncSecurityConfig
    agent_handler: SyncAgentHandlerProtocol | None
    _owned_bans: list[str]
    _owned_patterns: list[str]
    _refresh_attribution: Callable[[], None]

    def _apply_side_effects(
        self,
        rules: DynamicRulesProtocol,
        effects: RuleSideEffects | None = None,
        exempt_ips: list[str] | None = None,
    ) -> None:
        effects = effects or RuleSideEffects()
        if rules.ip_blacklist:
            self._apply_ip_bans(
                rules.ip_blacklist,
                rules.ip_ban_duration,
                effects.created_bans,
                effects.skipped,
            )

        whitelist = rules.ip_whitelist if exempt_ips is None else exempt_ips
        if whitelist:
            self._apply_ip_whitelist(whitelist)

        if rules.suspicious_patterns:
            self._apply_pattern_rules(
                rules.suspicious_patterns, effects.created_patterns, effects.skipped
            )

    def _owned_after(
        self, listed: list[str], previously_owned: list[str], created: list[str]
    ) -> list[str]:
        kept = [entry for entry in dict.fromkeys(listed) if entry in previously_owned]
        return [*kept, *created]

    def _undo_side_effects(self, effects: RuleSideEffects) -> None:
        self._revoke_owned(effects.created_bans, effects.created_patterns)

    def _revoke_owned(self, bans: list[str], patterns: list[str]) -> None:
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for

        ip_ban_manager = ip_ban_manager_for(self.config)
        from guard_core.sync.handlers.suspatterns_handler import (
            sus_patterns_manager_for,
        )

        patterns_manager = sus_patterns_manager_for(self.config)
        revoked: list[tuple[str, int]] = []
        for ip in bans:
            try:
                outcome = ip_ban_manager.revoke_rule_ban(ip)
            except Exception as e:
                self.logger.error(f"Failed to revoke IP ban {ip}: {e}")
                continue
            revoked.append((ip, outcome))
            if outcome in _LIFTED:
                self.logger.info(f"Dynamic rule: Revoked IP ban {ip}")
            if outcome == REVOKE_REWRITTEN:
                self.logger.info(
                    f"Dynamic rule: IP ban {ip} left at the shorter ban it hid"
                )
            if outcome not in _LIFTED:
                self.logger.info(
                    f"Dynamic rule: IP ban {ip} left in place (gone, or a longer ban "
                    "replaced it)"
                )
        ip_ban_manager.settle_rule_revocations(revoked)

        for pattern in patterns:
            try:
                patterns_manager.remove_pattern(pattern)
                self.logger.info(
                    "Dynamic rule: Revoked suspicious pattern "
                    f"{_redact_pattern_source_of_app(pattern, self.config)}"
                )
            except Exception as e:
                self.logger.error(f"Failed to revoke suspicious pattern: {e}")

    def _apply_ip_bans(
        self,
        ip_list: list[str],
        duration: int,
        created: list[str] | None = None,
        skipped: list[str] | None = None,
    ) -> None:
        created = created if created is not None else []
        skipped = skipped if skipped is not None else []
        for ip in ip_list:
            try:
                self._ban_rule_ip(ip, duration, created, skipped)
            except Exception as e:
                self.logger.error(f"Failed to ban IP {ip}: {e}")

    def _ban_rule_ip(
        self,
        ip: str,
        duration: int,
        created: list[str],
        skipped: list[str],
    ) -> None:
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for

        ip_ban_manager = ip_ban_manager_for(self.config)

        canonical = rule_ban_target(ip)[1]
        takes_ownership = (
            canonical not in self._owned_bans
            and not ip_ban_manager.is_ip_banned(canonical)
        )
        if ip_ban_manager.ban_ip(ip, duration, DYNAMIC_RULE_BAN_REASON):
            self.logger.info(f"Dynamic rule: Banned IP {ip} for {duration}s")
            if takes_ownership and canonical not in created:
                created.append(canonical)
            return
        refusal = ip_ban_manager._self_dos_refusal_reason(canonical)
        if refusal is not None:
            skipped.append(f"ip_blacklist: {ip} (ban refused: {refusal})")

    def _apply_ip_whitelist(self, ip_list: list[str]) -> None:
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for

        ip_ban_manager = ip_ban_manager_for(self.config)

        ranges = [ip for ip in ip_list if "/" in ip]
        if ranges:
            try:
                ip_ban_manager.unban_inside(ranges)
                ip_ban_manager.forget_strikes_inside(ranges)
            except Exception as e:
                self.logger.error(f"Failed to whitelist ranges {ranges}: {e}")
        for ip in ip_list:
            try:
                if "/" not in ip:
                    ip_ban_manager.unban_ip(ip, reason="dynamic_rule_whitelist")
                self.logger.info(f"Dynamic rule: Whitelisted IP {ip}")
            except Exception as e:
                self.logger.error(f"Failed to whitelist IP {ip}: {e}")

    def _apply_pattern_rules(
        self,
        patterns: list[str],
        created: list[str] | None = None,
        skipped: list[str] | None = None,
    ) -> None:
        from guard_core.sync.handlers.suspatterns_handler import (
            sus_patterns_manager_for,
        )

        created = created if created is not None else []
        skipped = skipped if skipped is not None else []
        patterns_manager = sus_patterns_manager_for(self.config)
        known = set(patterns_manager.patterns)
        candidates = [p for p in dict.fromkeys(patterns) if p not in known]
        rejected: list[str] = []
        added: list[str] = []
        for pattern in candidates:
            if patterns_manager.add_pattern(pattern):
                created.append(pattern)
                added.append(pattern)
            else:
                rejected.append(pattern)
        if added:
            shown = _redact_pattern_list(added, self.config)
            self.logger.info(f"Dynamic rule: Added suspicious patterns {shown}")

        if rejected:
            skipped.extend(
                f"suspicious_patterns: pattern {pattern!r} rejected"
                for pattern in _redact_pattern_list(rejected, self.config)
            )
            redacted = _redact_pattern_list(rejected, self.config)
            self.logger.warning(f"Dynamic rule: rejected patterns {redacted}")

    def _announce_emergency_mode(self, whitelist: list[str]) -> None:
        self.logger.critical(
            "[EMERGENCY MODE] ACTIVATED - Enhanced security posture enabled"
        )
        warn_unexempted_probe_paths(self.config, self.logger)
        if self.agent_handler:
            self._send_emergency_event(whitelist)

    def _revoke_stale_side_effects(
        self, rules: DynamicRulesProtocol, effects: RuleSideEffects
    ) -> None:
        listed = [rule_ban_target(ip)[1] for ip in rules.ip_blacklist]
        previous = [rule_ban_target(ip)[1] for ip in self._owned_bans]
        bans = self._owned_after(listed, previous, effects.created_bans)
        patterns = self._owned_after(
            rules.suspicious_patterns, self._owned_patterns, effects.created_patterns
        )
        stale_bans = self._stale_rule_bans(set(listed))
        stale_patterns = [p for p in self._owned_patterns if p not in patterns]
        self._owned_bans, self._owned_patterns = bans, patterns
        self._revoke_owned(stale_bans, stale_patterns)

    def _stale_rule_bans(self, listed: set[str]) -> list[str]:
        """The bans a rule owns, here or in Redis (a worker that restarted or
        never applied the earlier set owns nothing locally), that the new set
        does not list."""
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for

        ip_ban_manager = ip_ban_manager_for(self.config)

        owned = [rule_ban_target(ip)[1] for ip in self._owned_bans]
        try:
            owned.extend(ip_ban_manager.owned_rule_ban_targets())
        except Exception as e:
            self.logger.error(f"Failed to list the bans a dynamic rule owns: {e}")
        return [ip for ip in dict.fromkeys(owned) if ip not in listed]

    def _revoke_all_owned(self) -> None:
        stale_bans = self._stale_rule_bans(set())
        patterns = self._owned_patterns
        self._owned_bans, self._owned_patterns = [], []
        self._refresh_attribution()
        self._revoke_owned(stale_bans, patterns)

    def _announce_plan(self, plan: DynamicRulePlan) -> None:
        for level, message in plan.messages:
            self.logger.log(level, message)
        if plan.emergency_whitelist is not None:
            self._announce_emergency_mode(plan.emergency_whitelist)
