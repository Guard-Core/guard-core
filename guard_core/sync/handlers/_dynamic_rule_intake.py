import logging
import time
from collections.abc import Callable
from typing import Any

from guard_core._dynamic_rules import content_fingerprint
from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.handlers._dynamic_rule_events import DynamicRuleEventSenderMixin
from guard_core.sync.handlers._dynamic_rule_purge import DynamicRulePurgeMixin
from guard_core.sync.handlers._dynamic_rule_validation import find_malformed_values


class DynamicRuleIntakeMixin(DynamicRuleEventSenderMixin, DynamicRulePurgeMixin):
    config: SecurityConfig
    agent_handler: Any
    logger: logging.Logger
    last_update: float
    current_rules: DynamicRules | None
    _current_fingerprint: str | None
    _last_skipped_expired_rule: tuple[str, int] | None
    _last_ignored_platform_default: tuple[str, int] | None
    _last_rejected_rule: tuple[str, int, str] | None
    _has_rule_expired: Callable[[DynamicRules], bool]
    _check_rule_expiry: Callable[[], None]
    _revoke_active_rules: Callable[[DynamicRules], None]
    _apply_rules: Callable[[DynamicRules], list[str]]

    def _should_update_rules(self, rules: DynamicRules) -> bool:
        current = self.current_rules
        if not current:
            return True

        current_fingerprint = self._current_fingerprint or content_fingerprint(current)
        return (rules.rule_id, rules.version, content_fingerprint(rules)) != (
            current.rule_id,
            current.version,
            current_fingerprint,
        )

    def _is_no_op_answer(self, rules: DynamicRules) -> bool:
        return getattr(rules, "version", None) == 0

    def _ignore_platform_default(self, rules: DynamicRules) -> bool:
        if getattr(rules, "is_platform_default", False) is not True:
            return False

        key = (rules.rule_id, rules.version)
        if self._last_ignored_platform_default != key:
            self._last_ignored_platform_default = key
            self.logger.warning(
                f"Dynamic rule {rules.rule_id} v{rules.version} is a platform "
                "default, not an operator rule; ignoring"
            )
        return True

    def _reject_if_already_expired(self, rules: DynamicRules) -> bool:
        if not self._has_rule_expired(rules):
            return False

        key = (rules.rule_id, rules.version)
        if self._last_skipped_expired_rule != key:
            self._last_skipped_expired_rule = key
            self.logger.warning(
                f"Dynamic rule {rules.rule_id} v{rules.version} already "
                "expired on receipt; ignoring"
            )
        return True

    def _reject_if_malformed(self, rules: DynamicRules) -> bool:
        problems = find_malformed_values(rules)
        if not problems:
            return False

        key = (rules.rule_id, rules.version, content_fingerprint(rules))
        if self._last_rejected_rule != key:
            self._last_rejected_rule = key
            self.logger.warning(
                f"Dynamic rule {rules.rule_id} v{rules.version} rejected, "
                f"keeping the last-known rules: {problems}"
            )
            self._send_rule_rejected_event(rules, problems)
        return True

    def update_rules(self) -> None:
        if not self.config.enable_dynamic_rules or not self.agent_handler:
            return

        try:
            self._check_rule_expiry()

            marker = self._read_marker_and_revert_if_purged()

            rules = self.agent_handler.get_dynamic_rules()
            if not self._has_applicable_answer(rules, marker):
                return

            if self._ignore_platform_default(rules):
                return

            if self._is_no_op_answer(rules):
                self._revoke_active_rules(rules)
                return

            if self._reject_if_already_expired(rules):
                return

            if self._reject_if_malformed(rules):
                return

            if not self._should_update_rules(rules):
                return

            self._send_rule_received_event(rules)

            self.logger.info(
                f"Applying dynamic rules: {rules.rule_id} v{rules.version}"
            )
            skipped = self._apply_rules(rules)

            self.current_rules = rules
            self._refresh_attribution()
            self._current_fingerprint = content_fingerprint(rules)
            self.last_update = time.time()

            self._send_rule_applied_event(rules, skipped)

        except Exception as e:
            self.logger.error(f"Failed to update dynamic rules: {e}")
