import logging
import time
from collections.abc import Callable

from guard_core._dynamic_rules import content_fingerprint
from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers._dynamic_rule_events import DynamicRuleEventSenderMixin
from guard_core.sync.handlers._dynamic_rule_purge import DynamicRulePurgeMixin
from guard_core.sync.handlers._dynamic_rule_validation import find_malformed_values
from guard_core.sync.protocols.agent_protocol import (
    DynamicRulesProtocol,
    SyncAgentHandlerProtocol,
)


class RunStopped(Exception):
    """The update loop run that fetched these rules was stopped (its app was
    released) before it applied them."""


class DynamicRuleIntakeMixin(DynamicRuleEventSenderMixin, DynamicRulePurgeMixin):
    config: SyncSecurityConfig
    agent_handler: SyncAgentHandlerProtocol | None
    logger: logging.Logger
    last_update: float
    current_rules: DynamicRulesProtocol | None
    _current_fingerprint: str | None
    _last_skipped_expired_rule: tuple[str, int] | None
    _last_ignored_platform_default: tuple[str, int] | None
    _last_rejected_rule: tuple[str, int, str] | None
    _has_rule_expired: Callable[[DynamicRulesProtocol], bool]
    _check_rule_expiry: Callable[[], None]
    _revoke_active_rules: Callable[[DynamicRulesProtocol], None]
    _apply_rules: Callable[[DynamicRulesProtocol], list[str]]
    _run_was_stopped: Callable[[], bool]

    def _should_update_rules(self, rules: DynamicRulesProtocol) -> bool:
        current = self.current_rules
        if not current:
            return True

        current_fingerprint = self._current_fingerprint or content_fingerprint(current)
        return (rules.rule_id, rules.version, content_fingerprint(rules)) != (
            current.rule_id,
            current.version,
            current_fingerprint,
        )

    def _is_no_op_answer(self, rules: DynamicRulesProtocol) -> bool:
        return getattr(rules, "version", None) == 0

    def _ignore_platform_default(self, rules: DynamicRulesProtocol) -> bool:
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

    def _reject_if_already_expired(self, rules: DynamicRulesProtocol) -> bool:
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

    def _reject_if_malformed(self, rules: DynamicRulesProtocol) -> bool:
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

            answer: DynamicRulesProtocol | None = self.agent_handler.get_dynamic_rules()
            rules = self._rules_that_apply(answer, marker)
            if rules is None:
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

            if self._run_was_stopped():
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

        except RunStopped:
            return
        except Exception as e:
            self.logger.error(f"Failed to update dynamic rules: {e}")
