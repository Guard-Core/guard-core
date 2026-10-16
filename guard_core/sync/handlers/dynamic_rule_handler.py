import logging
import threading
import time
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from guard_core._dynamic_rules import content_fingerprint
from guard_core.models import (
    DynamicRules,
    SecurityConfig,
)
from guard_core.sync.handlers._dynamic_rule_application import (
    DynamicRuleApplicationMixin,
    RuleSideEffects,
)
from guard_core.sync.handlers._dynamic_rule_plan import (
    DynamicRulePlan,
    DynamicRulePlanMixin,
)
from guard_core.sync.handlers._dynamic_rule_snapshot import DynamicRuleSnapshotMixin
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.utils import _canonicalize_ip


def _coerce_naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class DynamicRuleManager(
    DynamicRulePlanMixin, DynamicRuleApplicationMixin, DynamicRuleSnapshotMixin
):
    _instance = None
    config: SecurityConfig
    agent_handler: Any = None
    redis_handler: Any = None
    logger: logging.Logger
    last_update: float = 0
    current_rules: DynamicRules | None = None
    update_task: threading.Thread | None = None
    _lock: threading.Lock
    _stop_event: threading.Event
    _active_base_snapshot: dict[str, object] | None = None
    _last_skipped_expired_rule: tuple[str, int] | None = None
    _last_ignored_platform_default: tuple[str, int] | None = None
    _hydrated_last_known_rules: bool = False
    _current_fingerprint: str | None = None
    _owned_bans: list[str]
    _owned_patterns: list[str]

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
        "exempt_ips",
        "auto_ban_threshold",
        "auto_ban_duration",
        "enable_rate_limit_auto_ban",
    )

    def __new__(
        cls: type["DynamicRuleManager"], config: SecurityConfig
    ) -> "DynamicRuleManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.config = config
            cls._instance.agent_handler = None
            cls._instance.redis_handler = None
            cls._instance.logger = logging.getLogger(
                "guard_core.sync.handlers.dynamic_rule"
            )
            cls._instance.last_update = 0
            cls._instance.current_rules = None
            cls._instance.update_task = None
            cls._instance._lock = threading.Lock()
            cls._instance._stop_event = threading.Event()
            cls._instance._active_base_snapshot = None
            cls._instance._last_skipped_expired_rule = None
            cls._instance._last_ignored_platform_default = None
            cls._instance._hydrated_last_known_rules = False
            cls._instance._current_fingerprint = None
            cls._instance._owned_bans = []
            cls._instance._owned_patterns = []
        return cls._instance

    def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

        if self.config.enable_dynamic_rules:
            if not self._hydrated_last_known_rules:
                self._hydrated_last_known_rules = True
                self._hydrate_last_known_rules()
            if not self.update_task:
                self._stop_event.clear()
                self.update_task = threading.Thread(
                    target=self._rule_update_loop, daemon=True
                )
                self.update_task.start()
                self.logger.info("Started dynamic rule update loop")

    def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler

    def match_event(self, event: Any) -> tuple[str, int] | None:
        rules = self.current_rules
        if rules is None:
            return None
        if (
            self._event_matches_ip(event, rules)
            or self._event_matches_country(event, rules)
            or self._event_matches_type(event, rules)
        ):
            return rules.rule_id, rules.version
        return None

    def _event_matches_ip(self, event: Any, rules: DynamicRules) -> bool:
        ip = getattr(event, "ip_address", None)
        if not ip:
            return False
        return ip in (rules.ip_blacklist or []) or ip in (rules.ip_whitelist or [])

    def _event_matches_country(self, event: Any, rules: DynamicRules) -> bool:
        country = getattr(event, "country", None)
        return bool(country and country in (rules.blocked_countries or []))

    def _event_matches_type(self, event: Any, rules: DynamicRules) -> bool:
        event_type = getattr(event, "event_type", None)
        if event_type == "rate_limited":
            return rules.global_rate_limit is not None or bool(
                rules.endpoint_rate_limits
            )
        if event_type == "cloud_blocked":
            return bool(rules.blocked_cloud_providers)
        if event_type == "user_agent_blocked":
            return bool(rules.blocked_user_agents)
        return False

    def _rule_update_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.update_rules()
                self._interruptible_sleep(self.config.dynamic_rule_interval)
            except Exception as e:
                self.logger.error(f"Error in dynamic rule update loop: {e}")
                self._interruptible_sleep(min(60, self.config.dynamic_rule_interval))

    def _interruptible_sleep(self, timeout: float) -> None:
        self._stop_event.wait(timeout=timeout)

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

    def _revert_to_base_config(self) -> None:
        ip_ban_manager.set_rule_exempt_ips(())
        if self._active_base_snapshot is not None:
            self._restore_config(self._active_base_snapshot)
        self.current_rules = None
        self._current_fingerprint = None
        self._active_base_snapshot = None

    def _check_rule_expiry(self) -> None:
        with self._lock:
            rules = self.current_rules
            if rules is None or rules.expires_at is None:
                return
            if datetime.now(timezone.utc) <= _coerce_naive_utc(rules.expires_at):
                return

            self._revert_to_base_config()
            self._revoke_all_owned()
            self.logger.info(
                f"Dynamic rule {rules.rule_id} v{rules.version} expired; "
                "restored base config"
            )

    def _is_no_op_answer(self, rules: DynamicRules) -> bool:
        return getattr(rules, "version", None) == 0

    def _revoke_active_rules(self, answer: DynamicRules) -> None:
        with self._lock:
            rules = self.current_rules
            if rules is None:
                return
            self._revert_to_base_config()
            self._revoke_all_owned()
            self._clear_last_known_rules()
            self.logger.info(
                f"Dynamic rule {rules.rule_id} v{rules.version} revoked by the "
                f"version-0 answer {answer.rule_id}; restored base config"
            )

    def _has_rule_expired(self, rules: DynamicRules) -> bool:
        if rules.expires_at is None:
            return False
        return datetime.now(timezone.utc) > _coerce_naive_utc(rules.expires_at)

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

    def update_rules(self) -> None:
        if not self.config.enable_dynamic_rules or not self.agent_handler:
            return

        try:
            self._check_rule_expiry()

            rules = self.agent_handler.get_dynamic_rules()
            if not rules:
                return

            if self._ignore_platform_default(rules):
                return

            if self._is_no_op_answer(rules):
                self._revoke_active_rules(rules)
                return

            if self._reject_if_already_expired(rules):
                return

            if not self._should_update_rules(rules):
                return

            self._send_rule_received_event(rules)

            self.logger.info(
                f"Applying dynamic rules: {rules.rule_id} v{rules.version}"
            )
            skipped = self._apply_rules(rules)

            self.current_rules = rules
            self._current_fingerprint = content_fingerprint(rules)
            self.last_update = time.time()

            self._send_rule_applied_event(rules, skipped)

        except Exception as e:
            self.logger.error(f"Failed to update dynamic rules: {e}")

    def _snapshot_config(self) -> dict[str, object]:
        return {
            field: deepcopy(getattr(self.config, field))
            for field in self._SNAPSHOT_FIELDS
            if hasattr(self.config, field)
        }

    def _restore_config(self, snapshot: dict[str, object]) -> None:
        for field, value in snapshot.items():
            self.config._set_prevalidated(field, deepcopy(value))

    def _apply_rules(self, rules: DynamicRules) -> list[str]:
        with self._lock:
            base = self._active_base_snapshot
            if base is None:
                base = self._snapshot_config()
            plan = self._build_plan(rules, base)
            effects = RuleSideEffects()
            previous_exempt = ip_ban_manager.rule_exempt_networks
            try:
                ip_ban_manager.set_rule_exempt_ips(plan.exempt_ips)
                self._apply_side_effects(rules, effects, plan.exempt_ips)
                self._swap_config_or_restore(plan)
            except Exception:
                ip_ban_manager.rule_exempt_networks = previous_exempt
                self._undo_side_effects(effects)
                raise
            self._active_base_snapshot = base
            self._revoke_stale_side_effects(rules, effects)
            self._announce_plan(plan)
            self._persist_last_known_rules(rules)
            return plan.skipped

    def _revoke_stale_side_effects(
        self, rules: DynamicRules, effects: RuleSideEffects
    ) -> None:
        bans = self._owned_after(
            [_canonicalize_ip(ip) for ip in rules.ip_blacklist],
            self._owned_bans,
            effects.created_bans,
        )
        patterns = self._owned_after(
            rules.suspicious_patterns, self._owned_patterns, effects.created_patterns
        )
        stale_bans = [ip for ip in self._owned_bans if ip not in bans]
        stale_patterns = [p for p in self._owned_patterns if p not in patterns]
        self._owned_bans, self._owned_patterns = bans, patterns
        self._revoke_owned(stale_bans, stale_patterns)

    def _revoke_all_owned(self) -> None:
        bans, patterns = self._owned_bans, self._owned_patterns
        self._owned_bans, self._owned_patterns = [], []
        self._revoke_owned(bans, patterns)

    def _swap_config_or_restore(self, plan: DynamicRulePlan) -> None:
        previous = self._snapshot_config()
        try:
            self._swap_config(plan)
        except Exception as e:
            self._restore_config(previous)
            self.logger.error(f"Failed to apply dynamic rules: {e}")
            raise

    def _announce_plan(self, plan: DynamicRulePlan) -> None:
        for level, message in plan.messages:
            self.logger.log(level, message)
        if plan.emergency_whitelist is not None:
            self._announce_emergency_mode(plan.emergency_whitelist)

    def get_current_rules(self) -> DynamicRules | None:
        return self.current_rules

    def force_update(self) -> None:
        self.update_rules()

    def stop(self) -> None:
        if self.update_task:
            self._stop_event.set()
            self.update_task.join(timeout=5)
            self.update_task = None
            self.logger.info("Stopped dynamic rule update loop")


dynamic_rule_manager = DynamicRuleManager
