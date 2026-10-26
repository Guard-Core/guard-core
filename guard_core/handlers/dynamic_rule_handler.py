import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from guard_core._utils.app_managers import AppManagers
from guard_core._utils.app_scope import app_scope_of, in_app_scope
from guard_core._utils.rule_attribution import set_attribution_view
from guard_core.handlers._dynamic_rule_application import (
    DynamicRuleApplicationMixin,
    RuleSideEffects,
)
from guard_core.handlers._dynamic_rule_attribution import (
    RuleAttribution,
    build_rule_attribution,
)
from guard_core.handlers._dynamic_rule_intake import DynamicRuleIntakeMixin
from guard_core.handlers._dynamic_rule_plan import (
    DynamicRulePlanMixin,
)
from guard_core.handlers._dynamic_rule_snapshot import DynamicRuleSnapshotMixin
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.models import (
    DynamicRules,
    SecurityConfig,
)


def _coerce_naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


_APP_RULE_MANAGERS: AppManagers["DynamicRuleManager"] = AppManagers("dynamic_rules")


class DynamicRuleManager(
    DynamicRuleIntakeMixin,
    DynamicRulePlanMixin,
    DynamicRuleApplicationMixin,
    DynamicRuleSnapshotMixin,
):
    _instance = None
    config: SecurityConfig
    agent_handler: Any = None
    redis_handler: Any = None
    logger: logging.Logger
    last_update: float = 0
    current_rules: DynamicRules | None = None
    update_task: asyncio.Task | None = None
    _lock: asyncio.Lock
    _stop_event: asyncio.Event
    _active_base_snapshot: dict[str, object] | None = None
    _last_skipped_expired_rule: tuple[str, int] | None = None
    _last_ignored_platform_default: tuple[str, int] | None = None
    _last_rejected_rule: tuple[str, int, str] | None = None
    _hydrated_last_known_rules: bool = False
    _current_fingerprint: str | None = None
    _owned_bans: list[str]
    _owned_patterns: list[str]
    _restored_ownership: tuple[list[str], list[str]]
    _reverted_rules: DynamicRules | None
    _attribution_cache: tuple[tuple[object, ...], RuleAttribution] | None = None

    def __new__(
        cls: type["DynamicRuleManager"], config: SecurityConfig
    ) -> "DynamicRuleManager":
        own = _APP_RULE_MANAGERS.own(config)
        if own is not None:
            return own
        if cls._instance is None:
            cls._instance = cls._fresh(config)
        return _APP_RULE_MANAGERS.bind(
            config, cls._instance, lambda: cls._fresh(config)
        )

    @classmethod
    def _fresh(
        cls: type["DynamicRuleManager"], config: SecurityConfig
    ) -> "DynamicRuleManager":
        instance = super().__new__(cls)
        instance.config = config
        instance.agent_handler = None
        instance.redis_handler = None
        instance.logger = logging.getLogger("guard_core.handlers.dynamic_rule")
        instance.last_update = 0
        instance.current_rules = None
        instance.update_task = None
        instance._lock = asyncio.Lock()
        instance._stop_event = asyncio.Event()
        instance._active_base_snapshot = None
        instance._last_skipped_expired_rule = None
        instance._last_ignored_platform_default = None
        instance._last_rejected_rule = None
        instance._hydrated_last_known_rules = False
        instance._current_fingerprint = None
        instance._owned_bans = []
        instance._owned_patterns = []
        instance._restored_ownership = ([], [])
        instance._reverted_rules = None
        return instance

    async def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

        if self.config.enable_dynamic_rules:
            if not self._hydrated_last_known_rules:
                self._hydrated_last_known_rules = True
                await self._hydrate_last_known_rules()
            if not self.update_task:
                self._stop_event.clear()
                self.update_task = asyncio.create_task(self._rule_update_loop())
                self.logger.info("Started dynamic rule update loop")

    async def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler

    def _refresh_attribution(self, rules: DynamicRules | None = None) -> None:
        """Build the attribution view of the applied set. Called wherever the
        rules, their owned bans or patterns or the base snapshot change, so a
        request never pays for it; the identity check keeps it from rebuilding
        a view whose inputs did not change."""
        rules = rules if rules is not None else self.current_rules
        if rules is None:
            self._attribution_cache = None
            set_attribution_view(None)
            return
        inputs = (
            rules,
            self._owned_bans,
            self._owned_patterns,
            self._active_base_snapshot,
        )
        cached = self._attribution_cache
        if cached is not None:
            held = cached[0]
            if (
                held[0] is inputs[0]
                and held[1] is inputs[1]
                and held[2] is inputs[2]
                and held[3] is inputs[3]
            ):
                set_attribution_view(cached[1])
                return
        view = build_rule_attribution(
            rules,
            self.config,
            self._owned_bans,
            self._owned_patterns,
            self._active_base_snapshot or {},
        )
        self._attribution_cache = (inputs, view)
        set_attribution_view(view)

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

    async def _rule_update_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                await self.update_rules()
                await self._interruptible_sleep(self.config.dynamic_rule_interval)
            except asyncio.CancelledError:
                self.logger.info("Dynamic rule update loop cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error in dynamic rule update loop: {e}")
                await self._interruptible_sleep(
                    min(60, self.config.dynamic_rule_interval)
                )

    async def _interruptible_sleep(self, timeout: float) -> None:
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass

    def _revert_to_base_config(self) -> None:
        ip_ban_manager_for(self.config).set_rule_exempt_ips(())
        if self._active_base_snapshot is not None:
            self._restore_config(self._active_base_snapshot)
        self.current_rules = None
        self._current_fingerprint = None
        self._active_base_snapshot = None
        self._refresh_attribution()

    async def _check_rule_expiry(self) -> None:
        async with self._lock:
            rules = self.current_rules
            if rules is None or rules.expires_at is None:
                return
            if datetime.now(timezone.utc) <= _coerce_naive_utc(rules.expires_at):
                return

            self._revert_to_base_config()
            await self._revoke_all_owned()
            self.logger.info(
                f"Dynamic rule {rules.rule_id} v{rules.version} expired; "
                "restored base config"
            )

    async def _revoke_active_rules(self, answer: DynamicRules) -> None:
        async with self._lock:
            rules = self.current_rules
            if rules is None:
                return
            self._revert_to_base_config()
            await self._revoke_all_owned()
            await self._clear_last_known_rules()
            self.logger.info(
                f"Dynamic rule {rules.rule_id} v{rules.version} revoked by the "
                f"version-0 answer {answer.rule_id}; restored base config"
            )

    def _has_rule_expired(self, rules: DynamicRules) -> bool:
        if rules.expires_at is None:
            return False
        return datetime.now(timezone.utc) > _coerce_naive_utc(rules.expires_at)

    _BAN_THRESHOLD_LIMIT_FIELDS = (
        "auto_ban_threshold",
        "rate_limit",
        "rate_limit_window",
        "enable_rate_limiting",
        "exempt_ips",
    )

    def _log_unreachable_ban_thresholds_after_swap(
        self, base: dict[str, object], plan: Any
    ) -> None:
        if all(
            base.get(name) == plan.state.get(name)
            for name in self._BAN_THRESHOLD_LIMIT_FIELDS
        ):
            return
        from guard_core.core.initialization._ban_threshold_report import (
            log_unreachable_ban_thresholds_after_rule_change,
        )

        try:
            log_unreachable_ban_thresholds_after_rule_change(self.config, self.logger)
        except Exception:
            self.logger.exception("Checking the ban thresholds after a rule failed")

    async def _apply_rules(self, rules: DynamicRules) -> list[str]:
        async with self._lock:
            base = self._active_base_snapshot
            if base is None:
                base = self._snapshot_config()
            plan = await self._build_plan(rules, base)
            effects = RuleSideEffects()
            ip_ban_manager = ip_ban_manager_for(self.config)
            previous_exempt = ip_ban_manager.rule_exempt_networks
            try:
                ip_ban_manager.set_rule_exempt_ips(plan.exempt_ips)
                await self._apply_side_effects(rules, effects, plan.exempt_ips)
                self._swap_config(plan)
            except Exception as e:
                ip_ban_manager.rule_exempt_networks = previous_exempt
                await self._undo_side_effects(effects)
                self.logger.error(f"Failed to apply dynamic rules: {e}")
                raise
            self._active_base_snapshot = base
            self._log_unreachable_ban_thresholds_after_swap(base, plan)
            await self._revoke_stale_side_effects(rules, effects)
            self._refresh_attribution(rules)
            await self._announce_plan(plan)
            await self._persist_last_known_rules(rules)
            return [*plan.skipped, *effects.skipped]

    async def get_current_rules(self) -> DynamicRules | None:
        return self.current_rules

    async def force_update(self) -> None:
        with in_app_scope(app_scope_of(self.config)):
            await self.update_rules()

    async def stop(self) -> None:
        if self.update_task:
            self._stop_event.set()
            self.update_task.cancel()
            try:
                await self.update_task
            except asyncio.CancelledError:
                pass
            self.update_task = None
            self.logger.info("Stopped dynamic rule update loop")


dynamic_rule_manager = DynamicRuleManager
