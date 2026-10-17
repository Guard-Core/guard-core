import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from guard_core.handlers._dynamic_rule_application import (
    DynamicRuleApplicationMixin,
    RuleSideEffects,
)
from guard_core.handlers._dynamic_rule_intake import DynamicRuleIntakeMixin
from guard_core.handlers._dynamic_rule_plan import (
    DynamicRulePlanMixin,
)
from guard_core.handlers._dynamic_rule_snapshot import DynamicRuleSnapshotMixin
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.models import (
    DynamicRules,
    SecurityConfig,
)


def _coerce_naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


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

    def __new__(
        cls: type["DynamicRuleManager"], config: SecurityConfig
    ) -> "DynamicRuleManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.config = config
            cls._instance.agent_handler = None
            cls._instance.redis_handler = None
            cls._instance.logger = logging.getLogger("guard_core.handlers.dynamic_rule")
            cls._instance.last_update = 0
            cls._instance.current_rules = None
            cls._instance.update_task = None
            cls._instance._lock = asyncio.Lock()
            cls._instance._stop_event = asyncio.Event()
            cls._instance._active_base_snapshot = None
            cls._instance._last_skipped_expired_rule = None
            cls._instance._last_ignored_platform_default = None
            cls._instance._last_rejected_rule = None
            cls._instance._hydrated_last_known_rules = False
            cls._instance._current_fingerprint = None
            cls._instance._owned_bans = []
            cls._instance._owned_patterns = []
            cls._instance._restored_ownership = ([], [])
        return cls._instance

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
        ip_ban_manager.set_rule_exempt_ips(())
        if self._active_base_snapshot is not None:
            self._restore_config(self._active_base_snapshot)
        self.current_rules = None
        self._current_fingerprint = None
        self._active_base_snapshot = None

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

    async def _apply_rules(self, rules: DynamicRules) -> list[str]:
        async with self._lock:
            base = self._active_base_snapshot
            if base is None:
                base = self._snapshot_config()
            plan = await self._build_plan(rules, base)
            effects = RuleSideEffects()
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
            await self._revoke_stale_side_effects(rules, effects)
            await self._announce_plan(plan)
            await self._persist_last_known_rules(rules)
            return [*plan.skipped, *effects.skipped]

    async def get_current_rules(self) -> DynamicRules | None:
        return self.current_rules

    async def force_update(self) -> None:
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
