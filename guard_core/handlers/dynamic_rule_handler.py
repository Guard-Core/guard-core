import asyncio
import logging
import time
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from guard_core.handlers._dynamic_rule_application import DynamicRuleApplicationMixin
from guard_core.handlers._dynamic_rule_snapshot import DynamicRuleSnapshotMixin
from guard_core.models import (
    DynamicRules,
    SecurityConfig,
)


def _coerce_naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class DynamicRuleManager(DynamicRuleApplicationMixin, DynamicRuleSnapshotMixin):
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
    _hydrated_last_known_rules: bool = False

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
            cls._instance.logger = logging.getLogger("guard_core.handlers.dynamic_rule")
            cls._instance.last_update = 0
            cls._instance.current_rules = None
            cls._instance.update_task = None
            cls._instance._lock = asyncio.Lock()
            cls._instance._stop_event = asyncio.Event()
            cls._instance._active_base_snapshot = None
            cls._instance._last_skipped_expired_rule = None
            cls._instance._hydrated_last_known_rules = False
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

    def _should_update_rules(self, rules: DynamicRules) -> bool:
        if not self.current_rules:
            return True

        return not (
            rules.rule_id == self.current_rules.rule_id
            and rules.version <= self.current_rules.version
        )

    async def _check_rule_expiry(self) -> None:
        async with self._lock:
            rules = self.current_rules
            if rules is None or rules.expires_at is None:
                return
            if datetime.now(timezone.utc) <= _coerce_naive_utc(rules.expires_at):
                return

            if self._active_base_snapshot is not None:
                self._restore_config(self._active_base_snapshot)
            self.current_rules = None
            self._active_base_snapshot = None
            self.logger.info(
                f"Dynamic rule {rules.rule_id} v{rules.version} expired; "
                "restored base config"
            )

    def _has_rule_expired(self, rules: DynamicRules) -> bool:
        if rules.expires_at is None:
            return False
        return datetime.now(timezone.utc) > _coerce_naive_utc(rules.expires_at)

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

    async def update_rules(self) -> None:
        if not self.config.enable_dynamic_rules or not self.agent_handler:
            return

        try:
            await self._check_rule_expiry()

            rules = await self.agent_handler.get_dynamic_rules()
            if not rules:
                return

            if self._reject_if_already_expired(rules):
                return

            if not self._should_update_rules(rules):
                return

            await self._send_rule_received_event(rules)

            self.logger.info(
                f"Applying dynamic rules: {rules.rule_id} v{rules.version}"
            )
            await self._apply_rules(rules)

            self.current_rules = rules
            self.last_update = time.time()

            await self._send_rule_applied_event(rules)

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

    def _capture_active_base_snapshot(self, snapshot: dict[str, object]) -> None:
        if self.current_rules is None and self._active_base_snapshot is None:
            self._active_base_snapshot = snapshot

    async def _apply_rules(self, rules: DynamicRules) -> None:
        async with self._lock:
            previous = self._snapshot_config()
            if self._active_base_snapshot is not None:
                self._restore_config(self._active_base_snapshot)
            snapshot = self._snapshot_config()
            try:
                await self._apply_ip_rules(rules)

                await self._apply_blocking_rules(rules)

                if rules.global_rate_limit or rules.endpoint_rate_limits:
                    await self._apply_rate_limit_rules(rules)

                await self._apply_feature_toggles(rules)

                if rules.emergency_mode:
                    await self._activate_emergency_mode(rules.emergency_whitelist)

            except Exception as e:
                self._restore_config(previous)
                self.logger.error(f"Failed to apply dynamic rules: {e}")
                raise

            self._capture_active_base_snapshot(snapshot)

            await self._persist_last_known_rules(rules)

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
