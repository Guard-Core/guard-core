import logging
import threading
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import cast

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.app_managers import AppManagers as AppManagers
from guard_core.sync._utils.app_scope import (
    WeakableConfig,
    app_scope_of,
    forget_config,
    in_app_scope,
    release_config_to_app,
    serve_config_of_the_live_app,
)
from guard_core.sync._utils.nat64 import nat64_table_of
from guard_core.sync._utils.rule_attribution_shared import _APP_RULE_MANAGERS
from guard_core.sync._utils.whitelist_match import is_listed
from guard_core.sync.handlers._background_stop import (
    stop_before_redis_closes,
    stop_task_from_another_thread,
    stop_task_on_its_own_loop,
)
from guard_core.sync.handlers._dynamic_rule_application import (
    DynamicRuleApplicationMixin,
    RuleSideEffects,
)
from guard_core.sync.handlers._dynamic_rule_attribution import (
    RuleAttribution,
    build_rule_attribution,
)
from guard_core.sync.handlers._dynamic_rule_intake import DynamicRuleIntakeMixin
from guard_core.sync.handlers._dynamic_rule_plan import (
    DynamicRulePlan,
    DynamicRulePlanMixin,
)
from guard_core.sync.handlers._dynamic_rule_snapshot import DynamicRuleSnapshotMixin
from guard_core.sync.handlers.ipban_handler import IPBanManager, ip_ban_manager_for
from guard_core.sync.protocols.agent_protocol import (
    DynamicRulesProtocol,
    SyncAgentHandlerProtocol,
)
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol


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
    # A WeakableConfig descriptor; instances read a SecurityConfig through it.
    config: SyncSecurityConfig = cast("SyncSecurityConfig", WeakableConfig())
    agent_handler: SyncAgentHandlerProtocol | None = None
    redis_handler: SyncRedisHandlerProtocol | None = None
    bound_ban_manager: IPBanManager | None = None
    logger: logging.Logger
    last_update: float = 0
    current_rules: DynamicRulesProtocol | None = None
    update_task: threading.Thread | None = None
    _lock: threading.Lock
    _stop_event: threading.Event
    _active_base_snapshot: dict[str, object] | None = None
    _last_skipped_expired_rule: tuple[str, int] | None = None
    _last_ignored_platform_default: tuple[str, int] | None = None
    _last_rejected_rule: tuple[str, int, str] | None = None
    _hydrated_last_known_rules: bool = False
    _current_fingerprint: str | None = None
    _owned_bans: list[str]
    _owned_patterns: list[str]
    _restored_ownership: tuple[list[str], list[str]]
    _reverted_rules: DynamicRulesProtocol | None
    _attribution_cache: tuple[tuple[object, ...], RuleAttribution] | None = None
    _attribution_view: RuleAttribution | None = None

    def __new__(
        cls: type["DynamicRuleManager"], config: SyncSecurityConfig
    ) -> "DynamicRuleManager":
        own = _APP_RULE_MANAGERS.own(config)
        if own is not None:
            return own
        if cls._instance is None:
            cls._instance = cls._fresh(config)
        manager = _APP_RULE_MANAGERS.bind(
            config, cls._instance, lambda: cls._fresh(config)
        )
        if manager is cls._instance:
            serve_config_of_the_live_app(manager, config)
        return manager

    def use_ban_manager(self, manager: IPBanManager) -> None:
        """The ban manager this app was bound to, handed in by its initializer after
        the bind; never captured at construction, which can precede the bind."""
        self.bound_ban_manager = manager

    def ban_manager_of_the_app(self) -> IPBanManager:
        bound = self.bound_ban_manager
        return bound if bound is not None else ip_ban_manager_for(self.config)

    def forget_state_of_the_gone_app(self) -> None:
        """What the default manager of a finished app must not keep for the next
        one. It stops the update loop without awaiting it (from any thread; a loop
        that is closed or stopped is only dropped), withdraws the applied rule set
        from the app's config, and forgets the hydration, the ownership lists, the
        ban manager and the Redis and agent handlers and the config, so the next app
        hydrates and applies its own. Called only when the default is not shared
        by another app."""
        stop_task_from_another_thread(self.update_task, self._stop_event)
        self.update_task = None
        self._withdraw_the_applied_rules()
        self.current_rules = None
        self.last_update = 0
        self._hydrated_last_known_rules = False
        self._owned_bans = []
        self._owned_patterns = []
        self._restored_ownership = ([], [])
        self.bound_ban_manager = None
        for name in ("redis_handler", "agent_handler"):
            self.__dict__.pop(name, None)
        forget_config(self, "config")

    def _withdraw_the_applied_rules(self) -> None:
        if self.current_rules is None or self.config is None:
            return
        try:
            self._revert_to_base_config()
        except Exception as e:
            self.logger.error(f"Withdrawing the applied dynamic rules failed: {e}")

    @classmethod
    def _fresh(
        cls: type["DynamicRuleManager"], config: SyncSecurityConfig
    ) -> "DynamicRuleManager":
        instance = super().__new__(cls)
        instance.config = config
        instance.agent_handler = None
        instance.redis_handler = None
        instance.logger = logging.getLogger("guard_core.sync.handlers.dynamic_rule")
        instance.last_update = 0
        instance.current_rules = None
        instance.update_task = None
        instance._lock = threading.Lock()
        instance._stop_event = threading.Event()
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

    def initialize_agent(self, agent_handler: SyncAgentHandlerProtocol) -> None:
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

    def initialize_redis(self, redis_handler: SyncRedisHandlerProtocol) -> None:
        self.redis_handler = redis_handler
        stop_before_redis_closes(redis_handler, self._stop_update_loop)

    def _stop_update_loop(self) -> None:
        stop_task_on_its_own_loop(self.update_task)

    def _refresh_attribution(self, rules: DynamicRulesProtocol | None = None) -> None:
        """Build the attribution view of the applied set. Called wherever the
        rules, their owned bans or patterns or the base snapshot change, so a
        request never pays for it; the identity check keeps it from rebuilding
        a view whose inputs did not change."""
        rules = rules if rules is not None else self.current_rules
        if rules is None:
            self._attribution_cache = None
            self._attribution_view = None
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
                self._attribution_view = cached[1]
                return
        view = build_rule_attribution(
            rules,
            self.config,
            self._owned_bans,
            self._owned_patterns,
            self._active_base_snapshot or {},
        )
        self._attribution_cache = (inputs, view)
        self._attribution_view = view

    def match_event(self, event: object) -> tuple[str, int] | None:
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

    def _event_matches_ip(self, event: object, rules: DynamicRulesProtocol) -> bool:
        ip = getattr(event, "ip_address", None)
        if not ip:
            return False
        entries = [*(rules.ip_blacklist or []), *(rules.ip_whitelist or [])]
        try:
            return is_listed(
                ip_address(ip), ip, tuple(entries), "list", nat64_table_of(self.config)
            )
        except ValueError:
            return ip in entries

    def _event_matches_country(
        self, event: object, rules: DynamicRulesProtocol
    ) -> bool:
        country = getattr(event, "country", None)
        if not country:
            return False
        blocked = {str(code).upper() for code in rules.blocked_countries or []}
        return str(country).upper() in blocked

    def _event_matches_type(self, event: object, rules: DynamicRulesProtocol) -> bool:
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

    def _revert_to_base_config(self) -> None:
        self.ban_manager_of_the_app().set_rule_exempt_ips(())
        if self._active_base_snapshot is not None:
            self._restore_config(self._active_base_snapshot)
        self.current_rules = None
        self._current_fingerprint = None
        self._active_base_snapshot = None
        self._refresh_attribution()

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

    def _revoke_active_rules(self, answer: DynamicRulesProtocol) -> None:
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

    def _has_rule_expired(self, rules: DynamicRulesProtocol) -> bool:
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
        self, base: dict[str, object], plan: DynamicRulePlan
    ) -> None:
        if all(
            base.get(name) == plan.state.get(name)
            for name in self._BAN_THRESHOLD_LIMIT_FIELDS
        ):
            return
        from guard_core.sync.core.initialization._ban_threshold_report import (
            log_unreachable_ban_thresholds_after_rule_change,
        )

        try:
            log_unreachable_ban_thresholds_after_rule_change(self.config, self.logger)
        except Exception:
            self.logger.exception("Checking the ban thresholds after a rule failed")

    def _apply_rules(self, rules: DynamicRulesProtocol) -> list[str]:
        with self._lock:
            base = self._active_base_snapshot
            if base is None:
                base = self._snapshot_config()
            plan = self._build_plan(rules, base)
            effects = RuleSideEffects()
            ip_ban_manager = self.ban_manager_of_the_app()
            previous_exempt = ip_ban_manager.rule_exempt_networks
            try:
                ip_ban_manager.set_rule_exempt_ips(plan.exempt_ips)
                self._apply_side_effects(rules, effects, plan.exempt_ips)
                self._swap_config(plan)
            except Exception as e:
                ip_ban_manager.rule_exempt_networks = previous_exempt
                self._undo_side_effects(effects)
                self.logger.error(f"Failed to apply dynamic rules: {e}")
                raise
            self._active_base_snapshot = base
            self._log_unreachable_ban_thresholds_after_swap(base, plan)
            self._revoke_stale_side_effects(rules, effects)
            self._refresh_attribution(rules)
            self._announce_plan(plan)
            self._persist_last_known_rules(rules)
            return [*plan.skipped, *effects.skipped]

    def get_current_rules(self) -> DynamicRulesProtocol | None:
        return self.current_rules

    def force_update(self) -> None:
        with in_app_scope(app_scope_of(self.config)):
            self.update_rules()

    def stop(self) -> None:
        if self.update_task:
            self._stop_event.set()
            self.update_task.join(timeout=5)
            self.update_task = None
            self.logger.info("Stopped dynamic rule update loop")


dynamic_rule_manager = DynamicRuleManager


def dynamic_rule_manager_of_the_app(config: SyncSecurityConfig) -> DynamicRuleManager:
    """The manager an app's own initializer uses: the app owns the config, so a
    module-held manager must not keep it alive."""
    manager = DynamicRuleManager(config)
    release_config_to_app(manager, config)
    return manager
