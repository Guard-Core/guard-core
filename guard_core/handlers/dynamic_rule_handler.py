import asyncio
import logging
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import cast

from guard_core._utils.app_managers import AppManagers as AppManagers
from guard_core._utils.app_scope import (
    WeakableConfig,
    app_scope_of,
    forget_config,
    in_app_scope,
    release_config_to_app,
    serve_config_of_the_live_app,
)
from guard_core._utils.nat64 import nat64_table_of
from guard_core._utils.pending_rule_base import record_pending_rule_base
from guard_core._utils.rule_attribution_shared import _APP_RULE_MANAGERS
from guard_core._utils.whitelist_match import is_listed
from guard_core.handlers._background_stop import (
    background_task_is_live,
    stop_before_redis_closes,
    stop_task_from_another_thread,
    stop_task_on_its_own_loop,
)
from guard_core.handlers._dynamic_rule_application import (
    DynamicRuleApplicationMixin,
    RuleSideEffects,
    RuleTargets,
)
from guard_core.handlers._dynamic_rule_attribution import (
    RuleAttribution,
    build_rule_attribution,
)
from guard_core.handlers._dynamic_rule_intake import (
    DynamicRuleIntakeMixin,
    RunStopped,
)
from guard_core.handlers._dynamic_rule_plan import (
    DynamicRulePlan,
    DynamicRulePlanMixin,
)
from guard_core.handlers._dynamic_rule_snapshot import DynamicRuleSnapshotMixin
from guard_core.handlers._ipban_cache import _Network
from guard_core.handlers._redis_attempt import ConnectionLocks
from guard_core.handlers.ipban_handler import IPBanManager, ip_ban_manager_for
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import (
    AgentHandlerProtocol,
    DynamicRulesProtocol,
)
from guard_core.protocols.redis_protocol import RedisHandlerProtocol


def _coerce_naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


# The stop event of the loop run this context belongs to; set by the run itself, so a
# stop can only ever reach the run it was meant for.
_RUN_STOP: ContextVar[asyncio.Event | None] = ContextVar(
    "guard_core_rule_run_stop", default=None
)


class _NoTask:
    """Stands in for the task of a coroutine driven without one."""


_NO_TASK = _NoTask()


# The manager, the task and the release epoch a rule cycle started with, the first two
# as weak references (never the objects: a copied context must not keep a released app
# alive; never ids: a freed address is reused at once, a dead referent is not); the
# epoch is compared with the manager's own, so a release during its awaits ends it.
_ENTRY_EPOCH: ContextVar[
    tuple[weakref.ref["DynamicRuleManager"], weakref.ref[object], int] | None
] = ContextVar("guard_core_rule_entry_epoch", default=None)


def _current_owner() -> object:
    return asyncio.current_task() or _NO_TASK


class DynamicRuleManager(
    DynamicRuleIntakeMixin,
    DynamicRulePlanMixin,
    DynamicRuleApplicationMixin,
    DynamicRuleSnapshotMixin,
):
    _instance = None
    # A WeakableConfig descriptor; instances read a SecurityConfig through it.
    config: SecurityConfig = cast("SecurityConfig", WeakableConfig())
    agent_handler: AgentHandlerProtocol | None = None
    redis_handler: RedisHandlerProtocol | None = None
    bound_ban_manager: IPBanManager | None = None
    logger: logging.Logger
    last_update: float = 0
    current_rules: DynamicRulesProtocol | None = None
    update_task: asyncio.Task | None = None
    _connection_locks: ConnectionLocks
    _stop_event: asyncio.Event
    _release_epoch: int = 0
    _active_base_snapshot: dict[str, object] | None = None
    _active_base_owner: weakref.ReferenceType[SecurityConfig] | None = None
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
        cls: type["DynamicRuleManager"], config: SecurityConfig
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

    @property
    def _lock(self) -> asyncio.Lock:
        """One lock per running loop: a contended asyncio.Lock binds the loop it first
        waited on, and a default manager outlives the app (and loop) that used it."""
        return self._connection_locks.here()

    def _base_snapshot_of(self, config: SecurityConfig) -> dict[str, object] | None:
        """The base taken from this config, never the one a previous app left."""
        owner = self._active_base_owner
        if owner is not None and owner() is not config:
            return None
        return self._active_base_snapshot

    def _keep_base_snapshot(
        self, base: dict[str, object], config: SecurityConfig
    ) -> None:
        self._active_base_snapshot = base
        self._active_base_owner = weakref.ref(config)

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
        self.mark_released()
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

    def mark_released(self) -> None:
        """The first thing a release does, before any state is popped or withdrawn:
        every apply, expiry and revoke that started earlier now ends."""
        self._release_epoch += 1

    @contextmanager
    def _entry_epoch_scope(self) -> Iterator[None]:
        """The epoch of the whole rule cycle: the outermost scope of this manager in
        this task takes it and the scopes nested inside keep it, so a release during
        the fetch ends the cycle. A task made inside a cycle copies its context but
        starts its own cycle."""
        owner = _current_owner()
        entry = _ENTRY_EPOCH.get()
        if entry is not None and entry[0]() is self and entry[1]() is owner:
            yield
            return
        token = _ENTRY_EPOCH.set(
            (weakref.ref(self), weakref.ref(owner), self._release_epoch)
        )
        try:
            yield
        finally:
            _ENTRY_EPOCH.reset(token)

    def _released_since_entry(self) -> bool:
        entry = _ENTRY_EPOCH.get()
        return (
            entry is not None and entry[0]() is self and entry[2] != self._release_epoch
        )

    def _end_if_released_since_entry(self) -> None:
        if self._released_since_entry():
            raise RunStopped

    def _withdraw_the_applied_rules(self) -> None:
        # An apply, a revoke or an expiry holds ``_lock`` while it works. Reverting
        # under it would race that write, and waiting for it would block release on
        # the network, so a held lock leaves the overlay in place: the stopped run
        # applies nothing more (the run check in ``_apply_rules``) and the app's own
        # next initialization replaces it.
        if (
            self.current_rules is None
            or self.config is None
            or self._connection_locks.any_locked()
        ):
            self._keep_pending_base_on_the_config()
            return
        try:
            self._revert_to_base_config()
        except Exception as e:
            self.logger.error(f"Withdrawing the applied dynamic rules failed: {e}")

    def _keep_pending_base_on_the_config(self) -> None:
        base = self._base_snapshot_of(self.config)
        if self.current_rules is not None and base is not None:
            record_pending_rule_base(self.config, base)

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
        instance._connection_locks = ConnectionLocks()
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

    async def initialize_agent(self, agent_handler: AgentHandlerProtocol) -> None:
        self.agent_handler = agent_handler

        if self.config.enable_dynamic_rules:
            if not self._hydrated_last_known_rules:
                self._hydrated_last_known_rules = True
                await self._hydrate_last_known_rules()
            if not background_task_is_live(self.update_task):
                stop_event = asyncio.Event()
                self._stop_event = stop_event
                self.update_task = asyncio.create_task(
                    self._rule_update_loop(stop_event)
                )
                self.logger.info("Started dynamic rule update loop")

    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        self.redis_handler = redis_handler
        stop_before_redis_closes(redis_handler, self._stop_update_loop)

    async def _stop_update_loop(self) -> None:
        await stop_task_on_its_own_loop(self.update_task)

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

    def _run_was_stopped(self) -> bool:
        stop_event = _RUN_STOP.get()
        stopped = stop_event is not None and stop_event.is_set()
        return stopped or self._released_since_entry()

    async def _rule_update_loop(self, stop_event: asyncio.Event | None = None) -> None:
        run_stop = stop_event if stop_event is not None else self._stop_event
        token = _RUN_STOP.set(run_stop)
        try:
            while not run_stop.is_set():
                try:
                    await self.update_rules()
                    if run_stop.is_set():
                        break
                    await self._interruptible_sleep(
                        self.config.dynamic_rule_interval, run_stop
                    )
                except asyncio.CancelledError:
                    self.logger.info("Dynamic rule update loop cancelled")
                    break
                except RunStopped:
                    break
                except Exception as e:
                    self.logger.error(f"Error in dynamic rule update loop: {e}")
                    if run_stop.is_set():
                        break
                    await self._interruptible_sleep(
                        min(60, self.config.dynamic_rule_interval), run_stop
                    )
        finally:
            _RUN_STOP.reset(token)

    async def _interruptible_sleep(
        self, timeout: float, stop_event: asyncio.Event | None = None
    ) -> None:
        event = stop_event if stop_event is not None else self._stop_event
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass

    def _revert_to_base_config(self) -> None:
        self.ban_manager_of_the_app().set_rule_exempt_ips(())
        base = self._base_snapshot_of(self.config)
        if base is not None:
            self._restore_config(base)
        self.current_rules = None
        self._current_fingerprint = None
        self._active_base_snapshot = None
        self._active_base_owner = None
        self._refresh_attribution()

    async def _check_rule_expiry(self) -> None:
        with self._entry_epoch_scope():
            await self._expire_from_entry()

    async def _expire_from_entry(self) -> None:
        async with self._lock:
            self._end_if_released_since_entry()
            rules = self.current_rules
            if rules is None or rules.expires_at is None:
                return
            if datetime.now(timezone.utc) <= _coerce_naive_utc(rules.expires_at):
                return

            self._revert_to_base_config()
            self._end_if_released_since_entry()
            await self._revoke_all_owned()
            self.logger.info(
                f"Dynamic rule {rules.rule_id} v{rules.version} expired; "
                "restored base config"
            )

    async def _revoke_active_rules(self, answer: DynamicRulesProtocol) -> None:
        with self._entry_epoch_scope():
            await self._revoke_from_entry(answer)

    async def _revoke_from_entry(self, answer: DynamicRulesProtocol) -> None:
        async with self._lock:
            self._end_if_released_since_entry()
            rules = self.current_rules
            if rules is None:
                return
            self._revert_to_base_config()
            self._end_if_released_since_entry()
            await self._revoke_all_owned()
            self._end_if_released_since_entry()
            await self._clear_last_known_rules()
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
        from guard_core.core.initialization._ban_threshold_report import (
            log_unreachable_ban_thresholds_after_rule_change,
        )

        try:
            log_unreachable_ban_thresholds_after_rule_change(self.config, self.logger)
        except Exception:
            self.logger.exception("Checking the ban thresholds after a rule failed")

    async def _apply_rules(self, rules: DynamicRulesProtocol) -> list[str]:
        with self._entry_epoch_scope():
            return await self._apply_rules_from_entry(rules)

    async def _apply_rules_from_entry(self, rules: DynamicRulesProtocol) -> list[str]:
        async with self._lock:
            self._end_run_if_stopped()
            targets = self._capture_rule_targets()
            base = self._base_snapshot_of(targets.config)
            if base is None:
                base = self._snapshot_config()
            plan = await self._build_plan(rules, base)
            self._end_run_if_stopped()
            effects = RuleSideEffects()
            previous_exempt = targets.ban_manager.rule_exempt_networks
            try:
                await self._write_plan(rules, plan, effects, targets)
            except BaseException as e:
                await self._roll_back(effects, targets, previous_exempt)
                if isinstance(e, Exception):
                    self.logger.error(f"Failed to apply dynamic rules: {e}")
                raise
            try:
                await self._finish_after_the_swap(rules, plan, effects, targets, base)
            except RunStopped:
                record_pending_rule_base(targets.config, base)
                raise
            return [*plan.skipped, *effects.skipped]

    async def _finish_after_the_swap(
        self,
        rules: DynamicRulesProtocol,
        plan: DynamicRulePlan,
        effects: RuleSideEffects,
        targets: RuleTargets,
        base: dict[str, object],
    ) -> None:
        # A release past the swap ends the apply without rollback (it held the lock,
        # so the release could not withdraw): the caller records the base on the
        # config, and none of the tail may write for the next app.
        self._end_if_released_since_entry()
        self._keep_base_snapshot(base, targets.config)
        self._log_unreachable_ban_thresholds_after_swap(base, plan)
        await self._revoke_stale_side_effects(rules, effects, targets)
        self._end_if_released_since_entry()
        self._refresh_attribution(rules)
        await self._announce_plan(plan)
        self._end_if_released_since_entry()
        await self._persist_last_known_rules(rules)

    async def _write_plan(
        self,
        rules: DynamicRulesProtocol,
        plan: DynamicRulePlan,
        effects: RuleSideEffects,
        targets: RuleTargets,
    ) -> None:
        targets.ban_manager.set_rule_exempt_ips(plan.exempt_ips)
        await self._apply_side_effects(rules, effects, plan.exempt_ips, targets)
        self._end_run_if_stopped()
        self._swap_config(plan, targets.config)

    async def _roll_back(
        self,
        effects: RuleSideEffects,
        targets: RuleTargets,
        previous_exempt: tuple[_Network, ...],
    ) -> None:
        targets.ban_manager.rule_exempt_networks = previous_exempt
        await self._undo_side_effects(effects, targets)

    async def get_current_rules(self) -> DynamicRulesProtocol | None:
        return self.current_rules

    async def force_update(self) -> None:
        with self._entry_epoch_scope(), in_app_scope(app_scope_of(self.config)):
            try:
                await self.update_rules()
            except RunStopped:
                return

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


def dynamic_rule_manager_of_the_app(config: SecurityConfig) -> DynamicRuleManager:
    """The manager an app's own initializer uses: the app owns the config, so a
    module-held manager must not keep it alive."""
    manager = DynamicRuleManager(config)
    release_config_to_app(manager, config)
    return manager
