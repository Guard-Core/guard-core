import logging
import threading
from abc import abstractmethod
from collections import OrderedDict
from typing import TYPE_CHECKING, Protocol

from guard_core._redis_enablement import redis_is_configured, resolve_enable_redis
from guard_core._staged_defaults import signal_changed_defaults
from guard_core.exceptions import GuardRedisError
from guard_core.sync._utils.app_scope import app_scope_of, in_app_scope
from guard_core.sync._utils.geo_member_call import settle_geo_member_call
from guard_core.sync._utils.sampling import observe_sampled_key
from guard_core.sync.core.initialization._cloud_initialization import (
    CloudInitializationMixin,
)
from guard_core.sync.core.initialization._headers_manager_attach import (
    attach_security_headers_manager_to_redis,
)
from guard_core.sync.core.initialization._nat64 import apply_nat64_prefixes
from guard_core.sync.core.initialization._redis_handler_members import (
    report_incomplete_redis_handler,
)
from guard_core.sync.core.initialization._route_misconfiguration_reports import (
    RouteMisconfigurationReportsMixin,
)
from guard_core.sync.core.initialization._whitelist_strikes import (
    reset_startup_whitelist_strikes,
)

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.core.events.composite_handler import CompositeAgentHandler
    from guard_core.sync.core.events.enricher import EventEnricher
    from guard_core.sync.core.events.event_types import EventFilter
    from guard_core.sync.decorators.base import BaseSecurityDecorator
    from guard_core.sync.handlers.behavior_handler import BehaviorTracker
    from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
    from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
    from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol

_INIT_FAILURE_SAMPLE_WINDOW_SECONDS = 60
_init_failure_lock = threading.Lock()
_init_failure_samples: OrderedDict[str, float] = OrderedDict()


def _sample_init_failure_line() -> bool:
    return observe_sampled_key(
        _init_failure_samples,
        _init_failure_lock,
        "redis-unavailable-during-initialization",
        window=_INIT_FAILURE_SAMPLE_WINDOW_SECONDS,
        max_tracked=1,
    )


class _RateLimitSlot(Protocol):
    def initialize_redis(
        self, redis_handler: "SyncRedisHandlerProtocol | None"
    ) -> None: ...

    def initialize_agent(self, agent_handler: "SyncAgentHandlerProtocol") -> None: ...


class _HandlerInitializerStepsMixin(
    RouteMisconfigurationReportsMixin, CloudInitializationMixin
):
    config: "SyncSecurityConfig"
    redis_handler: "SyncRedisHandlerProtocol | None" = None
    agent_handler: "SyncAgentHandlerProtocol | None" = None
    geo_ip_handler: "SyncGeoIPHandler | None" = None
    rate_limit_handler: "_RateLimitSlot | None" = None
    guard_decorator: "BaseSecurityDecorator | None" = None
    composite_handler: "CompositeAgentHandler | None" = None
    event_filter: "EventFilter | None" = None
    behavior_tracker: "BehaviorTracker | None" = None
    enricher: "EventEnricher | None" = None
    _lazy_init_task: "threading.Thread | None" = None
    logger: logging.Logger
    _adapter: str | None = None
    _geo_handler_is_ours: bool = False

    def _require_tree_downloader(self, adapter: str | None) -> None:
        from guard_core._config_capabilities import cloud_blocking_enabled
        from guard_core.sync.handlers._downloader import require_downloader_installed

        if cloud_blocking_enabled(self.config) or self._cloud_providers_to_load():
            require_downloader_installed(
                "cloud", "Cloud provider blocking or dynamic rules", adapter
            )
        builds_its_own_geo_database = (
            self.geo_ip_handler is not None
            and (
                self.geo_ip_handler is self.config.geo_ip_handler
                or self._geo_handler_is_ours
            )
            and bool(self.config.ipinfo_token)
        )
        if builds_its_own_geo_database:
            require_downloader_installed(
                "geo", "The built-in GeoIP database download", adapter
            )

    @abstractmethod
    def build_composite_handler(self) -> "CompositeAgentHandler": ...

    @abstractmethod
    def build_event_filter(self) -> "EventFilter": ...

    def _require_redis_handler(self) -> "SyncRedisHandlerProtocol":
        if self.redis_handler is None:
            raise RuntimeError("This step needs a redis_handler and none is set")
        return self.redis_handler

    def _run_lazy_init(self) -> None:
        with in_app_scope(app_scope_of(self.config)):
            self._run_lazy_init_in_scope()

    def _run_lazy_init_in_scope(self) -> None:
        from guard_core.sync.handlers.cloud_handler import cloud_handler_for

        redis_handler = self._require_redis_handler()
        if providers := self._cloud_providers_to_load():
            try:
                cloud_handler_for(self.config).initialize_redis(
                    redis_handler,
                    providers,
                    ttl=self.config.cloud_ip_refresh_interval,
                )
            except Exception as e:
                self.logger.warning(
                    "Lazy cloud-IP initialization failed: %s", e, exc_info=True
                )

        if self.geo_ip_handler is not None:
            try:
                settle_geo_member_call(
                    self.geo_ip_handler, "initialize_redis", redis_handler
                )
            except Exception as e:
                self.logger.warning(
                    "Lazy geo-IP initialization failed: %s", e, exc_info=True
                )

    def _configure_detection(self) -> None:
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
        from guard_core.sync.handlers.suspatterns_handler import (
            sus_patterns_manager_for,
        )

        resolve_enable_redis(self.config)
        signal_changed_defaults(self.config)
        ip_ban_manager = ip_ban_manager_for(self.config, bind=True)
        ip_ban_manager.set_capacity(self.config.banned_ips_max_entries)
        sus_patterns_manager_for(self.config, bind=True).configure(self.config)
        apply_nat64_prefixes(self.config, self.logger)

    def _warn_if_lazy_init_is_inert(self) -> None:
        if not (self._cloud_providers_to_load() or self.geo_ip_handler is not None):
            return
        self.logger.warning(
            "lazy_init has no effect without Redis (enable_redis=True and a "
            "redis_handler); cloud-IP ranges and the geo-IP database will "
            "initialize through their own on-demand paths regardless of "
            "lazy_init's value."
        )

    def _connect_redis(self) -> bool:
        redis_handler = self._require_redis_handler()
        try:
            redis_handler.initialize()
        except GuardRedisError as e:
            if _sample_init_failure_line():
                self.logger.error(
                    "Redis unavailable during initialization: %s", e, exc_info=True
                )
            if not self.config.redis_fail_open:
                raise
            return False
        return True

    def _initialize_connected_redis_handlers(self) -> None:
        from guard_core.sync.handlers.cloud_handler import cloud_handler_for
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
        from guard_core.sync.handlers.suspatterns_handler import (
            sus_patterns_manager_for,
        )

        redis_handler = self._require_redis_handler()
        app_scope_of(self.config).redis_handler = redis_handler
        ip_ban_manager = ip_ban_manager_for(self.config, bind=True)
        if self.config.cloud_ip_store is not None:
            cloud_handler_for(self.config).set_store(self._resolve_cloud_ip_store())

        self._initialize_cloud_and_geo_redis(redis_handler)
        ip_ban_manager.initialize_redis(redis_handler)
        reset_startup_whitelist_strikes(self.config, redis_handler, ip_ban_manager)

        if self.rate_limit_handler is not None:
            self.rate_limit_handler.initialize_redis(redis_handler)
        sus_patterns_manager_for(self.config).initialize_redis(redis_handler)
        attach_security_headers_manager_to_redis(redis_handler, self.config)

        if self.guard_decorator is not None:
            self.guard_decorator.initialize_behavior_tracking(redis_handler)
        if self.behavior_tracker is not None:
            self.behavior_tracker.initialize_redis(redis_handler)

    def initialize_redis_handlers(self) -> None:
        scope = app_scope_of(self.config)
        scope.redis_handler = None
        with in_app_scope(scope):
            self.report_route_misconfigurations()
            self._configure_detection()

            without_redis = not (
                redis_is_configured(self.config) and self.redis_handler
            )
            if not without_redis:
                report_incomplete_redis_handler(
                    self.config, self.redis_handler, self.logger
                )
            if without_redis and self.config.lazy_init:
                self._warn_if_lazy_init_is_inert()
            elif without_redis or not self._connect_redis():
                self._load_cloud_and_geo_without_redis()
            else:
                self._initialize_connected_redis_handlers()

            self._purge_configured_dynamic_rules()

    def _purge_configured_dynamic_rules(self) -> None:
        if self.config.purge_dynamic_rules_on_start is None:
            return

        from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
        from guard_core.sync.handlers.redis_handler import is_connected_redis_manager

        manager = DynamicRuleManager(self.config)
        if is_connected_redis_manager(self.redis_handler):
            manager.initialize_redis(self.redis_handler)
        try:
            manager.purge_configured_dynamic_rules()
        except Exception:
            self.logger.exception("Purging the dynamic rules at start failed")

    def initialize_agent_for_handlers(self) -> None:
        telemetry = self.composite_handler or self.agent_handler
        if telemetry is None:
            return
        scope = app_scope_of(self.config)
        scope.agent_handler = telemetry
        with in_app_scope(scope):
            self._initialize_agent_for_handlers_in_scope(telemetry)

    def _initialize_agent_for_handlers_in_scope(
        self, telemetry: "SyncAgentHandlerProtocol"
    ) -> None:
        from guard_core.sync.handlers.cloud_handler import cloud_handler_for
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
        from guard_core.sync.handlers.security_headers_handler import (
            security_headers_manager,
        )
        from guard_core.sync.handlers.suspatterns_handler import (
            sus_patterns_manager_for,
        )

        ip_ban_manager_for(self.config, bind=True).initialize_agent(telemetry)
        if self.rate_limit_handler is not None:
            self.rate_limit_handler.initialize_agent(telemetry)
        sus_patterns_manager_for(self.config).initialize_agent(telemetry)
        security_headers_manager.initialize_agent(telemetry)

        if self._cloud_providers_to_load():
            cloud_handler_for(self.config).initialize_agent(telemetry)

        if self.geo_ip_handler and hasattr(self.geo_ip_handler, "initialize_agent"):
            settle_geo_member_call(self.geo_ip_handler, "initialize_agent", telemetry)

    def initialize_dynamic_rule_manager(self) -> None:
        if not self.config.enable_dynamic_rules:
            return
        if not self.agent_handler:
            self.logger.warning(
                "Dynamic rules enabled but agent unavailable; falling back to "
                "static config. Dashboard rule updates will not propagate until "
                "agent connectivity is restored."
            )
            return

        from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager

        dynamic_rule_manager = DynamicRuleManager(self.config)
        telemetry = self.composite_handler or self.agent_handler

        # The update loop task copies this scope, so its bans and pattern
        # writes use this app's handlers.
        with in_app_scope(app_scope_of(self.config)):
            if self.redis_handler:
                dynamic_rule_manager.initialize_redis(self.redis_handler)

            dynamic_rule_manager.initialize_agent(telemetry)

    def initialize_agent_integrations(self) -> None:
        if (
            not self.agent_handler
            and not self.config.enable_otel
            and not self.config.enable_logfire
            and not self.config.enable_enrichment
        ):
            return

        from guard_core._pydantic_plugin_mute import (
            _mute_pydantic_plugin_instrumentation,
        )

        _mute_pydantic_plugin_instrumentation()

        self.composite_handler = self.build_composite_handler()
        self.event_filter = self.build_event_filter()

        self.composite_handler.start()

        if self.agent_handler and self.redis_handler:
            self.agent_handler.initialize_redis(self.redis_handler)
            self.redis_handler.initialize_agent(self.agent_handler)

        self.initialize_agent_for_handlers()
        self._initialize_behavior_telemetry()
        self.initialize_dynamic_rule_manager()

    def _initialize_behavior_telemetry(self) -> None:
        telemetry = self.composite_handler or self.agent_handler
        if (
            telemetry is not None
            and self.guard_decorator
            and hasattr(self.guard_decorator, "initialize_agent")
        ):
            self.guard_decorator.initialize_agent(telemetry)

        if self.behavior_tracker is not None and self.composite_handler is not None:
            self.behavior_tracker.initialize_agent(self.composite_handler)

    def shutdown_agent_integrations(self) -> None:
        if self.composite_handler is None:
            return
        self.composite_handler.stop()
        app_scope_of(self.config).agent_handler = None
        self.composite_handler = None
        self.event_filter = None
        self.enricher = None
