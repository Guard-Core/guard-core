import asyncio
import logging
from typing import TYPE_CHECKING, Any

from guard_core._misconfiguration import report_misconfiguration
from guard_core._staged_defaults import _warn_whitelist_without_access_only
from guard_core.core.checks.helpers import _MAX_RETAINED_EVENTS_PER_CATEGORY
from guard_core.core.initialization._ban_threshold_report import (
    _BanThresholdContext,
    remember_ban_threshold_context,
    report_unreachable_ban_thresholds,
)
from guard_core.core.initialization._cloud_initialization import (
    CloudInitializationMixin,
)
from guard_core.core.initialization._headers_manager_attach import (
    attach_security_headers_manager_to_redis,
)
from guard_core.core.initialization._nat64 import apply_nat64_prefixes
from guard_core.core.initialization._route_limit_report import (
    report_route_limits_with_global_switch_off,
)
from guard_core.core.initialization._whitelist_strikes import (
    reset_startup_whitelist_strikes,
)
from guard_core.exceptions import GuardRedisError

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig


class _HandlerInitializerStepsMixin(CloudInitializationMixin):
    config: "SecurityConfig"
    redis_handler: Any = None
    agent_handler: Any = None
    geo_ip_handler: Any = None
    rate_limit_handler: Any = None
    guard_decorator: Any = None
    composite_handler: Any = None
    event_filter: Any = None
    behavior_tracker: Any = None
    _lazy_init_task: "asyncio.Task[None] | None" = None
    logger: logging.Logger

    def build_composite_handler(self) -> Any: ...

    def build_event_filter(self) -> Any: ...

    async def _run_lazy_init(self) -> None:
        from guard_core.handlers.cloud_handler import cloud_handler

        if providers := self._cloud_providers_to_load():
            try:
                await cloud_handler.initialize_redis(
                    self.redis_handler,
                    providers,
                    ttl=self.config.cloud_ip_refresh_interval,
                )
            except Exception as e:
                self.logger.warning(
                    "Lazy cloud-IP initialization failed: %s", e, exc_info=True
                )

        if self.geo_ip_handler is not None:
            try:
                await self.geo_ip_handler.initialize_redis(self.redis_handler)
            except Exception as e:
                self.logger.warning(
                    "Lazy geo-IP initialization failed: %s", e, exc_info=True
                )

    def _configure_detection(self) -> None:
        from guard_core.handlers.ipban_handler import ip_ban_manager
        from guard_core.handlers.suspatterns_handler import sus_patterns_handler

        ip_ban_manager.config = self.config
        _warn_whitelist_without_access_only(self.config, stacklevel=3)
        ip_ban_manager.set_capacity(self.config.banned_ips_max_entries)
        sus_patterns_handler.configure(self.config)
        apply_nat64_prefixes(self.config, self.logger)

    def _report_unreachable_ban_thresholds(self) -> None:
        context = _BanThresholdContext(
            lambda: tuple(getattr(self.guard_decorator, "_route_configs", {}).values()),
            lambda: bool(self.config.enable_redis and self.redis_handler),
        )
        remember_ban_threshold_context(context.route_configs, context.redis_shared)
        report_unreachable_ban_thresholds(
            self.config, context, self.logger, stacklevel=5
        )

    def _report_country_decorators_without_geoip(self) -> None:
        if self.guard_decorator is None:
            return
        route_configs = getattr(self.guard_decorator, "_route_configs", {})
        for route_id, route_config in route_configs.items():
            decorators = []
            if self.geo_ip_handler is None and (
                route_config.blocked_countries or route_config.whitelist_countries
            ):
                decorators.append("block_countries or allow_countries")
            if self.geo_ip_handler is None and route_config.geo_rate_limits:
                decorators.append("geo_rate_limit")
            for decorator in decorators:
                report_misconfiguration(
                    self.config,
                    f"Route {route_id!r} uses {decorator} but no GeoIP database "
                    "is configured (geo_ip_handler is None; set ipinfo_token or "
                    "geo_ip_handler), so the country rule is ignored.",
                    logger=self.logger,
                    stacklevel=4,
                )

    def _report_route_limits_with_global_switch_off(self) -> None:
        report_route_limits_with_global_switch_off(
            self.config, self.guard_decorator, self.logger
        )

    def _warn_if_lazy_init_is_inert(self) -> None:
        if not (self._cloud_providers_to_load() or self.geo_ip_handler is not None):
            return
        self.logger.warning(
            "lazy_init has no effect without Redis (enable_redis=True and a "
            "redis_handler); cloud-IP ranges and the geo-IP database will "
            "initialize through their own on-demand paths regardless of "
            "lazy_init's value."
        )

    async def _connect_redis(self) -> bool:
        try:
            await self.redis_handler.initialize()
        except GuardRedisError as e:
            self.logger.error(
                "Redis unavailable during initialization: %s", e, exc_info=True
            )
            if not self.config.redis_fail_open:
                raise
            return False
        return True

    async def _initialize_connected_redis_handlers(self) -> None:
        from guard_core.handlers.cloud_handler import cloud_handler
        from guard_core.handlers.ipban_handler import ip_ban_manager
        from guard_core.handlers.suspatterns_handler import sus_patterns_handler

        if self.config.cloud_ip_store is not None:
            cloud_handler.set_store(self._resolve_cloud_ip_store())

        await self._initialize_cloud_and_geo_redis()
        await ip_ban_manager.initialize_redis(self.redis_handler)
        await reset_startup_whitelist_strikes(
            self.config, self.redis_handler, ip_ban_manager
        )

        if self.rate_limit_handler is not None:
            await self.rate_limit_handler.initialize_redis(self.redis_handler)
        await sus_patterns_handler.initialize_redis(self.redis_handler)
        await attach_security_headers_manager_to_redis(self.redis_handler, self.config)

        if self.guard_decorator is not None:
            await self.guard_decorator.initialize_behavior_tracking(self.redis_handler)
        if self.behavior_tracker is not None:
            await self.behavior_tracker.initialize_redis(self.redis_handler)

    async def initialize_redis_handlers(self) -> None:
        self._report_unreachable_ban_thresholds()
        self._report_country_decorators_without_geoip()
        self._report_route_limits_with_global_switch_off()
        self._configure_detection()

        if not (self.config.enable_redis and self.redis_handler):
            if self.config.lazy_init:
                self._warn_if_lazy_init_is_inert()
                return
            await self._load_cloud_and_geo_without_redis()
            return

        if not await self._connect_redis():
            await self._load_cloud_and_geo_without_redis()
            return

        await self._initialize_connected_redis_handlers()

    async def initialize_agent_for_handlers(self) -> None:
        telemetry = self.composite_handler or self.agent_handler
        if telemetry is None:
            return

        from guard_core.handlers.cloud_handler import cloud_handler
        from guard_core.handlers.ipban_handler import ip_ban_manager
        from guard_core.handlers.security_headers_handler import (
            security_headers_manager,
        )
        from guard_core.handlers.suspatterns_handler import sus_patterns_handler

        await ip_ban_manager.initialize_agent(telemetry)
        if self.rate_limit_handler is not None:
            await self.rate_limit_handler.initialize_agent(telemetry)
        await sus_patterns_handler.initialize_agent(telemetry)
        await security_headers_manager.initialize_agent(telemetry)

        if self._cloud_providers_to_load():
            await cloud_handler.initialize_agent(telemetry)

        if self.geo_ip_handler and hasattr(self.geo_ip_handler, "initialize_agent"):
            await self.geo_ip_handler.initialize_agent(telemetry)

    async def initialize_dynamic_rule_manager(self) -> None:
        if not self.config.enable_dynamic_rules:
            return
        if not self.agent_handler:
            self.logger.warning(
                "Dynamic rules enabled but agent unavailable; falling back to "
                "static config. Dashboard rule updates will not propagate until "
                "agent connectivity is restored."
            )
            return

        from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager

        dynamic_rule_manager = DynamicRuleManager(self.config)
        telemetry = self.composite_handler or self.agent_handler

        if self.redis_handler:
            await dynamic_rule_manager.initialize_redis(self.redis_handler)

        await dynamic_rule_manager.initialize_agent(telemetry)

    async def initialize_agent_integrations(self) -> None:
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

        await self.composite_handler.start()

        if self.agent_handler and self.redis_handler:
            await self.agent_handler.initialize_redis(self.redis_handler)
            await self.redis_handler.initialize_agent(self.agent_handler)

        await self.initialize_agent_for_handlers()
        await self._initialize_behavior_telemetry()
        await self.initialize_dynamic_rule_manager()

    async def _initialize_behavior_telemetry(self) -> None:
        if self.guard_decorator and hasattr(self.guard_decorator, "initialize_agent"):
            telemetry = self.composite_handler or self.agent_handler
            await self.guard_decorator.initialize_agent(telemetry)

        if self.behavior_tracker is not None:
            await self.behavior_tracker.initialize_agent(self.composite_handler)

    async def shutdown_agent_integrations(self) -> None:
        if self.composite_handler is None:
            return
        await self.composite_handler.stop()
        self.composite_handler = None
        self.event_filter = None
        self.enricher = None
