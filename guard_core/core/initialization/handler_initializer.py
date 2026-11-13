import asyncio
import logging
from typing import TYPE_CHECKING

from guard_core._geo_handler_for_tree import (
    GeoIPHandlerOfEitherTree,
    geo_ip_handler_for_tree,
)
from guard_core._utils.config_registry import REDIS_HANDLERS
from guard_core._utils.pending_rule_base import revert_pending_rule_base
from guard_core.core.initialization._handler_initializer_steps import (
    _HandlerInitializerStepsMixin,
    _RateLimitSlot,
)
from guard_core.handlers._redis_attempt import ConnectionLocks
from guard_core.handlers.behavior_handler import BehaviorTracker

if TYPE_CHECKING:
    from guard_core.core.events.composite_handler import CompositeAgentHandler
    from guard_core.core.events.enricher import EventEnricher
    from guard_core.core.events.event_types import EventFilter
    from guard_core.core.events.metrics import MetricsCollector
    from guard_core.core.events.middleware_events import SecurityEventBus
    from guard_core.decorators.base import BaseSecurityDecorator
    from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
    from guard_core.models import SecurityConfig
    from guard_core.protocols.agent_protocol import AgentHandlerProtocol
    from guard_core.protocols.redis_protocol import RedisHandlerProtocol


def bind_app_managers(config: "SecurityConfig") -> None:
    """Bind the app of this config to its ban, cloud and pattern managers."""
    from guard_core.handlers.cloud_handler import cloud_handler_for
    from guard_core.handlers.ipban_handler import ip_ban_manager_for
    from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for

    revert_pending_rule_base(config)
    ip_ban_manager_for(config, bind=True)
    cloud_handler_for(config, bind=True)
    sus_patterns_manager_for(config, bind=True)


class HandlerInitializer(_HandlerInitializerStepsMixin):
    def __init__(
        self,
        config: "SecurityConfig",
        redis_handler: "RedisHandlerProtocol | None" = None,
        agent_handler: "AgentHandlerProtocol | None" = None,
        geo_ip_handler: "GeoIPHandlerOfEitherTree | None" = None,
        rate_limit_handler: "_RateLimitSlot | None" = None,
        guard_decorator: "BaseSecurityDecorator | None" = None,
        adapter: str | None = None,
    ):
        self.config = config
        self.redis_handler = redis_handler
        if redis_handler is not None:
            REDIS_HANDLERS.register(config, redis_handler)
        bind_app_managers(config)
        self.agent_handler = agent_handler
        from guard_core.handlers._downloader import TREE_AWAITS

        self.geo_ip_handler = geo_ip_handler_for_tree(
            config, geo_ip_handler, tree_awaits=TREE_AWAITS
        )
        self._geo_handler_is_ours = self.geo_ip_handler is not geo_ip_handler
        self._adapter = adapter
        self.rate_limit_handler = rate_limit_handler
        mark_bound = getattr(rate_limit_handler, "mark_bound_to_app", None)
        if callable(mark_bound):
            mark_bound()
        self.guard_decorator = guard_decorator
        self.composite_handler: CompositeAgentHandler | None = None
        self.event_filter: EventFilter | None = None
        self.enricher: EventEnricher | None = None
        self.behavior_tracker = (
            None if guard_decorator is not None else BehaviorTracker(config)
        )
        self._lazy_init_task: asyncio.Task[None] | None = None
        self._decorator_adoption_lock = ConnectionLocks()
        self.logger = logging.getLogger("guard_core.core.initialization")
        self._require_tree_downloader(adapter)
        self.inject_bound_ban_manager()

    async def reinitialize_after_release(self) -> None:
        """Run again what the app's startup ran, after ``release_app`` ended it: the
        bind, the Redis and detection setup (Redis and config-declared state come
        back, runtime state does not), the agent wiring and the rule loop. The
        pipeline awaits it once, before it rebuilds its checks."""
        adoption_pending = self._pending_adoption()
        bind_app_managers(self.config)
        self.inject_bound_ban_manager()
        await self.initialize_redis_handlers()
        if self.composite_handler is not None or self.agent_handler is not None:
            await self.initialize_agent_for_handlers()
            await self._initialize_behavior_telemetry()
            await self.initialize_dynamic_rule_manager()
        if self._pending_adoption() is adoption_pending:
            self._decorator_adoption_pending = None

    def inject_bound_ban_manager(self) -> None:
        """Hand the ban manager this app was bound to (the bind is in ``__init__``)
        to what it adopts, so a tracker built by a decorator before any bind, or a
        rule manager a host built early, bans on this app's manager and never on
        whichever manager a lookup by config finds later."""
        from guard_core.handlers.ipban_handler import ip_ban_manager_for

        manager = ip_ban_manager_for(self.config)
        trackers = (
            self.behavior_tracker,
            getattr(self.guard_decorator, "behavior_tracker", None),
        )
        for tracker in trackers:
            use_ban_manager = getattr(tracker, "use_ban_manager", None)
            if use_ban_manager is not None:
                use_ban_manager(manager)

    def dynamic_rule_manager_of_this_app(self) -> "DynamicRuleManager":
        from guard_core.handlers.dynamic_rule_handler import (
            dynamic_rule_manager_of_the_app,
        )
        from guard_core.handlers.ipban_handler import ip_ban_manager_for

        manager = dynamic_rule_manager_of_the_app(self.config)
        manager.use_ban_manager(ip_ban_manager_for(self.config))
        return manager

    def get_initialization_status(self) -> dict[str, object]:
        from guard_core.handlers.cloud_handler import cloud_handler_for

        geo_status: dict[str, object] | None = None
        if self.geo_ip_handler is not None:
            status_getter = getattr(self.geo_ip_handler, "get_status", None)
            if callable(status_getter):
                geo_status = status_getter()
            else:
                geo_status = {
                    "ready": self.geo_ip_handler.is_initialized,
                    "last_refreshed": None,
                    "entries": 0,
                }

        return {
            "cloud_providers": cloud_handler_for(self.config).get_status(),
            "geo_ip": geo_status,
        }

    def build_enricher(self) -> "EventEnricher | None":
        if not self.config.enable_enrichment:
            return None
        from guard_core.core.events.enricher import EnrichmentContext, EventEnricher

        dynamic_rule_handler: object | None = None
        if self.config.enable_dynamic_rules:
            dynamic_rule_handler = self.dynamic_rule_manager_of_this_app()

        behavior_tracker = self.behavior_tracker
        if behavior_tracker is None:
            behavior_tracker = getattr(self.guard_decorator, "behavior_tracker", None)
        if behavior_tracker is None:
            behavior_tracker = BehaviorTracker(self.config)

        self.behavior_tracker = behavior_tracker
        self.inject_bound_ban_manager()

        context = EnrichmentContext(
            config=self.config,
            agent_handler=self.agent_handler,
            dynamic_rule_handler=dynamic_rule_handler,
            behavior_tracker=behavior_tracker,
        )
        return EventEnricher(context)

    def build_composite_handler(self) -> "CompositeAgentHandler":
        from guard_core.core.events.composite_handler import CompositeAgentHandler

        handlers: list[AgentHandlerProtocol] = []
        if self.agent_handler:
            handlers.append(self.agent_handler)
        if self.config.enable_otel:
            from guard_core.core.events.otel_handler import OtelHandler

            handlers.append(OtelHandler(self.config))
        if self.config.enable_logfire:
            from guard_core.core.events.logfire_handler import LogfireHandler

            handlers.append(LogfireHandler(self.config))
        event_filter = self.build_event_filter()
        self.enricher = self.build_enricher()
        return CompositeAgentHandler(
            handlers, event_filter=event_filter, enricher=self.enricher
        )

    def build_event_filter(self) -> "EventFilter":
        from guard_core.core.events.event_types import EventFilter

        return EventFilter(
            muted_event_types=frozenset(self.config.muted_event_types),
            muted_metric_types=frozenset(self.config.muted_metric_types),
        )

    def build_event_bus(
        self, geo_ip_handler: "GeoIPHandlerOfEitherTree | None" = None
    ) -> "SecurityEventBus":
        from guard_core.core.events.middleware_events import SecurityEventBus

        if self.composite_handler is None or self.event_filter is None:
            raise RuntimeError(
                "Call initialize_agent_integrations() before build_event_bus()."
            )
        return SecurityEventBus(
            agent_handler=self.composite_handler,
            config=self.config,
            geo_ip_handler=geo_ip_handler or self.geo_ip_handler,
            event_filter=self.event_filter,
        )

    def build_metrics_collector(self) -> "MetricsCollector":
        from guard_core.core.events.metrics import MetricsCollector

        if self.composite_handler is None or self.event_filter is None:
            raise RuntimeError(
                "Call initialize_agent_integrations() before build_metrics_collector()."
            )
        return MetricsCollector(
            agent_handler=self.composite_handler,
            config=self.config,
            event_filter=self.event_filter,
        )
