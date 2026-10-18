import logging
import threading
from typing import TYPE_CHECKING, Any

from guard_core.sync._utils.config_registry import REDIS_HANDLERS
from guard_core.sync.core.initialization._handler_initializer_steps import (
    _HandlerInitializerStepsMixin,
)
from guard_core.sync.handlers.behavior_handler import BehaviorTracker

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig
    from guard_core.sync.core.events.metrics import MetricsCollector
    from guard_core.sync.core.events.middleware_events import SecurityEventBus


class HandlerInitializer(_HandlerInitializerStepsMixin):
    def __init__(
        self,
        config: "SecurityConfig",
        redis_handler: Any = None,
        agent_handler: Any = None,
        geo_ip_handler: Any = None,
        rate_limit_handler: Any = None,
        guard_decorator: Any = None,
    ):
        self.config = config
        self.redis_handler = redis_handler
        if redis_handler is not None:
            REDIS_HANDLERS.register(config, redis_handler)
        self.agent_handler = agent_handler
        self.geo_ip_handler = geo_ip_handler
        self.rate_limit_handler = rate_limit_handler
        mark_bound = getattr(rate_limit_handler, "mark_bound_to_app", None)
        if callable(mark_bound):
            mark_bound()
        self.guard_decorator = guard_decorator
        self.composite_handler: Any = None
        self.event_filter: Any = None
        self.enricher: Any = None
        self.behavior_tracker: Any = (
            None if guard_decorator is not None else BehaviorTracker(config)
        )
        self._lazy_init_task: threading.Thread | None = None
        self.logger = logging.getLogger("guard_core.sync.core.initialization")

    def get_initialization_status(self) -> dict[str, Any]:
        from guard_core.sync.handlers.cloud_handler import cloud_handler

        geo_status: dict[str, Any] | None = None
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
            "cloud_providers": cloud_handler.get_status(),
            "geo_ip": geo_status,
        }

    def build_enricher(self) -> Any | None:
        if not self.config.enable_enrichment:
            return None
        from guard_core.sync.core.events.enricher import (
            EnrichmentContext,
            EventEnricher,
        )

        dynamic_rule_handler: Any = None
        if self.config.enable_dynamic_rules:
            from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager

            dynamic_rule_handler = DynamicRuleManager(self.config)

        behavior_tracker = self.behavior_tracker
        if behavior_tracker is None:
            behavior_tracker = getattr(self.guard_decorator, "behavior_tracker", None)
        if behavior_tracker is None:
            behavior_tracker = BehaviorTracker(self.config)

        self.behavior_tracker = behavior_tracker

        context = EnrichmentContext(
            config=self.config,
            agent_handler=self.agent_handler,
            dynamic_rule_handler=dynamic_rule_handler,
            behavior_tracker=behavior_tracker,
        )
        return EventEnricher(context)

    def build_composite_handler(self) -> Any:
        from guard_core.sync.core.events.composite_handler import CompositeAgentHandler

        handlers = []
        if self.agent_handler:
            handlers.append(self.agent_handler)
        if self.config.enable_otel:
            from guard_core.sync.core.events.otel_handler import OtelHandler

            handlers.append(OtelHandler(self.config))
        if self.config.enable_logfire:
            from guard_core.sync.core.events.logfire_handler import LogfireHandler

            handlers.append(LogfireHandler(self.config))
        event_filter = self.build_event_filter()
        self.enricher = self.build_enricher()
        return CompositeAgentHandler(
            handlers, event_filter=event_filter, enricher=self.enricher
        )

    def build_event_filter(self) -> Any:
        from guard_core.sync.core.events.event_types import EventFilter

        return EventFilter(
            muted_event_types=frozenset(self.config.muted_event_types),
            muted_metric_types=frozenset(self.config.muted_metric_types),
        )

    def build_event_bus(self, geo_ip_handler: Any = None) -> "SecurityEventBus":
        from guard_core.sync.core.events.middleware_events import SecurityEventBus

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
        from guard_core.sync.core.events.metrics import MetricsCollector

        if self.composite_handler is None or self.event_filter is None:
            raise RuntimeError(
                "Call initialize_agent_integrations() before build_metrics_collector()."
            )
        return MetricsCollector(
            agent_handler=self.composite_handler,
            config=self.config,
            event_filter=self.event_filter,
        )
