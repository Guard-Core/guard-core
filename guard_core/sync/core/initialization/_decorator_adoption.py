import threading
from abc import abstractmethod
from typing import TYPE_CHECKING

from guard_core.sync._utils.app_scope import app_scope_of, in_app_scope
from guard_core.sync.core.initialization._route_misconfiguration_reports import (
    RouteMisconfigurationReportsMixin,
)
from guard_core.sync.handlers.behavior_handler import BehaviorTracker

if TYPE_CHECKING:
    from guard_core.sync.core.events.composite_handler import CompositeAgentHandler
    from guard_core.sync.core.events.enricher import EventEnricher
    from guard_core.sync.decorators.base import BaseSecurityDecorator
    from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol


class DecoratorAdoptionMixin(RouteMisconfigurationReportsMixin):
    """Brings a decorator given after construction to the state of one given at
    construction: ``adopt_decorator`` runs what can raise, then binds, and
    ``complete_decorator_adoption`` runs the awaited steps the app's own startup
    already ran for the decorator it knew."""

    behavior_tracker: "BehaviorTracker | None" = None
    enricher: "EventEnricher | None" = None
    composite_handler: "CompositeAgentHandler | None" = None
    _decorator_adoption_pending: "tuple[BaseSecurityDecorator | None] | None" = None
    _decorator_adoption_lock: threading.Lock

    @abstractmethod
    def inject_bound_ban_manager(self) -> None: ...

    @abstractmethod
    def _initialize_behavior_tracking_on_redis(
        self, redis_handler: "SyncRedisHandlerProtocol"
    ) -> None: ...

    @abstractmethod
    def _initialize_behavior_telemetry(self) -> None: ...

    def _tracker_the_initializer_holds_with(
        self, decorator: "BaseSecurityDecorator | None"
    ) -> "BehaviorTracker | None":
        if decorator is None:
            return (
                self.behavior_tracker
                if self.guard_decorator is None
                else BehaviorTracker(self.config)
            )
        if self.enricher is None:
            return None
        return getattr(decorator, "behavior_tracker", None) or BehaviorTracker(
            self.config
        )

    def _pending_adoption(self) -> "tuple[BaseSecurityDecorator | None] | None":
        return self._decorator_adoption_pending

    def adopt_decorator(self, decorator: "BaseSecurityDecorator | None") -> None:
        """Bind a decorator given after construction. What can raise runs first, on
        the candidate, so a raise leaves the previous decorator bound and its
        state as it was. ``None`` takes the decorator away and gives the initializer
        its own tracker, as a construction without one does."""
        if decorator is not None:
            self._require_what_the_geo_handler_for_route_rules_needs(decorator)
            self.report_route_misconfigurations(decorator)
        tracker = self._tracker_the_initializer_holds_with(decorator)
        self.guard_decorator = decorator
        self.behavior_tracker = tracker
        if self.enricher is not None:
            self.enricher.use_behavior_tracker(tracker)
        self.inject_bound_ban_manager()
        self._build_geo_ip_handler_for_route_rules(decorator)
        self._decorator_adoption_pending = (decorator,)

    def complete_decorator_adoption(self) -> None:
        """Run the awaited steps ``adopt_decorator`` left pending: the Redis behavior
        tracking when the app's Redis is connected and the behavior telemetry when
        the agent is wired. A no-op when nothing is pending, and a raise leaves it
        pending so the next call retries."""
        if self._decorator_adoption_pending is None:
            return
        with self._decorator_adoption_lock:
            pending = self._pending_adoption()
            if pending is None:
                return
            scope = app_scope_of(self.config)
            with in_app_scope(scope):
                if scope.redis_handler is not None:
                    self._initialize_behavior_tracking_on_redis(scope.redis_handler)
                if self.composite_handler is not None:
                    self._initialize_behavior_telemetry()
            if self._pending_adoption() is pending:
                self._decorator_adoption_pending = None
