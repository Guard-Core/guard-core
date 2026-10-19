from __future__ import annotations

import logging
from typing import Any

from guard_core.sync.core.events.event_types import EventFilter

logger = logging.getLogger("guard_core")


class CompositeAgentHandler:
    def __init__(
        self,
        handlers: list[Any],
        event_filter: EventFilter | None = None,
        enricher: Any | None = None,
    ) -> None:
        self._handlers = handlers
        self._event_filter = event_filter or EventFilter()
        self._enricher = enricher
        self._started = False
        self._failed_handlers: list[str] = []

    @property
    def started(self) -> bool:
        return self._started

    @property
    def degraded(self) -> bool:
        return self._started and bool(self._failed_handlers)

    @property
    def failed_handlers(self) -> list[str]:
        return list(self._failed_handlers)

    def send_event(self, event: Any) -> None:
        event_type = getattr(event, "event_type", None)
        if event_type and not self._event_filter.is_event_allowed(event_type):
            return
        if self._enricher is not None:
            self._enricher.enrich_event(event)
        for handler in self._handlers:
            try:
                handler.send_event(event)
            except Exception:
                logger.exception("handler.send_event failed")

    def send_metric(self, metric: Any) -> None:
        metric_type = getattr(metric, "metric_type", None)
        if metric_type and not self._event_filter.is_metric_allowed(metric_type):
            return
        if self._enricher is not None:
            self._enricher.enrich_metric(metric)
        for handler in self._handlers:
            try:
                handler.send_metric(metric)
            except Exception:
                logger.exception("handler.send_metric failed")

    def initialize_redis(self, redis_handler: Any) -> None:
        for handler in self._handlers:
            try:
                handler.initialize_redis(redis_handler)
            except Exception:
                logger.exception("handler.initialize_redis failed")

    def start(self) -> None:
        self._failed_handlers = []
        for handler in self._handlers:
            handler_name = type(handler).__name__
            try:
                handler.start()
            except Exception as e:
                self._failed_handlers.append(handler_name)
                logger.error("Handler %s failed to start: %s", handler_name, e)
        self._started = True

    def stop(self) -> None:
        for handler in self._handlers:
            try:
                handler.stop()
            except Exception:
                logger.exception("handler.stop failed")

    def flush_buffer(self) -> None:
        for handler in self._handlers:
            try:
                handler.flush_buffer()
            except Exception:
                logger.exception("handler.flush_buffer failed")

    def get_dynamic_rules(self) -> Any | None:
        for handler in self._handlers:
            try:
                result = handler.get_dynamic_rules()
                if result is not None:
                    return result
            except Exception:
                logger.exception("handler.get_dynamic_rules failed")
        return None

    def get_status(self) -> Any | None:
        for handler in self._handlers:
            get_status = getattr(handler, "get_status", None)
            if get_status is None:
                continue
            try:
                return get_status()
            except Exception:
                logger.exception("handler.get_status failed")
        return None

    def health_check(self) -> bool:
        if not self._handlers:
            return True
        results = []
        for handler in self._handlers:
            try:
                results.append(handler.health_check())
            except Exception:
                logger.exception("handler.health_check failed")
                results.append(False)
        return all(results)
