from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol

from guard_core.core.events.event_types import EventFilter

if TYPE_CHECKING:
    from guard_core.protocols.agent_protocol import (
        AgentHandlerProtocol,
        DynamicRulesProtocol,
        JsonValue,
    )
    from guard_core.protocols.redis_protocol import RedisHandlerProtocol

logger = logging.getLogger("guard_core")


class EventEnrichment(Protocol):
    async def enrich_event(self, event: object) -> None: ...

    async def enrich_metric(self, metric: object) -> None: ...


class CompositeAgentHandler:
    def __init__(
        self,
        handlers: list[AgentHandlerProtocol],
        event_filter: EventFilter | None = None,
        enricher: EventEnrichment | None = None,
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

    async def send_event(self, event: object) -> None:
        event_type = getattr(event, "event_type", None)
        if event_type and not self._event_filter.is_event_allowed(event_type):
            return
        if self._enricher is not None:
            await self._enricher.enrich_event(event)
        for handler in self._handlers:
            try:
                await handler.send_event(event)
            except Exception:
                logger.exception("handler.send_event failed")

    async def send_metric(self, metric: object) -> None:
        metric_type = getattr(metric, "metric_type", None)
        if metric_type and not self._event_filter.is_metric_allowed(metric_type):
            return
        if self._enricher is not None:
            await self._enricher.enrich_metric(metric)
        for handler in self._handlers:
            try:
                await handler.send_metric(metric)
            except Exception:
                logger.exception("handler.send_metric failed")

    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        for handler in self._handlers:
            try:
                await handler.initialize_redis(redis_handler)
            except Exception:
                logger.exception("handler.initialize_redis failed")

    async def start(self) -> None:
        self._failed_handlers = []
        for handler in self._handlers:
            handler_name = type(handler).__name__
            try:
                await handler.start()
            except Exception as e:
                self._failed_handlers.append(handler_name)
                logger.error("Handler %s failed to start: %s", handler_name, e)
        self._started = True

    async def stop(self) -> None:
        for handler in self._handlers:
            try:
                await handler.stop()
            except Exception:
                logger.exception("handler.stop failed")

    async def flush_buffer(self) -> None:
        for handler in self._handlers:
            try:
                await handler.flush_buffer()
            except Exception:
                logger.exception("handler.flush_buffer failed")

    async def get_dynamic_rules(self) -> DynamicRulesProtocol | None:
        for handler in self._handlers:
            try:
                result: DynamicRulesProtocol | None = await handler.get_dynamic_rules()
                if result is not None:
                    return result
            except Exception:
                logger.exception("handler.get_dynamic_rules failed")
        return None

    async def get_status(self) -> object | None:
        for handler in self._handlers:
            get_status = getattr(handler, "get_status", None)
            if get_status is None:
                continue
            try:
                status: object = await get_status()
                return status
            except Exception:
                logger.exception("handler.get_status failed")
        return None

    def get_stats(self) -> dict[str, JsonValue]:
        stats: dict[str, JsonValue] = {}
        for handler in self._handlers:
            get_stats = getattr(handler, "get_stats", None)
            if get_stats is None:
                continue
            try:
                stats.update(get_stats())
            except Exception:
                logger.exception("handler.get_stats failed")
        return stats

    async def health_check(self) -> bool:
        if not self._handlers:
            return True
        results = []
        for handler in self._handlers:
            try:
                results.append(await handler.health_check())
            except Exception:
                logger.exception("handler.health_check failed")
                results.append(False)
        return all(results)
