from typing import Any, Protocol, TypeAlias, runtime_checkable

from guard_core.protocols.redis_protocol import RedisHandlerProtocol

JsonValue: TypeAlias = (
    str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)


@runtime_checkable
class AgentHandlerProtocol(Protocol):
    """Telemetry sink that ships security events and metrics off-box.

    WHAT: the bridge between the engine and a collector (the SaaS via
    guard-agent): it buffers events/metrics and pulls dynamic rules back.
    WHEN: the middleware calls ``send_event``/``send_metric`` per request when
    an agent is configured; ``start``/``stop`` bound its background lifecycle.
    HOW: implement non-blocking, fire-and-forget sends (buffer and flush rather
    than block the request); never let a transport error reach the caller.
    """

    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        """Attach the shared Redis backend used for cross-worker buffering."""
        ...

    async def send_event(self, event: object) -> None:
        """Enqueue a security event for delivery. Must not block or raise."""
        ...

    async def send_metric(self, metric: object) -> None:
        """Enqueue a metric for delivery. Must not block or raise."""
        ...

    async def start(self) -> None:
        """Start background buffering/flush and rule-sync loops."""
        ...

    async def stop(self) -> None:
        """Stop background loops and release resources. Must be idempotent."""
        ...

    async def flush_buffer(self) -> None:
        """Force an immediate send of any buffered events and metrics."""
        ...

    async def get_dynamic_rules(self) -> Any | None:
        """Return the latest dynamic rules, or ``None`` if none are available."""
        ...

    async def health_check(self) -> bool:
        """Return ``True`` when the agent can reach its collector."""
        ...

    def get_stats(self) -> dict[str, JsonValue]:
        """Return the handler's counters as a JSON-shaped mapping."""
        ...
