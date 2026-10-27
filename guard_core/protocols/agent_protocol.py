from datetime import datetime
from typing import Protocol, TypeAlias, runtime_checkable

from guard_core.protocols.redis_protocol import RedisHandlerProtocol

JsonValue: TypeAlias = (
    str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)


@runtime_checkable
class DynamicRulesProtocol(Protocol):
    """The dynamic-rules answer an agent hands the engine: the fields it reads.

    WHAT: a read-only view of one rule set (identity, expiry, bans, countries,
    rate limits, cloud providers, user agents, patterns, feature overrides and
    emergency mode).
    WHEN: ``AgentHandlerProtocol.get_dynamic_rules`` returns it on every rule
    poll; the engine validates it, applies it and stores it as current rules.
    HOW: ``guard_core.models.DynamicRules`` and guard-agent's own
    ``DynamicRules`` satisfy it as they are.
    """

    @property
    def rule_id(self) -> str: ...

    @property
    def version(self) -> int: ...

    @property
    def timestamp(self) -> datetime: ...

    @property
    def expires_at(self) -> datetime | None: ...

    @property
    def ttl(self) -> int: ...

    @property
    def ip_blacklist(self) -> list[str]: ...

    @property
    def ip_whitelist(self) -> list[str]: ...

    @property
    def ip_ban_duration(self) -> int: ...

    @property
    def blocked_countries(self) -> list[str]: ...

    @property
    def whitelist_countries(self) -> list[str]: ...

    @property
    def global_rate_limit(self) -> int | None: ...

    @property
    def global_rate_window(self) -> int | None: ...

    @property
    def endpoint_rate_limits(self) -> dict[str, tuple[int, int]]: ...

    @property
    def blocked_cloud_providers(self) -> set[str]: ...

    @property
    def blocked_user_agents(self) -> list[str]: ...

    @property
    def suspicious_patterns(self) -> list[str]: ...

    @property
    def enable_penetration_detection(self) -> bool | None: ...

    @property
    def enable_ip_banning(self) -> bool | None: ...

    @property
    def enable_rate_limiting(self) -> bool | None: ...

    @property
    def auto_ban_threshold(self) -> int | None: ...

    @property
    def auto_ban_duration(self) -> int | None: ...

    @property
    def enable_rate_limit_auto_ban(self) -> bool | None: ...

    @property
    def emergency_mode(self) -> bool: ...

    @property
    def emergency_whitelist(self) -> list[str]: ...

    @property
    def emergency_whitelist_only(self) -> bool: ...


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

    async def get_dynamic_rules(self) -> DynamicRulesProtocol | None:
        """Return the latest dynamic rules, or ``None`` if none are available."""
        ...

    async def health_check(self) -> bool:
        """Return ``True`` when the agent can reach its collector."""
        ...

    def get_stats(self) -> dict[str, JsonValue]:
        """Return the handler's counters as a JSON-shaped mapping."""
        ...
