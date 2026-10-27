from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from guard_core.protocols.response_protocol import GuardResponse, GuardResponseFactory

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence

    from guard_core.decorators.base import RouteConfig
    from guard_core.handlers.ratelimit_handler import (
        RateLimitBlock,
        RateLimitTier,
        RateLimitVerdict,
    )
    from guard_core.models import SecurityConfig
    from guard_core.protocols.agent_protocol import AgentHandlerProtocol
    from guard_core.protocols.redis_protocol import RedisHandlerProtocol
    from guard_core.protocols.request_protocol import GuardRequest


class RouteDecoratorRegistryProtocol(Protocol):
    """The route-decorator registry: the per-route configs and their revision."""

    @property
    def _route_configs(self) -> Mapping[str, RouteConfig]:
        """Every decorated route's config, keyed by route id."""
        ...

    @property
    def route_config_revision(self) -> int:
        """Changes whenever a route config is added or edited."""
        ...


class RateLimitHandlerProtocol(Protocol):
    """The rate-limit handler the rate-limit check drives."""

    @property
    def redis_handler(self) -> RedisHandlerProtocol | None:
        """The shared Redis backend, or ``None`` when rate limits are in memory."""
        ...

    @property
    def agent_handler(self) -> AgentHandlerProtocol | None:
        """The telemetry agent the handler reports blocks to, or ``None``."""
        ...

    async def check_rate_limit_tiers(
        self,
        request: GuardRequest,
        client_ip: str,
        create_error_response: Callable[[int, str], Awaitable[GuardResponse]],
        tiers: Sequence[RateLimitTier],
        config: SecurityConfig | None = None,
        window_identity: str | None = None,
        verdict: RateLimitVerdict | None = None,
    ) -> RateLimitBlock | None:
        """Count the request against the tiers; the block it hit, or ``None``."""
        ...

    async def report_rate_limit_block(
        self,
        request: GuardRequest,
        client_ip: str,
        block: RateLimitBlock,
        tier: RateLimitTier,
        config: SecurityConfig | None = None,
        attribution: dict[str, object] | None = None,
    ) -> None:
        """Report a rate-limit block to the agent."""
        ...


@runtime_checkable
class GuardMiddlewareProtocol(Protocol):
    """The middleware surface handlers and checks call back into.

    WHAT: the orchestrator that owns the resolved ``config`` and ``logger`` and
    exposes the shared handlers (event bus, route resolver, response factory,
    rate-limit/agent/geo-IP handlers) plus cross-request state.
    WHEN: passed to checks and decorators so they can build responses and reach
    shared services without importing the concrete middleware class.
    HOW: implement on the host middleware. The attributes ``config``,
    ``logger``, ``last_cloud_ip_refresh`` (epoch seconds of the last cloud-IP
    refresh) and ``suspicious_request_counts`` (per-IP suspicion tallies) are
    read directly; the handler properties may return ``None`` when a feature is
    disabled, so callers must guard for it. ``guard_decorator`` is the
    route-decorator registry the engine reads for per-route configs and their
    revision; ``None`` (or an absent attribute) means no route configs.
    """

    config: SecurityConfig
    logger: logging.Logger
    last_cloud_ip_refresh: int
    suspicious_request_counts: dict[str, dict[str, int]]

    @property
    def guard_decorator(self) -> RouteDecoratorRegistryProtocol | None:
        """The route-decorator registry, or ``None`` when no route is decorated.

        The engine reads it with a ``None`` default, so a middleware without the
        attribute works and has no route configs.
        """
        ...

    @property
    def event_bus(self) -> Any:
        """The event bus that fans out security events to subscribers."""
        ...

    @property
    def route_resolver(self) -> Any:
        """Resolves the effective per-route security configuration."""
        ...

    @property
    def response_factory(self) -> Any:
        """Factory for the engine's outgoing responses."""
        ...

    @property
    def rate_limit_handler(self) -> RateLimitHandlerProtocol | None:
        """The rate-limit handler, or ``None`` when rate limiting is disabled."""
        ...

    @property
    def agent_handler(self) -> AgentHandlerProtocol | None:
        """The telemetry agent handler, or ``None`` when no agent is configured."""
        ...

    @property
    def geo_ip_handler(self) -> Any:
        """The geo-IP handler, or ``None`` when geo features are disabled."""
        ...

    @property
    def guard_response_factory(self) -> GuardResponseFactory | None:
        """Factory producing ``GuardResponse`` objects for denied requests."""
        ...

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        """Build the error response for a denied request.

        Uses any configured custom message for ``status_code``, falling back to
        ``default_message``.
        """
        ...

    async def refresh_cloud_ip_ranges(self) -> None:
        """Refresh cached cloud-provider IP ranges and update the refresh stamp."""
        ...
