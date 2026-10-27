from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from guard_core.protocols.response_protocol import GuardResponse, GuardResponseFactory

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.decorators.base import RouteConfig
    from guard_core.sync.handlers.cloud_handler import CloudManager
    from guard_core.sync.handlers.ratelimit_handler import (
        RateLimitBlock,
        RateLimitTier,
        RateLimitVerdict,
    )
    from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
    from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
    from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol
    from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class SyncRouteDecoratorRegistryProtocol(Protocol):
    """The route-decorator registry: the per-route configs and their revision."""

    @property
    def _route_configs(self) -> Mapping[str, RouteConfig]:
        """Every decorated route's config, keyed by route id."""
        ...

    @property
    def route_config_revision(self) -> int:
        """Changes whenever a route config is added or edited."""
        ...


class SyncRateLimitHandlerProtocol(Protocol):
    """The rate-limit handler the rate-limit check drives."""

    @property
    def redis_handler(self) -> SyncRedisHandlerProtocol | None:
        """The shared Redis backend, or ``None`` when rate limits are in memory."""
        ...

    @property
    def agent_handler(self) -> SyncAgentHandlerProtocol | None:
        """The telemetry agent the handler reports blocks to, or ``None``."""
        ...

    def check_rate_limit_tiers(
        self,
        request: SyncGuardRequest,
        client_ip: str,
        create_error_response: Callable[[int, str], GuardResponse],
        tiers: Sequence[RateLimitTier],
        config: SyncSecurityConfig | None = None,
        window_identity: str | None = None,
        verdict: RateLimitVerdict | None = None,
    ) -> RateLimitBlock | None:
        """Count the request against the tiers; the block it hit, or ``None``."""
        ...

    def report_rate_limit_block(
        self,
        request: SyncGuardRequest,
        client_ip: str,
        block: RateLimitBlock,
        tier: RateLimitTier,
        config: SyncSecurityConfig | None = None,
        attribution: dict[str, object] | None = None,
    ) -> None:
        """Report a rate-limit block to the agent."""
        ...


class SecurityEventBusProtocol(Protocol):
    """The event bus surface the checks send security events through."""

    @property
    def agent_handler(self) -> SyncAgentHandlerProtocol | None:
        """The telemetry agent the bus forwards events to, or ``None``."""
        ...

    def send_middleware_event(
        self,
        event_type: str,
        request: SyncGuardRequest,
        action_taken: str,
        reason: str,
        **kwargs: object,
    ) -> None:
        """Send one security event to the agent."""
        ...

    def send_https_violation_event(
        self, request: SyncGuardRequest, route_config: RouteConfig | None
    ) -> None:
        """Send the event for a request that required HTTPS."""
        ...

    def send_cloud_detection_events(
        self,
        request: SyncGuardRequest,
        client_ip: str,
        cloud_providers_to_check: list[str],
        route_config: RouteConfig | None,
        cloud_handler: CloudManager,
        passive_mode: bool,
        cloud_details: tuple[str, str] | None = None,
        attribution: dict[str, object] | None = None,
    ) -> None:
        """Send the events for a request from a blocked cloud provider."""
        ...


class RouteResolverProtocol(Protocol):
    """The per-route configuration resolver the checks ask."""

    def get_route_config(self, request: SyncGuardRequest) -> RouteConfig | None:
        """The request's route config, or ``None`` when it has none."""
        ...

    def should_bypass_check(
        self, check_name: str, route_config: RouteConfig | None
    ) -> bool:
        """True when the route bypasses the named check."""
        ...

    def get_cloud_providers_to_check(
        self, route_config: RouteConfig | None
    ) -> list[str] | None:
        """The cloud providers to block for the route, or ``None``."""
        ...


class ResponseFactoryProtocol(Protocol):
    """The engine response factory the checks read from the middleware."""

    @property
    def security_headers_manager(self) -> object:
        """The security-headers manager; readers check its type."""
        ...

    def create_https_redirect(self, request: SyncGuardRequest) -> GuardResponse:
        """Build the redirect to the HTTPS URL."""
        ...

    def apply_modifier(
        self, response: GuardResponse, request: SyncGuardRequest | None = None
    ) -> GuardResponse:
        """Run the configured response modifier over the response."""
        ...


@runtime_checkable
class SyncGuardMiddlewareProtocol(Protocol):
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

    config: SyncSecurityConfig
    logger: logging.Logger
    last_cloud_ip_refresh: int
    suspicious_request_counts: dict[str, dict[str, int]]

    @property
    def guard_decorator(self) -> SyncRouteDecoratorRegistryProtocol | None:
        """The route-decorator registry, or ``None`` when no route is decorated.

        The engine reads it with a ``None`` default, so a middleware without the
        attribute works and has no route configs.
        """
        ...

    @property
    def event_bus(self) -> SecurityEventBusProtocol:
        """The event bus that fans out security events to subscribers."""
        ...

    @property
    def route_resolver(self) -> RouteResolverProtocol:
        """Resolves the effective per-route security configuration."""
        ...

    @property
    def response_factory(self) -> ResponseFactoryProtocol | None:
        """Factory for the engine's outgoing responses, or ``None`` for a host
        (the WebSocket detection middleware) that builds none."""
        ...

    @property
    def rate_limit_handler(self) -> SyncRateLimitHandlerProtocol | None:
        """The rate-limit handler, or ``None`` when rate limiting is disabled."""
        ...

    @property
    def agent_handler(self) -> SyncAgentHandlerProtocol | None:
        """The telemetry agent handler, or ``None`` when no agent is configured."""
        ...

    @property
    def geo_ip_handler(self) -> SyncGeoIPHandler | None:
        """The geo-IP handler, or ``None`` when geo features are disabled."""
        ...

    @property
    def guard_response_factory(self) -> GuardResponseFactory | None:
        """Factory producing ``GuardResponse`` objects for denied requests."""
        ...

    def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        """Build the error response for a denied request.

        Uses any configured custom message for ``status_code``, falling back to
        ``default_message``.
        """
        ...

    def refresh_cloud_ip_ranges(self) -> None:
        """Refresh cached cloud-provider IP ranges and update the refresh stamp."""
        ...
