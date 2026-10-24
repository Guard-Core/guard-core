from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from guard_core.protocols.response_protocol import GuardResponse

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig


@runtime_checkable
class SyncGuardMiddlewareProtocol(Protocol):
    """The middleware surface handlers and checks call back into.

    WHAT: the orchestrator that owns the resolved ``config`` and ``logger`` and
    exposes the shared handlers (event bus, route resolver, response factory,
    rate-limit/agent/geo-IP handlers) plus cross-request state.
    WHEN: passed to checks and decorators so they can build responses and reach
    shared services without importing the concrete middleware class.
    HOW: the blocking mirror of ``GuardMiddlewareProtocol``. The attributes
    ``config``, ``logger``, ``last_cloud_ip_refresh`` (epoch seconds of the
    last cloud-IP refresh) and ``suspicious_request_counts`` (per-IP suspicion
    tallies) are read directly; the handler properties may return ``None`` when
    a feature is disabled, so callers must guard for it. ``guard_decorator`` is
    the route-decorator registry the engine reads for per-route configs and their
    revision; ``None`` (or an absent attribute) means no route configs.
    """

    config: SyncSecurityConfig
    logger: logging.Logger
    last_cloud_ip_refresh: int
    suspicious_request_counts: dict[str, dict[str, int]]

    @property
    def guard_decorator(self) -> Any | None:
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
    def rate_limit_handler(self) -> Any:
        """The rate-limit handler, or ``None`` when rate limiting is disabled."""
        ...

    @property
    def agent_handler(self) -> Any:
        """The telemetry agent handler, or ``None`` when no agent is configured."""
        ...

    @property
    def geo_ip_handler(self) -> Any:
        """The geo-IP handler, or ``None`` when geo features are disabled."""
        ...

    @property
    def guard_response_factory(self) -> Any:
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
