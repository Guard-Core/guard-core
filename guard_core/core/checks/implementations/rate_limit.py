from collections.abc import Collection
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any, ClassVar, NamedTuple

from guard_core._redis_enablement import redis_is_configured
from guard_core._utils.agent_events import agent_receives_events
from guard_core._utils.ip_extraction import (
    MALFORMED_FORWARDED_FOR_PREFIX,
    _client_identity,
)
from guard_core._utils.request_logging import redact_endpoint_for_display
from guard_core._utils.rule_attribution import rate_limit_attribution
from guard_core.core.checks._ban_flow import BanFlow
from guard_core.core.checks._pending_ban import PendingBan, resolve_pending_ban
from guard_core.core.checks._rate_limit_ban_first import (
    defer_rate_limit,
    finish_tiers,
)
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.endpoint_limit_keys import EndpointLimitKeyMap
from guard_core.core.checks.helpers import (
    _increment_suspicious_counts,
    _ip_strike_counts,
    _log_exception_safely,
    _try_threshold_ban,
    emit_decorator_event,
    emit_rate_limit_event,
    get_guard_decorator,
    route_config_applies,
)
from guard_core.core.checks.route_prefixes import warn_unmatched_endpoint_keys
from guard_core.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_DYNAMIC_RULE_VIOLATION,
)
from guard_core.decorators.base import RouteConfig
from guard_core.handlers.cors_handler import ALLOWED_PREFLIGHT_REQUEST_HEADER
from guard_core.handlers.ratelimit_handler import (
    RateLimitBlock,
    RateLimitTier,
    forget_shared_violations,
    record_shared_violation,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

if TYPE_CHECKING:
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol


_non_ip_ban_refusal_logged = False


def _is_ip_address(identity: str) -> bool:
    if identity.startswith(MALFORMED_FORWARDED_FOR_PREFIX):
        return True
    try:
        ip_address(identity)
    except ValueError:
        return False
    return True


def _is_cors_preflight(request: GuardRequest) -> bool:
    if request.method.upper() != "OPTIONS":
        return False
    names = {name.lower() for name in request.headers.keys()}
    return ALLOWED_PREFLIGHT_REQUEST_HEADER in names


def _route_rate_limit_configured(route_config: RouteConfig) -> bool:
    return route_config.rate_limit is not None or bool(route_config.geo_rate_limits)


def _rate_limit_applies(
    config: SecurityConfig,
    route_configs: Collection[RouteConfig] | None,
) -> bool:
    return (
        config.enable_rate_limiting
        or bool(config.endpoint_rate_limits)
        or route_config_applies(route_configs, _route_rate_limit_configured)
        or config.enable_dynamic_rules
    )


def _route_bucket_key(request: GuardRequest) -> str:
    # A pluggable route resolver can return a route config without a route id.
    route_id = getattr(request.state, "guard_route_id", None)
    return route_id if isinstance(route_id, str) and route_id else request.url_path


class _TierPlan(NamedTuple):
    tier: RateLimitTier
    event_type: str | None
    event_kwargs: dict[str, Any]
    trigger_info: str


class RateLimitCheck(SecurityCheck):
    defers_ban_read = True
    leaves_ban_pending = True
    container_fields: ClassVar[tuple[str, ...]] = ("endpoint_rate_limits",)

    def __init__(self, middleware: "GuardMiddlewareProtocol") -> None:
        super().__init__(middleware)
        from guard_core.handlers.ipban_handler import ip_ban_manager

        self.ip_ban_manager = ip_ban_manager
        self._endpoint_key_map: EndpointLimitKeyMap | None = None

    @property
    def check_name(self) -> str:
        return "rate_limit"

    def _current_endpoint_key_map(
        self, limits: dict[str, tuple[int, int]]
    ) -> EndpointLimitKeyMap:
        keys = limits.keys()
        key_map = self._endpoint_key_map
        if key_map is None or key_map.keys != keys:
            key_map = EndpointLimitKeyMap(
                keys, getattr(self.middleware, "resolve_route", None)
            )
            self._endpoint_key_map = key_map
            warn_unmatched_endpoint_keys(self.middleware, key_map.unresolved)
        return key_map

    @property
    def needs_route_identity(self) -> bool:
        limits = self.config.endpoint_rate_limits
        if not limits:
            return False
        return bool(self._current_endpoint_key_map(limits).by_identity)

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return _rate_limit_applies(config, route_configs)

    async def _send_rate_limit_event(
        self,
        request: GuardRequest,
        event_type: str,
        event_kwargs: dict[str, Any],
        attribution: dict[str, Any],
    ) -> None:
        decorator_type = event_kwargs.get("decorator_type")
        reason = str(event_kwargs.get("reason", ""))

        if decorator_type == "rate_limiting":
            await emit_rate_limit_event(
                self.middleware,
                request,
                event_type=event_type,
                limit=event_kwargs["rate_limit"],
                window=event_kwargs["window"],
                reason=reason,
                passive_mode=self.config.passive_mode,
            )
            return

        if decorator_type == "geo_rate_limiting":
            metadata = {
                key: value
                for key, value in event_kwargs.items()
                if key not in {"reason", "decorator_type"}
            }
            await emit_decorator_event(
                self.middleware,
                request,
                event_type=event_type,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason=reason,
                decorator_type=decorator_type,
                **metadata,
            )
            return

        await self.middleware.event_bus.send_middleware_event(
            event_type=event_type,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            **event_kwargs,
            **attribution,
        )

    async def _record_rate_limit_autoban(
        self, request: GuardRequest, client_ip: str, trigger_info: str
    ) -> None:
        if not self.config.enable_rate_limit_auto_ban:
            return
        if not _is_ip_address(client_ip):
            self._log_non_ip_ban_refusal(client_ip)
            return
        identity = self._strike_identity(request, client_ip)
        try:
            _increment_suspicious_counts(self.middleware, identity, "rate_limit")
            shared = await self._shared_violation_counts(identity)
            banned = await _try_threshold_ban(
                request,
                self.config,
                self.ip_ban_manager,
                self.middleware,
                identity,
                trigger_info,
                self.logger,
                self.check_name,
                self.config.muted_check_logs,
                ("rate_limit",),
                reason="rate_limit_exceeded",
                ip_counts=shared
                if shared is not None
                else _ip_strike_counts(self.middleware, identity),
            )
            if banned and shared is not None:
                await forget_shared_violations(self._shared_redis(), identity)
        except Exception:
            _log_exception_safely(
                self.logger, "rate-limit auto-ban failed for %s", client_ip
            )

    def _strike_identity(self, request: GuardRequest, client_ip: str) -> str:
        if ":" not in client_ip:
            return client_ip
        entry = (
            getattr(request.state, "whitelist_entry", None)
            if self.config.whitelist_access_only
            else None
        )
        return _client_identity(client_ip, self.config.ipv6_prefix_length, entry)

    def _shared_redis(self) -> Any:
        if not redis_is_configured(self.config):
            return None
        return getattr(self.middleware.rate_limit_handler, "redis_handler", None)

    async def _shared_violation_counts(self, client_ip: str) -> dict[str, int] | None:
        redis_handler = self._shared_redis()
        if not redis_handler:
            return None
        try:
            return {
                "rate_limit": await record_shared_violation(redis_handler, client_ip)
            }
        except Exception as error:
            self.logger.warning(
                "Shared rate-limit violation counter unavailable, counting this "
                "violation in this process only: %s",
                error,
            )
            return None

    def _log_non_ip_ban_refusal(self, identity: str) -> None:
        global _non_ip_ban_refusal_logged
        if _non_ip_ban_refusal_logged:
            return
        _non_ip_ban_refusal_logged = True
        self.logger.warning(
            "Not auto-banning %r: it is not an IP address, so every client with "
            "this identity shares one rate-limit counter and cannot be banned. If "
            'the app is served over a Unix socket add "unix" to trusted_proxies. '
            "This is logged once.",
            identity,
        )

    def _endpoint_plans(self, request: GuardRequest) -> list[_TierPlan]:
        limits = self.config.endpoint_rate_limits
        if not limits:
            return []
        identity = getattr(request.state, "guard_route_identity", None)
        return [
            self._endpoint_plan(key, limits[key])
            for key in self._current_endpoint_key_map(limits).matched_keys(
                identity, request.url_path
            )
        ]

    def _endpoint_plan(self, endpoint_key: str, limit: tuple[int, int]) -> _TierPlan:
        rate_limit, window = limit
        safe_endpoint = redact_endpoint_for_display(
            endpoint_key,
            self.config.log_sensitive_params,
            self.config.log_sensitive_body_fields,
            self.config.log_sensitive_headers,
        )
        reason = (
            f"Endpoint-specific rate limit exceeded: {rate_limit} "
            f"requests per {window}s for {safe_endpoint}"
        )
        return _TierPlan(
            RateLimitTier("endpoint", rate_limit, window, endpoint_key),
            EVENT_DYNAMIC_RULE_VIOLATION,
            {
                "reason": reason,
                "rule_type": "endpoint_rate_limit",
                "endpoint": safe_endpoint,
                "rate_limit": rate_limit,
                "window": window,
            },
            reason,
        )

    def _route_plan(self, request: GuardRequest, route_config: Any) -> _TierPlan | None:
        if not route_config or route_config.rate_limit is None:
            return None

        window = route_config.rate_limit_window or 60
        reason = (
            f"Route-specific rate limit exceeded: "
            f"{route_config.rate_limit} requests per {window}s"
        )
        return _TierPlan(
            RateLimitTier(
                "route", route_config.rate_limit, window, _route_bucket_key(request)
            ),
            EVENT_DECORATOR_VIOLATION,
            {
                "reason": reason,
                "decorator_type": "rate_limiting",
                "violation_type": "rate_limit",
                "rate_limit": route_config.rate_limit,
                "window": window,
            },
            reason,
        )

    def _geo_plan(
        self, request: GuardRequest, client_ip: str, route_config: Any
    ) -> _TierPlan | None:
        if not route_config or not route_config.geo_rate_limits:
            return None

        geo_handler = self.middleware.geo_ip_handler
        if not geo_handler:
            return None

        country = geo_handler.get_country(client_ip)
        limits = route_config.geo_rate_limits

        if country and country in limits:
            rate_limit, window = limits[country]
        elif "*" in limits:
            rate_limit, window = limits["*"]
        else:
            return None

        reason = (
            f"Geo rate limit exceeded for {country or 'unknown'}: "
            f"{rate_limit} requests per {window}s"
        )
        return _TierPlan(
            RateLimitTier("geo", rate_limit, window, _route_bucket_key(request)),
            EVENT_DECORATOR_VIOLATION,
            {
                "reason": reason,
                "decorator_type": "geo_rate_limiting",
                "violation_type": "geo_rate_limit",
                "rate_limit": rate_limit,
                "window": window,
            },
            reason,
        )

    def _global_plan(self) -> _TierPlan | None:
        if not self.config.enable_rate_limiting:
            return None
        return _TierPlan(
            RateLimitTier(
                "global", self.config.rate_limit, self.config.rate_limit_window
            ),
            None,
            {},
            "Global rate limit exceeded",
        )

    def _tier_plans(
        self, request: GuardRequest, client_ip: str, route_config: Any
    ) -> list[_TierPlan]:
        candidates = [
            *self._endpoint_plans(request),
            self._route_plan(request, route_config),
            self._geo_plan(request, client_ip, route_config),
            self._global_plan(),
        ]
        return [plan for plan in candidates if plan is not None]

    def _decorator_sends_rate_limited(
        self, request: GuardRequest, plan: _TierPlan
    ) -> bool:
        return (
            plan.event_kwargs.get("decorator_type") == "rate_limiting"
            and get_guard_decorator(self.middleware, request) is not None
        )

    async def _report_block(
        self,
        request: GuardRequest,
        client_ip: str,
        plan: _TierPlan,
        block: RateLimitBlock,
    ) -> None:
        try:
            limiter_agent = self.middleware.rate_limit_handler.agent_handler
        except AttributeError:
            limiter_agent = None
        attribution = (
            rate_limit_attribution(plan.tier.kind, plan.tier.bucket)
            if agent_receives_events(self.middleware.event_bus, self.config)
            or limiter_agent
            else {}
        )
        if plan.event_type is not None:
            await self._send_rate_limit_event(
                request, plan.event_type, plan.event_kwargs, attribution
            )
        if self._decorator_sends_rate_limited(request, plan):
            return
        await self.middleware.rate_limit_handler.report_rate_limit_block(
            request, client_ip, block, plan.tier, self.config, attribution
        )

    def _skips_rate_limiting(self, request: GuardRequest, route_config: Any) -> bool:
        state = request.state
        if (
            getattr(state, "is_whitelisted", False)
            or getattr(state, "is_exempt", False) is True
        ):
            return True
        if _is_cors_preflight(request):
            return True
        return bool(
            route_config
            and self.middleware.route_resolver.should_bypass_check(
                "rate_limit", route_config
            )
        )

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        state = request.state
        client_ip = getattr(state, "client_ip", None)
        route_config = getattr(state, "route_config", None)
        plans = (
            self._tier_plans(request, client_ip, route_config)
            if client_ip and not self._skips_rate_limiting(request, route_config)
            else []
        )
        flow = getattr(state, "guard_ban_flow", None)
        pending = flow.pending if isinstance(flow, BanFlow) else None
        if defer_rate_limit(self, pending, client_ip, plans):
            return None
        if isinstance(pending, PendingBan):
            banned = await resolve_pending_ban(request)
            if banned is not None:
                return banned
        if client_ip is None or not plans:
            return None
        return await finish_tiers(self, request, client_ip, plans, None)
