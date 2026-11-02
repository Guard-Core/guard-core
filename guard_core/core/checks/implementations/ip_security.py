from ipaddress import ip_address
from typing import TYPE_CHECKING

from guard_core._utils.access_control import load_geo_database_for_route_rules
from guard_core._utils.agent_events import agent_receives_events
from guard_core._utils.ip_extraction import (
    _is_trusted_proxy,
    forwarded_for_addresses,
)
from guard_core._utils.nat64 import nat64_table_of
from guard_core._utils.rule_attribution import (
    ban_attribution,
    cached_ban_stamp,
    country_attribution,
)
from guard_core._utils.rule_attribution_shared import Stamp
from guard_core._utils.whitelist_match import most_specific_whitelist_entry
from guard_core.core.checks._ban_flow import BanFlow
from guard_core.core.checks._ip_ban_read import (
    IpBanReadMixin,
    _route_denial_category,
    _route_overrides_ip_lists,
)
from guard_core.core.checks._ip_ban_read import (
    _route_blacklist_matches as _route_blacklist_matches,
)
from guard_core.core.checks._pending_ban import resolve_pending_ban
from guard_core.core.checks.helpers import (
    check_country_access,
    check_route_ip_access,
    emit_access_denied_event,
    report_hostile_signal,
)
from guard_core.core.events.event_types import (
    EVENT_COUNTRY_BLOCKED,
    EVENT_DECORATOR_VIOLATION,
    EVENT_GEO_LOOKUP_FAILED,
    EVENT_IP_BLOCKED,
)
from guard_core.decorators.base import RouteConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import (
    IpAccessResult,
    _ip_in_list,
    check_ip_access,
    log_activity,
)

if TYPE_CHECKING:
    from guard_core._geo_handler_for_tree import GeoIPHandlerOfThisTree
    from guard_core.models import SecurityConfig


def _is_private_peer_without_forwarded_for(
    request: GuardRequest, client_ip: str
) -> bool:
    if request.headers.get("X-Forwarded-For"):
        return False
    try:
        return not ip_address(client_ip).is_global
    except ValueError:
        return False


def _route_country_whitelist_matched(
    client_ip: str,
    route_config: RouteConfig | None,
    geo_ip_handler: "GeoIPHandlerOfThisTree | None",
) -> bool:
    if not route_config:
        return False
    return check_country_access(client_ip, route_config, geo_ip_handler) is True


def _resolve_is_whitelisted(
    client_ip: str,
    route_config: RouteConfig | None,
    config: "SecurityConfig",
    is_allowed: bool,
    skip_ip_lists: bool,
) -> bool:
    return is_allowed and bool(config.whitelist) and not skip_ip_lists


def _resolve_is_exempt(
    client_ip: str, config: "SecurityConfig", is_allowed: bool, skip_ip_lists: bool
) -> bool:
    if not is_allowed or skip_ip_lists or not config.exempt_ips:
        return False
    try:
        client_ip_addr = ip_address(client_ip)
    except ValueError:
        return False
    return _ip_in_list(
        client_ip_addr, client_ip, config.exempt_ips, nat64_table_of(config)
    )


def _classify_route_ip_denial(
    route_config: RouteConfig,
    geo_ip_handler: "GeoIPHandlerOfThisTree | None",
    client_ip: str,
    country_result: bool | None,
) -> tuple[str, str]:
    if (
        country_result is not False
        or route_config.ip_whitelist
        or route_config.ip_blacklist
    ):
        return "access_control", "ip_restriction"
    if route_config.blocked_countries and geo_ip_handler is not None:
        country = geo_ip_handler.get_country(client_ip)
        if country in route_config.blocked_countries:
            return "block_countries", "country_restriction"
    return "allow_countries", "country_restriction"


class IpSecurityCheck(IpBanReadMixin):
    enforced_on_excluded_paths = True
    leaves_ban_pending = True

    @property
    def check_name(self) -> str:
        return "ip_security"

    async def banned_response(
        self, request: GuardRequest, client_ip: str
    ) -> GuardResponse | None:
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Banned IP attempted access: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            on_block=self.config.on_block,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )

        attribution: Stamp = {}
        try:
            agent_handler = self.middleware.event_bus.agent_handler
        except AttributeError:
            agent_handler = None
        if agent_handler and self.config.agent_enable_events:
            held = cached_ban_stamp(self.config, client_ip, self.ip_ban_manager)
            attribution = (
                held
                if held is not None
                else await ban_attribution(self.config, client_ip, self.ip_ban_manager)
            )
        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_IP_BLOCKED,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"Banned IP attempted access: {client_ip}",
            ip_address=client_ip,
            filter_type="banned",
            **attribution,
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=403,
                default_message="IP address banned",
            )

        return None

    async def _check_route_ip_restrictions(
        self, request: GuardRequest, client_ip: str, route_config: RouteConfig
    ) -> GuardResponse | None:
        route_allowed = await check_route_ip_access(
            client_ip, route_config, self.middleware, nat64_table_of(self.config)
        )

        if route_allowed is None or route_allowed:
            return None

        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"IP not allowed by route config: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            on_block=self.config.on_block,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )

        country_result = check_country_access(
            client_ip, route_config, self.middleware.geo_ip_handler
        )
        decorator_type, violation_type = _classify_route_ip_denial(
            route_config, self.middleware.geo_ip_handler, client_ip, country_result
        )

        await emit_access_denied_event(
            self.middleware,
            request,
            event_type=EVENT_DECORATOR_VIOLATION,
            reason=f"IP {client_ip} blocked",
            decorator_type=decorator_type,
            passive_mode=self.config.passive_mode,
            violation_type=violation_type,
        )

        route_denial_category = _route_denial_category(
            route_config, decorator_type, client_ip, nat64_table_of(self.config)
        )
        await report_hostile_signal(
            self,
            request,
            route_denial_category,
            f"IP not allowed by route config: {client_ip}",
            "ip_restriction",
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=403,
                default_message="Forbidden",
            )

        return None

    async def _resolve_global_ip_access(
        self,
        request: GuardRequest,
        client_ip: str,
        route_config: RouteConfig | None,
    ) -> tuple[IpAccessResult, bool, bool]:
        route_overrides_whitelist = _route_overrides_ip_lists(route_config)
        if route_config and (
            route_config.blocked_countries or route_config.whitelist_countries
        ):
            await load_geo_database_for_route_rules(self.middleware)
        skip_countries = _route_country_whitelist_matched(
            client_ip, route_config, self.middleware.geo_ip_handler
        ) or (
            self.config.country_rules_exempt_private_peers
            and _is_private_peer_without_forwarded_for(request, client_ip)
        )

        access_result = await check_ip_access(
            client_ip,
            self.config,
            self.middleware.geo_ip_handler,
            skip_whitelist=route_overrides_whitelist,
            skip_countries=skip_countries,
            skip_clouds=True,
        )

        is_whitelisted = _resolve_is_whitelisted(
            client_ip,
            route_config,
            self.config,
            access_result.allowed,
            route_overrides_whitelist,
        )
        is_exempt = _resolve_is_exempt(
            client_ip, self.config, access_result.allowed, route_overrides_whitelist
        )
        return access_result, is_whitelisted, is_exempt

    async def _check_global_ip_restrictions(
        self,
        request: GuardRequest,
        client_ip: str,
        route_config: RouteConfig | None = None,
        *,
        escalate: bool = True,
        precomputed: tuple[IpAccessResult, bool, bool] | None = None,
    ) -> GuardResponse | None:
        access_result, is_whitelisted, is_exempt = (
            precomputed
            or await self._resolve_global_ip_access(request, client_ip, route_config)
        )
        state = request.state
        state.is_whitelisted = self._trusts_whitelist_match(
            request, client_ip, is_whitelisted
        )
        state.is_exempt = is_exempt

        if access_result.geo_failure:
            await self._report_geo_failure(request, client_ip, access_result)

        if access_result.allowed:
            return None

        return await self._deny_globally_blocked_ip(
            request, client_ip, access_result, escalate
        )

    async def _deny_globally_blocked_ip(
        self,
        request: GuardRequest,
        client_ip: str,
        access_result: IpAccessResult,
        escalate: bool,
    ) -> GuardResponse | None:
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"IP not allowed: {client_ip} - {access_result.reason}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            on_block=self.config.on_block,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )

        attribution: Stamp = {}
        if access_result.country_rule:
            attribution = await self._send_country_blocked_event(
                request, client_ip, access_result
            )

        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_IP_BLOCKED,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=access_result.reason,
            ip_address=client_ip,
            filter_type="global",
            **(
                {"country": access_result.country} if access_result.country_rule else {}
            ),
            **attribution,
        )
        if not self.config.passive_mode:
            if escalate:
                await report_hostile_signal(
                    self,
                    request,
                    access_result.denial_category,
                    access_result.reason,
                    "ip_blocked",
                )
            return await self.middleware.create_error_response(
                status_code=access_result.status_code,
                default_message="Malformed forwarded address"
                if access_result.status_code == 400
                else "Forbidden",
            )

        return None

    def _trusts_whitelist_match(
        self, request: GuardRequest, client_ip: str, is_whitelisted: bool
    ) -> bool:
        if not (is_whitelisted and self.config.whitelist_access_only):
            return is_whitelisted
        request.state.whitelist_entry = most_specific_whitelist_entry(
            ip_address(client_ip),
            self.config.whitelist or (),
            nat64_table_of(self.config),
        )
        return False

    async def _report_geo_failure(
        self, request: GuardRequest, client_ip: str, access_result: IpAccessResult
    ) -> None:
        denied = not access_result.allowed
        self.logger.warning(
            "GeoIP lookup failed (%s) for %s: %s",
            access_result.geo_failure,
            client_ip,
            "the request is denied (fail_secure)"
            if denied and not self.config.passive_mode
            else "the request is let through",
        )
        if denied and not self.config.passive_mode:
            action_taken = "request_blocked"
        else:
            action_taken = "logged_only" if denied else "request_allowed"
        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_GEO_LOOKUP_FAILED,
            request=request,
            action_taken=action_taken,
            reason=f"GeoIP lookup failed ({access_result.geo_failure})",
            ip_address=client_ip,
            error_type=access_result.geo_failure,
        )

    async def _send_country_blocked_event(
        self, request: GuardRequest, client_ip: str, access_result: IpAccessResult
    ) -> Stamp:
        """Send country_blocked and return the rule attribution it carried (empty
        when no agent consumes events), for the ip_blocked event that follows."""
        attribution = (
            country_attribution(
                self.config, access_result.country_rule, access_result.country
            )
            if agent_receives_events(self.middleware.event_bus, self.config)
            else {}
        )
        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_COUNTRY_BLOCKED,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=access_result.reason,
            ip_address=client_ip,
            country=access_result.country,
            rule_type=access_result.country_rule,
            **attribution,
        )
        return attribution

    def _forwarded_for_claims_privileged_address(
        self, forwarded_for: str, route_config: RouteConfig | None
    ) -> bool:
        nat64 = nat64_table_of(self.config)
        for address in forwarded_for_addresses(forwarded_for, nat64):
            text = str(address)
            if (
                _is_trusted_proxy(text, self.config.trusted_proxies, nat64)
                or _ip_in_list(address, text, self.config.whitelist, nat64)
                or (
                    route_config is not None
                    and _ip_in_list(address, text, route_config.ip_whitelist, nat64)
                )
            ):
                return True
        return False

    async def _count_ip_spoofing(
        self, request: GuardRequest, route_config: RouteConfig | None = None
    ) -> GuardResponse | None:
        state = request.state
        forwarded_for = getattr(state, "untrusted_forwarded_for", None)
        if not self.config.ban_on_hostile_signals or not isinstance(forwarded_for, str):
            return None
        client_ip = getattr(state, "client_ip", None)
        if not client_ip or not self._forwarded_for_claims_privileged_address(
            forwarded_for, self._route_config_of(state, route_config)
        ):
            return None
        flow = getattr(state, "guard_ban_flow", None)
        if isinstance(flow, BanFlow) and flow.pending is not None:
            banned = await resolve_pending_ban(request, "ip_spoofing")
            if banned is not None:
                return banned
        elif await self._banned_at_spoofing(request, client_ip):
            return None
        await report_hostile_signal(
            self,
            request,
            "ip_spoofing",
            "X-Forwarded-For forged by an untrusted peer",
        )
        return None

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        response = await self._enforce_ip_rules(request)
        spoofing = await self._count_ip_spoofing(request)
        return response if response is not None else spoofing

    async def _enforce_ip_rules(self, request: GuardRequest) -> GuardResponse | None:
        state = request.state
        client_ip = getattr(state, "client_ip", None)
        route_config = getattr(state, "route_config", None)
        if not client_ip:
            return None

        ban_response = await self._check_banned_ip(request, client_ip, route_config)
        if ban_response:
            return ban_response

        if getattr(state, "guard_exclusion_scoped", False) is True:
            return await self._check_global_ip_restrictions(
                request, client_ip, None, escalate=False
            )

        if self.middleware.route_resolver.should_bypass_check("ip", route_config):
            return None

        flow = getattr(state, "guard_ban_flow", None)
        staged = flow.denied_access if isinstance(flow, BanFlow) else None
        precomputed = staged if isinstance(staged, tuple) else None
        if route_config:
            precomputed = precomputed or await self._resolve_global_ip_access(
                request, client_ip, route_config
            )
            route_response = await self._check_route_ip_restrictions(
                request, client_ip, route_config
            )
            if route_response:
                return route_response

        return await self._check_global_ip_restrictions(
            request, client_ip, route_config, precomputed=precomputed
        )
