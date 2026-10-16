from ipaddress import ip_address
from typing import Any

from guard_core._utils.ip_extraction import (
    _is_trusted_proxy,
    forwarded_for_addresses,
)
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.helpers import (
    check_country_access,
    check_route_ip_access,
    emit_access_denied_event,
    report_hostile_signal,
)
from guard_core.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_IP_BLOCKED,
)
from guard_core.decorators.base import RouteConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import (
    IpAccessResult,
    _ip_in_list,
    allow_list_miss_category,
    check_ip_access,
    log_activity,
)


def _route_overrides_ip_lists(route_config: RouteConfig | None) -> bool:
    return bool(route_config and route_config.ip_whitelist)


def _route_country_whitelist_matched(
    client_ip: str, route_config: RouteConfig | None, geo_ip_handler: Any
) -> bool:
    if not route_config:
        return False
    return check_country_access(client_ip, route_config, geo_ip_handler) is True


def _resolve_is_whitelisted(
    client_ip: str,
    route_config: RouteConfig | None,
    config: Any,
    is_allowed: bool,
    skip_ip_lists: bool,
) -> bool:
    return is_allowed and bool(config.whitelist) and not skip_ip_lists


def _resolve_is_exempt(
    client_ip: str, config: Any, is_allowed: bool, skip_ip_lists: bool
) -> bool:
    if not is_allowed or skip_ip_lists or not config.exempt_ips:
        return False
    try:
        client_ip_addr = ip_address(client_ip)
    except ValueError:
        return False
    return _ip_in_list(client_ip_addr, client_ip, config.exempt_ips)


def _classify_route_ip_denial(
    route_config: RouteConfig,
    geo_ip_handler: Any,
    client_ip: str,
    country_result: bool | None,
) -> tuple[str, str]:
    if (
        country_result is not False
        or route_config.ip_whitelist
        or route_config.ip_blacklist
    ):
        return "access_control", "ip_restriction"
    if (
        route_config.blocked_countries
        and geo_ip_handler.get_country(client_ip) in route_config.blocked_countries
    ):
        return "block_countries", "country_restriction"
    return "allow_countries", "country_restriction"


def _route_blacklist_matches(route_config: RouteConfig, client_ip: str) -> bool:
    try:
        return _ip_in_list(
            ip_address(client_ip), client_ip, route_config.ip_blacklist or []
        )
    except ValueError:
        return False


def _route_denial_category(
    route_config: RouteConfig, decorator_type: str, client_ip: str
) -> str | None:
    if decorator_type == "block_countries":
        return "country"
    if decorator_type == "allow_countries":
        return allow_list_miss_category("country")
    if route_config.ip_whitelist:
        return allow_list_miss_category("ip_list")
    return "ip_list" if _route_blacklist_matches(route_config, client_ip) else None


class IpSecurityCheck(SecurityCheck):
    enforced_on_excluded_paths = True

    @property
    def check_name(self) -> str:
        return "ip_security"

    async def _check_banned_ip(
        self, request: GuardRequest, client_ip: str, route_config: RouteConfig | None
    ) -> GuardResponse | None:
        if self.middleware.route_resolver.should_bypass_check("ip_ban", route_config):
            return None

        if not await self.ip_ban_manager.is_ip_banned(client_ip):
            return None

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

        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_IP_BLOCKED,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"Banned IP attempted access: {client_ip}",
            ip_address=client_ip,
            filter_type="banned",
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
            client_ip, route_config, self.middleware
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
            route_config, decorator_type, client_ip
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
        client_ip: str,
        route_config: RouteConfig | None,
    ) -> tuple[IpAccessResult, bool, bool]:
        skip_ip_lists = _route_overrides_ip_lists(route_config)
        skip_countries = _route_country_whitelist_matched(
            client_ip, route_config, self.middleware.geo_ip_handler
        )

        access_result = await check_ip_access(
            client_ip,
            self.config,
            self.middleware.geo_ip_handler,
            skip_ip_lists=skip_ip_lists,
            skip_countries=skip_countries,
        )

        is_whitelisted = _resolve_is_whitelisted(
            client_ip, route_config, self.config, access_result.allowed, skip_ip_lists
        )
        is_exempt = _resolve_is_exempt(
            client_ip, self.config, access_result.allowed, skip_ip_lists
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
            precomputed or await self._resolve_global_ip_access(client_ip, route_config)
        )
        request.state.is_whitelisted = is_whitelisted
        request.state.is_exempt = is_exempt

        if access_result.allowed:
            return None

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

        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_IP_BLOCKED,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=access_result.reason,
            ip_address=client_ip,
            filter_type="global",
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
                status_code=403,
                default_message="Forbidden",
            )

        return None

    def _forwarded_for_claims_privileged_address(
        self, forwarded_for: str, route_config: RouteConfig | None
    ) -> bool:
        for address in forwarded_for_addresses(forwarded_for):
            text = str(address)
            if (
                _is_trusted_proxy(text, self.config.trusted_proxies)
                or _ip_in_list(address, text, self.config.whitelist)
                or (
                    route_config is not None
                    and _ip_in_list(address, text, route_config.ip_whitelist)
                )
            ):
                return True
        return False

    async def _count_ip_spoofing(
        self, request: GuardRequest, route_config: RouteConfig | None
    ) -> None:
        forwarded_for = getattr(request.state, "untrusted_forwarded_for", None)
        if not self.config.ban_on_hostile_signals or not isinstance(forwarded_for, str):
            return
        if self._forwarded_for_claims_privileged_address(forwarded_for, route_config):
            await report_hostile_signal(
                self,
                request,
                "ip_spoofing",
                "X-Forwarded-For forged by an untrusted peer",
            )

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        response = await self._enforce_ip_rules(request)
        if response is None:
            await self._count_ip_spoofing(
                request, getattr(request.state, "route_config", None)
            )
        return response

    async def _enforce_ip_rules(self, request: GuardRequest) -> GuardResponse | None:
        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)
        if not client_ip:
            return None

        ban_response = await self._check_banned_ip(request, client_ip, route_config)
        if ban_response:
            return ban_response

        if getattr(request.state, "guard_exclusion_scoped", False) is True:
            return await self._check_global_ip_restrictions(
                request, client_ip, None, escalate=False
            )

        if self.middleware.route_resolver.should_bypass_check("ip", route_config):
            return None

        precomputed = None
        if route_config:
            precomputed = await self._resolve_global_ip_access(client_ip, route_config)
            route_response = await self._check_route_ip_restrictions(
                request, client_ip, route_config
            )
            if route_response:
                return route_response

        return await self._check_global_ip_restrictions(
            request, client_ip, route_config, precomputed=precomputed
        )
