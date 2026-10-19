import threading
from collections import OrderedDict
from collections.abc import Collection
from typing import TYPE_CHECKING

from guard_core._utils.sampling import observe_sampled_key
from guard_core.core.checks._shared_strikes import StrikeReport
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.helpers import (
    _increment_suspicious_counts,
    _ip_strike_counts,
    _try_threshold_ban,
    get_cached_detection_result,
    route_config_applies,
)
from guard_core.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_PENETRATION_ATTEMPT,
    EVENT_SUSPICIOUS_REQUEST,
)
from guard_core.decorators.base import RouteConfig
from guard_core.detection_result import BODY_READ_STALLED, DetectionResult
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity

if TYPE_CHECKING:
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol


_DISABLED_DETECTION_EVENT_WINDOW_SECONDS = 60
_MAX_TRACKED_DISABLED_DETECTION_CLIENTS = 10_000
_disabled_detection_lock = threading.Lock()
_disabled_detection_samples: OrderedDict[str, float] = OrderedDict()


def _sample_disabled_detection_event(client_ip: str, route_id: str) -> bool:
    return observe_sampled_key(
        _disabled_detection_samples,
        _disabled_detection_lock,
        f"{route_id}|{client_ip}",
        window=_DISABLED_DETECTION_EVENT_WINDOW_SECONDS,
        max_tracked=_MAX_TRACKED_DISABLED_DETECTION_CLIENTS,
    )


class SuspiciousActivityCheck(SecurityCheck):
    def __init__(self, middleware: "GuardMiddlewareProtocol") -> None:
        super().__init__(middleware)
        from guard_core.handlers.ipban_handler import ip_ban_manager

        self.ip_ban_manager = ip_ban_manager

    @property
    def check_name(self) -> str:
        return "suspicious_activity"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return (
            config.enable_penetration_detection
            or route_config_applies(
                route_configs, lambda rc: bool(rc.enable_suspicious_detection)
            )
            or config.enable_dynamic_rules
        )

    def _total_count_for_ip(self, client_ip: str) -> int:
        ip_counts = _ip_strike_counts(self.middleware, client_ip)
        request_total = getattr(ip_counts, "request_total", None)
        return sum(ip_counts.values()) if request_total is None else request_total

    async def _handle_suspicious_passive_mode(
        self, request: GuardRequest, client_ip: str, trigger_info: str
    ) -> None:
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Suspicious activity detected: {client_ip}",
            passive_mode=True,
            trigger_info=trigger_info,
            level=self.config.log_suspicious_level,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            on_block=self.config.on_block,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )

        message = "Suspicious pattern detected (passive mode)"

        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="logged_only",
            reason=f"{message}: {trigger_info}",
            request_count=self._total_count_for_ip(client_ip),
            passive_mode=True,
            trigger_info=trigger_info,
        )

    async def _handle_suspicious_active_mode(
        self,
        request: GuardRequest,
        client_ip: str,
        trigger_info: str,
        threat_categories: list[str],
    ) -> GuardResponse:
        strikes = StrikeReport()
        banned = await _try_threshold_ban(
            request,
            self.config,
            self.ip_ban_manager,
            self.middleware,
            client_ip,
            trigger_info,
            self.logger,
            self.check_name,
            self.config.muted_check_logs,
            threat_categories,
            strikes=strikes,
        )
        if banned:
            await self.middleware.event_bus.send_middleware_event(
                event_type=EVENT_PENETRATION_ATTEMPT,
                request=request,
                action_taken="request_blocked",
                reason=f"Penetration attempt detected: {trigger_info}",
                request_count=strikes.banning_count or 0,
                ban_duration=strikes.banned_duration,
                trigger_info=trigger_info,
            )
            return await self.middleware.create_error_response(
                status_code=403,
                default_message="IP has been banned",
            )

        sus_specs = f"{client_ip} - {trigger_info}"
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Suspicious activity detected for IP: {sus_specs}",
            level=self.config.log_suspicious_level,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            on_block=self.config.on_block,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )

        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="request_blocked",
            reason=f"Penetration attempt detected: {trigger_info}",
            request_count=strikes.count_or(lambda: self._total_count_for_ip(client_ip)),
            trigger_info=trigger_info,
        )

        return await self.middleware.create_error_response(
            status_code=400,
            default_message="Suspicious activity detected",
        )

    async def _handle_body_read_error(
        self, request: GuardRequest, client_ip: str, result: DetectionResult
    ) -> GuardResponse | None:
        stalled = result.body_read_error == BODY_READ_STALLED
        outcome = "stalled" if stalled else "failed"
        blocks = self.config.fail_secure and not self.config.passive_mode
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Request body read {outcome} for IP: {client_ip}",
            passive_mode=self.config.passive_mode,
            trigger_info=result.body_read_detail,
            level=self.config.log_suspicious_level,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            on_block=self.config.on_block,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )
        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_SUSPICIOUS_REQUEST,
            request=request,
            action_taken="request_blocked" if blocks else "logged_only",
            reason=f"Request body read {outcome}: {result.body_read_detail}",
            passive_mode=self.config.passive_mode,
            trigger_info=result.body_read_detail,
        )
        if not blocks:
            return None
        if stalled:
            return await self.middleware.create_error_response(
                status_code=408, default_message="Request body read timed out"
            )
        return await self.middleware.create_error_response(
            status_code=400, default_message="Request body could not be read"
        )

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        if getattr(request.state, "is_whitelisted", False):
            return None

        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)

        if not client_ip:
            return None

        result = await get_cached_detection_result(
            request,
            route_config,
            self.config,
            self.middleware.route_resolver.should_bypass_check,
        )

        if result.trigger_info == "disabled_by_decorator":
            route_id = str(getattr(request.state, "guard_route_id", ""))
            if _sample_disabled_detection_event(client_ip, route_id):
                await self.middleware.event_bus.send_middleware_event(
                    event_type=EVENT_DECORATOR_VIOLATION,
                    request=request,
                    action_taken="detection_disabled",
                    reason="Suspicious pattern detection disabled by route decorator",
                    decorator_type="advanced",
                    violation_type="suspicious_detection_disabled",
                )
            return None

        if result.body_read_error is not None:
            return await self._handle_body_read_error(request, client_ip, result)

        if not result.is_threat:
            return None

        trigger_info = result.trigger_info
        threat_categories = list(result.threat_categories)

        if self.config.passive_mode:
            await self._handle_suspicious_passive_mode(request, client_ip, trigger_info)
            return None

        _increment_suspicious_counts(self.middleware, client_ip, threat_categories)

        return await self._handle_suspicious_active_mode(
            request, client_ip, trigger_info, threat_categories
        )
