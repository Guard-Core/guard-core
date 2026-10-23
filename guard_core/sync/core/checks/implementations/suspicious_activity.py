import threading
from collections import OrderedDict
from collections.abc import Collection
from typing import TYPE_CHECKING, Any

from guard_core._misconfiguration import report_misconfiguration
from guard_core.sync._utils.agent_events import agent_receives_events
from guard_core.sync._utils.route_gate import (
    ROUTE_TEMPLATE_STATE_ATTR,
    STATIC_FILE_STATE_ATTR,
    might_be_a_gated_probe,
    might_be_a_static_file,
    path_params_without_a_literal_segment_before,
)
from guard_core.sync._utils.rule_attribution import pattern_attribution
from guard_core.sync._utils.sampling import observe_sampled_key
from guard_core.sync.core.checks._shared_strikes import StrikeReport
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.helpers import (
    _increment_suspicious_counts,
    _ip_strike_counts,
    _try_threshold_ban,
    get_cached_detection_result,
    route_config_applies,
)
from guard_core.sync.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_PENETRATION_ATTEMPT,
    EVENT_SUSPICIOUS_REQUEST,
)
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.detection_result import BODY_READ_STALLED, DetectionResult
from guard_core.models import SecurityConfig, SyncSecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.utils import log_activity

if TYPE_CHECKING:
    from guard_core.sync.protocols.middleware_protocol import SyncGuardMiddlewareProtocol


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
    def __init__(self, middleware: "SyncGuardMiddlewareProtocol") -> None:
        super().__init__(middleware)
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager

        self.ip_ban_manager = ip_ban_manager
        self._reported_root_path_params: set[tuple[str, str]] = set()

    @property
    def check_name(self) -> str:
        return "suspicious_activity"

    @classmethod
    def applies_to(
        cls,
        config: SyncSecurityConfig,
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

    def _detection_event_fields(self, result: DetectionResult) -> dict[str, Any]:
        """What the penetration events carry about the detection: the per-request
        id, the categories and, for a rule that decided, its attribution. Built
        only when an agent consumes events, which the callers check."""
        fields: dict[str, Any] = pattern_attribution(result.matched_pattern_source)
        if result.correlation_id is not None:
            fields["correlation_id"] = result.correlation_id
        if result.threat_categories:
            fields["threat_categories"] = list(result.threat_categories)
            fields["category"] = result.threat_categories[0]
        return fields

    def _handle_suspicious_passive_mode(
        self, request: SyncGuardRequest, client_ip: str, result: DetectionResult
    ) -> None:
        trigger_info = result.trigger_info
        consumed = agent_receives_events(self.middleware.event_bus, self.config)
        log_activity(
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

        self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="logged_only",
            reason=f"{message}: {trigger_info}",
            request_count=self._total_count_for_ip(client_ip),
            passive_mode=True,
            trigger_info=trigger_info,
            **(self._detection_event_fields(result) if consumed else {}),
        )

    def _handle_suspicious_active_mode(
        self,
        request: SyncGuardRequest,
        client_ip: str,
        result: DetectionResult,
    ) -> GuardResponse:
        trigger_info = result.trigger_info
        threat_categories = list(result.threat_categories)
        consumed = agent_receives_events(self.middleware.event_bus, self.config)
        strikes = StrikeReport()
        banned = _try_threshold_ban(
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
            self.middleware.event_bus.send_middleware_event(
                event_type=EVENT_PENETRATION_ATTEMPT,
                request=request,
                action_taken="request_blocked",
                reason=f"Penetration attempt detected: {trigger_info}",
                request_count=strikes.banning_count or 0,
                ban_duration=strikes.banned_duration,
                trigger_info=trigger_info,
                **(self._detection_event_fields(result) if consumed else {}),
            )
            return self.middleware.create_error_response(
                status_code=403,
                default_message="IP has been banned",
            )

        sus_specs = f"{client_ip} - {trigger_info}"
        log_activity(
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

        self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="request_blocked",
            reason=f"Penetration attempt detected: {trigger_info}",
            request_count=strikes.count_or(lambda: self._total_count_for_ip(client_ip)),
            trigger_info=trigger_info,
            **(self._detection_event_fields(result) if consumed else {}),
        )

        return self.middleware.create_error_response(
            status_code=400,
            default_message="Suspicious activity detected",
        )

    def _handle_body_read_error(
        self, request: SyncGuardRequest, client_ip: str, result: DetectionResult
    ) -> GuardResponse | None:
        stalled = result.body_read_error == BODY_READ_STALLED
        outcome = "stalled" if stalled else "failed"
        blocks = self.config.fail_secure and not self.config.passive_mode
        log_activity(
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
        self.middleware.event_bus.send_middleware_event(
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
            return self.middleware.create_error_response(
                status_code=408, default_message="Request body read timed out"
            )
        return self.middleware.create_error_response(
            status_code=400, default_message="Request body could not be read"
        )

    def _record_route_template(self, request: SyncGuardRequest) -> None:
        state = request.state
        if getattr(state, ROUTE_TEMPLATE_STATE_ATTR, None) is not None:
            return
        if getattr(state, "guard_route_unresolved", False) is True:
            return
        lookup = getattr(self.middleware, "route_template", None)
        path = str(request.url_path)
        if not callable(lookup) or not might_be_a_gated_probe(path):
            return
        try:
            template = lookup(path)
        except Exception:
            self.logger.error("route_template failed; the path is judged without it")
            return
        if isinstance(template, str):
            setattr(state, ROUTE_TEMPLATE_STATE_ATTR, template)

    def _report_root_capture_path_params(
        self, request: SyncGuardRequest, route_config: RouteConfig
    ) -> None:
        declared = route_config.excluded_detection_path_params or ()
        template = getattr(request.state, ROUTE_TEMPLATE_STATE_ATTR, None)
        if not isinstance(template, str):
            return
        route = str(getattr(request.state, "guard_route_id", template))
        for name in path_params_without_a_literal_segment_before(template, declared):
            if (route, name) in self._reported_root_path_params:
                continue
            report_misconfiguration(
                self.config,
                f"@detection_exclusion(path_params=...) on route {route!r} "
                f"declares {name!r}, which has no literal segment before it in "
                f"the route template {template!r}: it would exempt the whole "
                "path from the probe rows.",
                logger=self.logger,
                stacklevel=2,
            )
            self._reported_root_path_params.add((route, name))

    def _record_served_static_file(self, request: SyncGuardRequest) -> None:
        state = request.state
        if getattr(state, STATIC_FILE_STATE_ATTR, None) is not None:
            return
        if getattr(state, "guard_route_unresolved", False) is True:
            return
        lookup = getattr(self.middleware, "static_file_exists", None)
        path = str(request.url_path)
        if not callable(lookup) or not might_be_a_static_file(path):
            return
        try:
            served = lookup(path)
        except Exception:
            self.logger.error(
                "static_file_exists failed; the path is judged without it"
            )
            return
        if served is True:
            setattr(state, STATIC_FILE_STATE_ATTR, True)

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        if getattr(request.state, "is_whitelisted", False):
            return None

        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)

        if not client_ip:
            return None

        self._record_route_template(request)
        if route_config is not None and route_config.excluded_detection_path_params:
            self._report_root_capture_path_params(request, route_config)
        self._record_served_static_file(request)
        result = get_cached_detection_result(
            request,
            route_config,
            self.config,
            self.middleware.route_resolver.should_bypass_check,
        )

        if result.trigger_info == "disabled_by_decorator":
            route_id = str(getattr(request.state, "guard_route_id", ""))
            if _sample_disabled_detection_event(client_ip, route_id):
                self.middleware.event_bus.send_middleware_event(
                    event_type=EVENT_DECORATOR_VIOLATION,
                    request=request,
                    action_taken="detection_disabled",
                    reason="Suspicious pattern detection disabled by route decorator",
                    decorator_type="advanced",
                    violation_type="suspicious_detection_disabled",
                )
            return None

        if result.body_read_error is not None:
            return self._handle_body_read_error(request, client_ip, result)

        if not result.is_threat:
            return None

        if self.config.passive_mode:
            self._handle_suspicious_passive_mode(request, client_ip, result)
            return None

        _increment_suspicious_counts(
            self.middleware, client_ip, list(result.threat_categories)
        )

        return self._handle_suspicious_active_mode(request, client_ip, result)
