import logging
from collections.abc import Collection, Sequence
from ipaddress import ip_address
from typing import Protocol

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.agent_events import agent_receives_events
from guard_core.sync._utils.nat64 import nat64_table_of
from guard_core.sync._utils.rule_attribution import emergency_attribution
from guard_core.sync._utils.sampling import PerApp, SampledKeys, observe_sampled_key
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.events.event_types import EVENT_EMERGENCY_MODE_BLOCK
from guard_core.sync.core.validation.path_matching import path_is_excluded
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.middleware_protocol import SecurityEventBusProtocol
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import _ip_in_list, extract_client_ip, log_activity

EMERGENCY_RETRY_AFTER = 60
_EMERGENCY_SAMPLE_WINDOW_SECONDS = 60
_MAX_TRACKED_EMERGENCY_CLIENTS = 10_000
_emergency_samples: PerApp[SampledKeys] = PerApp("emergency", SampledKeys)


def _sample_emergency_line(config: object, kind: str, client_ip: str) -> bool:
    samples = _emergency_samples.for_app(config)
    return observe_sampled_key(
        samples.entries,
        samples.lock,
        f"{kind}|{client_ip}",
        window=_EMERGENCY_SAMPLE_WINDOW_SECONDS,
        max_tracked=_MAX_TRACKED_EMERGENCY_CLIENTS,
    )


EMERGENCY_CHECK_NAME = "emergency_mode"


class _CreateErrorResponse(Protocol):
    def __call__(self, status_code: int, default_message: str) -> GuardResponse: ...


def _admitted_lists(config: SyncSecurityConfig) -> tuple[Sequence[str] | None, ...]:
    if config.emergency_whitelist_only:
        return (config.emergency_whitelist,)
    return (config.emergency_whitelist, config.whitelist, config.exempt_ips)


def enforce_emergency_mode(
    request: SyncGuardRequest,
    config: SyncSecurityConfig,
    logger: logging.Logger,
    event_bus: SecurityEventBusProtocol,
    create_error_response: _CreateErrorResponse,
) -> GuardResponse | None:
    """The lockdown verdict of one request: a 503 for a client the whitelists do
    not admit. The pipeline check and the ``@bypass(["all"])`` path share it, each
    only when ``emergency_mode`` is on."""
    client_ip = getattr(request.state, "client_ip", None)
    if not client_ip:
        client_ip = extract_client_ip(request, config, event_bus.agent_handler)

    try:
        client_ip_addr = ip_address(client_ip)
    except ValueError:
        client_ip_addr = None

    is_whitelisted = client_ip_addr is not None and any(
        _ip_in_list(client_ip_addr, client_ip, entries, nat64_table_of(config))
        for entries in _admitted_lists(config)
    )

    if not is_whitelisted:
        exempt_paths = config.emergency_exempt_paths
        if exempt_paths and path_is_excluded(request.url_path, exempt_paths):
            return None
        return _deny(
            request, config, logger, event_bus, create_error_response, client_ip
        )
    _log_allowed(request, config, logger, client_ip)
    return None


def _deny(
    request: SyncGuardRequest,
    config: SyncSecurityConfig,
    logger: logging.Logger,
    event_bus: SecurityEventBusProtocol,
    create_error_response: _CreateErrorResponse,
    client_ip: str,
) -> GuardResponse | None:
    sampled = _sample_emergency_line(config, "block", client_ip)
    log_activity(
        request,
        logger,
        log_type="suspicious",
        reason=f"[EMERGENCY MODE] Access denied for IP {client_ip}",
        level=config.log_suspicious_level if sampled else None,
        passive_mode=config.passive_mode,
        check_name=EMERGENCY_CHECK_NAME,
        muted_check_logs=config.muted_check_logs,
        on_block=config.on_block,
        sensitive_headers=config.log_sensitive_headers,
        sensitive_params=config.log_sensitive_params,
        sensitive_body_fields=config.log_sensitive_body_fields,
    )

    if sampled:
        event_bus.send_middleware_event(
            event_type=EVENT_EMERGENCY_MODE_BLOCK,
            request=request,
            action_taken="request_blocked"
            if not config.passive_mode
            else "logged_only",
            reason=f"[EMERGENCY MODE] IP {client_ip} not in whitelist",
            emergency_whitelist_count=len(config.emergency_whitelist),
            emergency_active=True,
            **(
                emergency_attribution(config)
                if agent_receives_events(event_bus, config)
                else {}
            ),
        )

    if config.passive_mode:
        return None
    response: GuardResponse = create_error_response(
        status_code=503,
        default_message="Service temporarily unavailable",
    )
    response.headers["Retry-After"] = str(EMERGENCY_RETRY_AFTER)
    return response


def _log_allowed(
    request: SyncGuardRequest,
    config: SyncSecurityConfig,
    logger: logging.Logger,
    client_ip: str,
) -> None:
    if not _sample_emergency_line(config, "allow", client_ip):
        return
    log_activity(
        request,
        logger,
        log_type="info",
        reason=f"[EMERGENCY MODE] Allowed access for whitelisted IP {client_ip}",
        level="INFO",
        check_name=EMERGENCY_CHECK_NAME,
        muted_check_logs=config.muted_check_logs,
        sensitive_headers=config.log_sensitive_headers,
        sensitive_params=config.log_sensitive_params,
        sensitive_body_fields=config.log_sensitive_body_fields,
    )


class EmergencyModeCheck(SecurityCheck):
    enforced_on_excluded_paths = True

    @property
    def check_name(self) -> str:
        return EMERGENCY_CHECK_NAME

    @classmethod
    def applies_to(
        cls,
        config: SyncSecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return config.emergency_mode or config.enable_dynamic_rules

    def _admitted_lists(self) -> tuple[Sequence[str] | None, ...]:
        return _admitted_lists(self.config)

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        if not self.config.emergency_mode:
            return None
        return enforce_emergency_mode(
            request,
            self.config,
            self.logger,
            self.middleware.event_bus,
            self.middleware.create_error_response,
        )
