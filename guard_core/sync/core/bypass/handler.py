from collections.abc import Callable
from logging import Logger

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.block_events import fire_block_hook
from guard_core.sync._utils.request_logging import redact_endpoint_for_display
from guard_core.sync.core.bypass.context import BypassContext
from guard_core.sync.core.checks.implementations.emergency_mode import (
    EMERGENCY_CHECK_NAME,
    enforce_emergency_mode,
)
from guard_core.sync.core.events.event_types import EVENT_SECURITY_BYPASS
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import UNKNOWN_CLIENT_IDENTITY, extract_client_ip

UNRESOLVABLE_CLIENT_ADDRESS_CHECK_NAME = "client_address_unresolved"

_no_client_address_warned = False


def _warn_no_client_address(
    logger: Logger, *, rejected: bool, passive: bool = False
) -> None:
    global _no_client_address_warned
    if _no_client_address_warned:
        return
    _no_client_address_warned = True
    outcome = (
        'the request is admitted and logged with identity "unknown" (passive_mode=True)'
        if passive
        else "the request is rejected with 403 (fail_secure=True)"
        if rejected
        else (
            'the pipeline runs with identity "unknown" (fail_secure=False) and '
            "all such requests share one rate-limit bucket"
        )
    )
    logger.warning(
        "no client address on the connection; if the app is served over a "
        'Unix socket add "unix" to trusted_proxies; %s. This warning is '
        "logged once.",
        outcome,
    )


class BypassHandler:
    def __init__(self, context: BypassContext) -> None:
        self.context = context

    def handle_passthrough(
        self,
        request: SyncGuardRequest,
        call_next: Callable[[SyncGuardRequest], GuardResponse],
    ) -> GuardResponse | None:
        if self.context.validator.is_path_excluded(request):
            request.state.guard_exclusion_scoped = True
            return None

        if not request.client_host:
            client_ip = extract_client_ip(request, self.context.config)
            request.state.client_ip = client_ip
            if client_ip == UNKNOWN_CLIENT_IDENTITY:
                config = self.context.config
                _warn_no_client_address(
                    self.context.logger,
                    rejected=config.fail_secure,
                    passive=config.passive_mode and config.fail_secure,
                )
                if config.fail_secure and config.passive_mode:
                    fire_block_hook(
                        config.on_block,
                        request,
                        UNRESOLVABLE_CLIENT_ADDRESS_CHECK_NAME,
                        "Client address could not be determined",
                        "",
                        True,
                        None,
                        config.log_sensitive_params,
                        config.log_sensitive_body_fields,
                        config.log_sensitive_headers,
                    )
                elif config.fail_secure:
                    response = self.context.response_factory.create_error_response(
                        403, "Client address could not be determined"
                    )
                    fire_block_hook(
                        self.context.config.on_block,
                        request,
                        UNRESOLVABLE_CLIENT_ADDRESS_CHECK_NAME,
                        "Client address could not be determined",
                        "",
                        False,
                        response.status_code,
                        self.context.config.log_sensitive_params,
                        self.context.config.log_sensitive_body_fields,
                        self.context.config.log_sensitive_headers,
                    )
                    return response

        return None

    def _enforce_emergency_mode(
        self, request: SyncGuardRequest
    ) -> GuardResponse | None:
        """A lockdown holds on every route: ``@bypass(["all"])`` skips the pipeline,
        so the verdict the pipeline's emergency check would give is taken here."""
        context = self.context
        response = enforce_emergency_mode(
            request,
            context.config,
            context.logger,
            context.event_bus,
            context.response_factory.create_error_response,
        )
        if response is not None:
            stash = getattr(request.state, "_guard_block_stash", None) or {}
            fire_block_hook(
                context.config.on_block,
                request,
                EMERGENCY_CHECK_NAME,
                stash.get("reason", ""),
                stash.get("trigger_info", ""),
                False,
                response.status_code,
                context.config.log_sensitive_params,
                context.config.log_sensitive_body_fields,
                context.config.log_sensitive_headers,
            )
        return response

    def handle_security_bypass(
        self,
        request: SyncGuardRequest,
        call_next: Callable[[SyncGuardRequest], GuardResponse] | None = None,
        route_config: RouteConfig | None = None,
    ) -> GuardResponse | None:
        if not route_config or not self.context.route_resolver.should_bypass_check(
            "all", route_config
        ):
            return None

        if self.context.config.emergency_mode:
            locked_down = self._enforce_emergency_mode(request)
            if locked_down is not None:
                return locked_down

        self.context.event_bus.send_middleware_event(
            event_type=EVENT_SECURITY_BYPASS,
            request=request,
            action_taken="all_checks_bypassed",
            reason="Route configured to bypass all security checks",
            bypassed_checks=list(route_config.bypassed_checks),
            endpoint=redact_endpoint_for_display(
                str(request.url_path),
                self.context.config.log_sensitive_params,
                self.context.config.log_sensitive_body_fields,
                self.context.config.log_sensitive_headers,
            ),
        )

        if call_next is None:
            return None
        response = call_next(request)
        response = self.context.response_factory.apply_security_headers(
            response, str(request.url_path)
        )
        return self.context.response_factory.apply_modifier(response, request)
