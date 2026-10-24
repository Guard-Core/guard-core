import logging
from collections.abc import Callable, MutableMapping
from typing import Any

from guard_core._redis_enablement import redis_is_configured
from guard_core._security_headers_override import PROCESS_OVERRIDE, PULLED_OVERRIDES
from guard_core.exceptions import CallableShapeError
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.response_prefetch import (
    SHARED_PREFETCH,
    ResponseBodyPrefetch,
)
from guard_core.sync.core.callable_slot import CallableSlot
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.modifier_body import (
    apply_modifier_with_bounded_body,
)
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.behavior_handler import BehaviorRule, config_to_rule
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import extract_client_ip


def _drop_other_spellings(headers: dict[str, str], name: str) -> None:
    lowered = name.lower()
    for key in [key for key in headers if key.lower() == lowered and key != name]:
        del headers[key]


_LOWERED: dict[str, str] = {}


def _merge_into_foreign_headers(
    headers: MutableMapping[str, str],
    security_headers: dict[str, str],
    forced: frozenset[str],
) -> None:
    present = {key.lower() for key in headers}
    for name, value in security_headers.items():
        try:
            lowered = _LOWERED[name]
        except KeyError:
            lowered = _LOWERED[name] = name.lower()
        if lowered in forced or lowered not in present:
            headers[name] = value


def _merge_security_headers(
    headers: MutableMapping[str, str],
    security_headers: dict[str, str],
    forced: frozenset[str],
) -> None:
    if not isinstance(headers, dict):
        _merge_into_foreign_headers(headers, security_headers, forced)
        return
    present = {key.lower() for key in headers}
    for name, value in security_headers.items():
        lowered = name.lower()
        if lowered in present:
            if lowered not in forced:
                continue
            if name not in headers or len(present) < len(headers):
                _drop_other_spellings(headers, name)
        headers[name] = value
        present.add(lowered)


def _merge_planned_security_headers(
    headers: MutableMapping[str, str],
    security_headers: dict[str, str],
    plan: tuple[tuple[str, str, bool], ...],
) -> None:
    if not isinstance(headers, dict):
        for name, _, is_forced in plan:
            if is_forced or name not in headers:
                headers[name] = security_headers[name]
        return
    present = set(map(str.lower, headers))
    for name, lowered, is_forced in plan:
        if lowered in present:
            if not is_forced:
                continue
            _drop_other_spellings(headers, name)
        headers[name] = security_headers[name]


class ErrorResponseFactory:
    def __init__(self, context: ResponseContext):
        self.context = context
        self.logger = logging.getLogger("guard_core.sync.core.responses.factory")
        self._modifier_slot: CallableSlot[GuardResponse, GuardResponse] = CallableSlot(
            "custom_response_modifier", context.config.custom_response_modifier
        )
        self.security_headers_manager = context.security_headers_manager
        self.security_headers_manager.agent_handler = context.agent_handler
        if context.redis_handler is not None:
            self.security_headers_manager.redis_handler = context.redis_handler

    def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        custom_message = self.context.config.custom_error_responses.get(
            status_code, default_message
        )
        response: GuardResponse = self.context.response_factory.create_response(
            custom_message, status_code
        )

        response = self.apply_security_headers(response)

        response = self.apply_modifier(response)

        return response

    def create_https_redirect(self, request: SyncGuardRequest) -> GuardResponse:
        https_url = request.url_replace_scheme("https")
        status_code = 301 if request.method.upper() in ("GET", "HEAD") else 308
        redirect_response = self.context.response_factory.create_redirect_response(
            str(https_url), status_code
        )

        return self.apply_modifier(redirect_response)

    def apply_security_headers(
        self,
        response: GuardResponse,
        request_path: str | None = None,
        override: Any = None,
    ) -> GuardResponse:
        manager = self.security_headers_manager
        if override is None:
            override = manager.resolve_override()
        enabled = manager.headers_enabled_for(self.context.config, override)
        return self._apply_security_headers(response, request_path, override, enabled)

    def _apply_security_headers(
        self,
        response: GuardResponse,
        request_path: str | None,
        override: Any,
        enabled: bool,
    ) -> GuardResponse:
        if not enabled:
            return response
        security_headers = self.security_headers_manager.get_headers(
            request_path,
            config=self.context.config,
            override=override,
            checked=True,
        )
        plan = getattr(security_headers, "plan", None)
        if plan is None:
            forced: frozenset[str] = getattr(security_headers, "forced", frozenset())
            _merge_security_headers(response.headers, security_headers, forced)
        else:
            _merge_planned_security_headers(response.headers, security_headers, plan)
        return response

    def apply_cors_headers(
        self, response: GuardResponse, origin: str, override: Any = None
    ) -> GuardResponse:
        if override is None:
            override = self.security_headers_manager.resolve_override()
        return self._apply_cors_headers(response, origin, override)

    def _apply_cors_headers(
        self, response: GuardResponse, origin: str, override: Any
    ) -> GuardResponse:
        # CORS follows the CORS settings alone: the security headers switch never
        # governs it.
        cors_headers = self.security_headers_manager.get_cors_headers(
            origin, config=self.context.config, override=override
        )
        for header_name, header_value in cors_headers.items():
            response.headers[header_name] = header_value

        return response

    def apply_modifier(
        self,
        response: GuardResponse,
        request: SyncGuardRequest | None = None,
        prefetch: ResponseBodyPrefetch | None = None,
    ) -> GuardResponse:
        if prefetch is not None:
            SHARED_PREFETCH.set(None)
        configured = self.context.config.custom_response_modifier
        if not configured:
            return response
        slot = self._modifier_slot
        if configured is not slot.source:
            slot.adopt(configured)
        modifier = slot.invoke
        materialized = False
        if request is not None:
            declared: Any = response
            try:
                materialized = declared.body_is_materialized is True
            except AttributeError:
                pass
        if request is not None and not materialized:
            return apply_modifier_with_bounded_body(
                modifier,
                response,
                request,
                prefetch,
                self.context.config,
                self.logger,
                self.context.agent_handler,
            )
        try:
            result: GuardResponse = modifier(response)
            return result
        except CallableShapeError:
            raise
        except Exception as exc:
            self.logger.exception(
                "custom_response_modifier raised %s; returning unmodified response",
                exc,
            )
        return response

    def _apply_response_headers(
        self, request: SyncGuardRequest, response: GuardResponse
    ) -> GuardResponse:
        manager = self.security_headers_manager
        config = self.context.config
        # No override ever recorded and no Redis: the fab5abab path, no override or
        # CORS merge work.
        quiet = (
            PROCESS_OVERRIDE.record.set_at,
            manager._override.set_at,
            manager._override_epoch,
            manager.redis_handler is None,
            redis_is_configured(config),
            bool(PULLED_OVERRIDES),
        ) == (0.0, 0.0, PROCESS_OVERRIDE.reset_epoch, True, False, False)
        override = manager._override if quiet else manager.resolve_override()
        enabled = (
            bool(
                config.security_headers and config.security_headers.get("enabled", True)
            )
            if quiet
            else manager.headers_enabled_for(config, override)
        )
        skip_cors = quiet and not config.enable_cors
        response = self._apply_security_headers(
            response, str(request.url_path), override, enabled
        )
        origin = request.headers.get("origin")
        if origin and not skip_cors:
            response = self._apply_cors_headers(response, origin, override)
        return response

    def process_response(
        self,
        request: SyncGuardRequest,
        response: GuardResponse,
        response_time: float,
        route_config: RouteConfig | None,
        process_behavioral_rules: Callable[
            [SyncGuardRequest, GuardResponse, str, RouteConfig], None
        ]
        | None = None,
        process_global_behavioral_rules: Callable[
            [SyncGuardRequest, GuardResponse, str, list[BehaviorRule]], None
        ]
        | None = None,
    ) -> GuardResponse:
        prefetch = None
        if self.context.config.behavior_scan_response_body:
            prefetch = self._share_prefetch(response)

        client_ip = self._resolve_client_ip_for_behavioral_rules(
            request,
            route_config,
            process_behavioral_rules,
            process_global_behavioral_rules,
        )

        if (
            client_ip is not None
            and route_config is not None
            and route_config.behavior_rules
            and process_behavioral_rules is not None
        ):
            process_behavioral_rules(request, response, client_ip, route_config)

        if (
            client_ip is not None
            and self.context.config.global_behavior_rules
            and process_global_behavioral_rules is not None
        ):
            global_rules = [
                config_to_rule(cfg) for cfg in self.context.config.global_behavior_rules
            ]
            process_global_behavioral_rules(request, response, client_ip, global_rules)

        self.context.metrics_collector.collect_request_metrics(
            request, response_time, response.status_code
        )

        response = self._apply_response_headers(request, response)

        return self.apply_modifier(response, request, prefetch)

    def _share_prefetch(self, response: GuardResponse) -> ResponseBodyPrefetch:
        prefetch = ResponseBodyPrefetch(response)
        SHARED_PREFETCH.set(prefetch)
        return prefetch

    def _resolve_client_ip_for_behavioral_rules(
        self,
        request: SyncGuardRequest,
        route_config: RouteConfig | None,
        process_behavioral_rules: Callable[
            [SyncGuardRequest, GuardResponse, str, RouteConfig], None
        ]
        | None,
        process_global_behavioral_rules: Callable[
            [SyncGuardRequest, GuardResponse, str, list[BehaviorRule]], None
        ]
        | None,
    ) -> str | None:
        needs_client_ip = (
            route_config is not None
            and route_config.behavior_rules
            and process_behavioral_rules is not None
        ) or (
            bool(self.context.config.global_behavior_rules)
            and process_global_behavioral_rules is not None
        )
        if not needs_client_ip:
            return None
        return extract_client_ip(
            request, self.context.config, self.context.agent_handler
        )
