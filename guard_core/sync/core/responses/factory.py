import logging
from collections.abc import Callable, MutableMapping
from typing import Any

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.behavior_handler import BehaviorRule, config_to_rule
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import extract_client_ip


def _drop_other_spellings(headers: MutableMapping[str, str], name: str) -> None:
    if not isinstance(headers, dict):
        return
    lowered = name.lower()
    for key in [key for key in headers if key.lower() == lowered and key != name]:
        del headers[key]


class ErrorResponseFactory:
    def __init__(self, context: ResponseContext):
        self.context = context
        self.logger = logging.getLogger("guard_core.sync.core.responses.factory")
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
        redirect_response = self.context.response_factory.create_redirect_response(
            str(https_url), 301
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
        (
            security_headers,
            forced,
        ) = self.security_headers_manager.get_headers_and_forced(
            request_path,
            config=self.context.config,
            override=override,
            checked=True,
        )
        headers = response.headers
        present = (
            {key.lower() for key in headers} if isinstance(headers, dict) else None
        )
        for header_name, header_value in security_headers.items():
            lowered = header_name.lower()
            if lowered in forced:
                _drop_other_spellings(headers, header_name)
            elif (
                (lowered in present) if present is not None else header_name in headers
            ):
                continue
            headers[header_name] = header_value
            if present is not None:
                present.add(lowered)
        return response

    def apply_cors_headers(
        self, response: GuardResponse, origin: str, override: Any = None
    ) -> GuardResponse:
        manager = self.security_headers_manager
        if override is None:
            override = manager.resolve_override()
        enabled = manager.headers_enabled_for(self.context.config, override)
        return self._apply_cors_headers(response, origin, enabled)

    def _apply_cors_headers(
        self, response: GuardResponse, origin: str, enabled: bool
    ) -> GuardResponse:
        if enabled:
            cors_headers = self.security_headers_manager.get_cors_headers(
                origin, config=self.context.config
            )
            for header_name, header_value in cors_headers.items():
                response.headers[header_name] = header_value

        return response

    def apply_modifier(self, response: GuardResponse) -> GuardResponse:
        if self.context.config.custom_response_modifier:
            try:
                result: GuardResponse = self.context.config.custom_response_modifier(
                    response
                )
                return result
            except Exception as exc:
                self.logger.exception(
                    "custom_response_modifier raised %s; returning unmodified response",
                    exc,
                )
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

        manager = self.security_headers_manager
        override = manager.resolve_override()
        enabled = manager.headers_enabled_for(self.context.config, override)
        response = self._apply_security_headers(
            response, str(request.url_path), override, enabled
        )

        origin = request.headers.get("origin")
        if origin:
            response = self._apply_cors_headers(response, origin, enabled)

        return self.apply_modifier(response)

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
