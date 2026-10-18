import logging
from collections.abc import Awaitable, Callable, MutableMapping

from guard_core.core.responses.context import ResponseContext
from guard_core.decorators.base import RouteConfig
from guard_core.handlers.behavior_handler import BehaviorRule, config_to_rule
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import extract_client_ip


def _header_present(headers: MutableMapping[str, str], name: str) -> bool:
    if isinstance(headers, dict):
        lowered = name.lower()
        return any(key.lower() == lowered for key in headers)
    return name in headers


def _drop_other_spellings(headers: MutableMapping[str, str], name: str) -> None:
    if not isinstance(headers, dict):
        return
    lowered = name.lower()
    for key in [key for key in headers if key.lower() == lowered and key != name]:
        del headers[key]


class ErrorResponseFactory:
    def __init__(self, context: ResponseContext):
        self.context = context
        self.logger = logging.getLogger("guard_core.core.responses.factory")
        self.security_headers_manager = context.security_headers_manager
        self.security_headers_manager.agent_handler = context.agent_handler
        if context.redis_handler is not None:
            self.security_headers_manager.redis_handler = context.redis_handler

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        custom_message = self.context.config.custom_error_responses.get(
            status_code, default_message
        )
        response: GuardResponse = self.context.response_factory.create_response(
            custom_message, status_code
        )

        response = await self.apply_security_headers(response)

        response = await self.apply_modifier(response)

        return response

    async def create_https_redirect(self, request: GuardRequest) -> GuardResponse:
        https_url = request.url_replace_scheme("https")
        redirect_response = self.context.response_factory.create_redirect_response(
            str(https_url), 301
        )

        return await self.apply_modifier(redirect_response)

    async def apply_security_headers(
        self, response: GuardResponse, request_path: str | None = None
    ) -> GuardResponse:
        if self.security_headers_manager.headers_enabled_for(self.context.config):
            resolved = await self.security_headers_manager.get_headers_and_forced(
                request_path, config=self.context.config
            )
            security_headers, forced = resolved
            for header_name, header_value in security_headers.items():
                if header_name.lower() in forced:
                    _drop_other_spellings(response.headers, header_name)
                elif _header_present(response.headers, header_name):
                    continue
                response.headers[header_name] = header_value

        return response

    async def apply_cors_headers(
        self, response: GuardResponse, origin: str
    ) -> GuardResponse:
        if self.security_headers_manager.headers_enabled_for(self.context.config):
            cors_headers = await self.security_headers_manager.get_cors_headers(
                origin, config=self.context.config
            )
            for header_name, header_value in cors_headers.items():
                response.headers[header_name] = header_value

        return response

    async def apply_modifier(self, response: GuardResponse) -> GuardResponse:
        if self.context.config.custom_response_modifier:
            try:
                result: GuardResponse = (
                    await self.context.config.custom_response_modifier(response)
                )
                return result
            except Exception as exc:
                self.logger.exception(
                    "custom_response_modifier raised %s; returning unmodified response",
                    exc,
                )
        return response

    async def process_response(
        self,
        request: GuardRequest,
        response: GuardResponse,
        response_time: float,
        route_config: RouteConfig | None,
        process_behavioral_rules: Callable[
            [GuardRequest, GuardResponse, str, RouteConfig], Awaitable[None]
        ]
        | None = None,
        process_global_behavioral_rules: Callable[
            [GuardRequest, GuardResponse, str, list[BehaviorRule]], Awaitable[None]
        ]
        | None = None,
    ) -> GuardResponse:
        client_ip = await self._resolve_client_ip_for_behavioral_rules(
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
            await process_behavioral_rules(request, response, client_ip, route_config)

        if (
            client_ip is not None
            and self.context.config.global_behavior_rules
            and process_global_behavioral_rules is not None
        ):
            global_rules = [
                config_to_rule(cfg) for cfg in self.context.config.global_behavior_rules
            ]
            await process_global_behavioral_rules(
                request, response, client_ip, global_rules
            )

        await self.context.metrics_collector.collect_request_metrics(
            request, response_time, response.status_code
        )

        response = await self.apply_security_headers(response, str(request.url_path))

        origin = request.headers.get("origin")
        if origin:
            response = await self.apply_cors_headers(response, origin)

        return await self.apply_modifier(response)

    async def _resolve_client_ip_for_behavioral_rules(
        self,
        request: GuardRequest,
        route_config: RouteConfig | None,
        process_behavioral_rules: Callable[
            [GuardRequest, GuardResponse, str, RouteConfig], Awaitable[None]
        ]
        | None,
        process_global_behavioral_rules: Callable[
            [GuardRequest, GuardResponse, str, list[BehaviorRule]], Awaitable[None]
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
        return await extract_client_ip(
            request, self.context.config, self.context.agent_handler
        )
