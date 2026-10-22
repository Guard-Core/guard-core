import logging
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from guard_core._security_headers_override import PROCESS_OVERRIDE, PULLED_OVERRIDES
from guard_core.core.responses.context import ResponseContext
from guard_core.decorators.base import RouteConfig
from guard_core.handlers.behavior_handler import BehaviorRule, config_to_rule
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import extract_client_ip


def _drop_other_spellings(headers: dict[str, str], name: str) -> None:
    lowered = name.lower()
    for key in [key for key in headers if key.lower() == lowered and key != name]:
        del headers[key]


def _merge_into_foreign_headers(
    headers: MutableMapping[str, str],
    security_headers: dict[str, str],
    forced: frozenset[str],
) -> None:
    for name, value in security_headers.items():
        if name.lower() in forced or name not in headers:
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
        status_code = 301 if request.method.upper() in ("GET", "HEAD") else 308
        redirect_response = self.context.response_factory.create_redirect_response(
            str(https_url), status_code
        )

        return await self.apply_modifier(redirect_response)

    async def apply_security_headers(
        self,
        response: GuardResponse,
        request_path: str | None = None,
        override: Any = None,
    ) -> GuardResponse:
        manager = self.security_headers_manager
        if override is None:
            override = manager.resolve_override()
        enabled = manager.headers_enabled_for(self.context.config, override)
        return await self._apply_security_headers(
            response, request_path, override, enabled
        )

    async def _apply_security_headers(
        self,
        response: GuardResponse,
        request_path: str | None,
        override: Any,
        enabled: bool,
    ) -> GuardResponse:
        if not enabled:
            return response
        security_headers = await self.security_headers_manager.get_headers(
            request_path,
            config=self.context.config,
            override=override,
            checked=True,
        )
        forced: frozenset[str] = getattr(security_headers, "forced", frozenset())
        _merge_security_headers(response.headers, security_headers, forced)
        return response

    async def apply_cors_headers(
        self, response: GuardResponse, origin: str, override: Any = None
    ) -> GuardResponse:
        if override is None:
            override = self.security_headers_manager.resolve_override()
        return await self._apply_cors_headers(response, origin, override)

    async def _apply_cors_headers(
        self, response: GuardResponse, origin: str, override: Any
    ) -> GuardResponse:
        # CORS follows the CORS settings alone: the security headers switch never
        # governs it.
        cors_headers = await self.security_headers_manager.get_cors_headers(
            origin, config=self.context.config, override=override
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

    async def _apply_response_headers(
        self, request: GuardRequest, response: GuardResponse
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
            config.enable_redis,
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
        response = await self._apply_security_headers(
            response, str(request.url_path), override, enabled
        )
        origin = request.headers.get("origin")
        if origin and not skip_cors:
            response = await self._apply_cors_headers(response, origin, override)
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

        response = await self._apply_response_headers(request, response)

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
