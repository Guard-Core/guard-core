from collections.abc import Collection

from guard_core.core.callable_slot import CallableSlot
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.events.event_types import EVENT_CUSTOM_REQUEST_CHECK
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class CustomRequestCheck(SecurityCheck):
    def __init__(self, middleware: "GuardMiddlewareProtocol") -> None:
        super().__init__(middleware)
        self._slot: CallableSlot[GuardRequest, GuardResponse | None] = CallableSlot(
            "custom_request_check", self.config.custom_request_check
        )

    @property
    def check_name(self) -> str:
        return "custom_request"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return config.custom_request_check is not None

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        configured = self.config.custom_request_check
        if not configured:
            return None

        slot = self._slot
        if configured is not slot.source:
            slot.adopt(configured)
        custom_response = await slot.invoke(request)
        if custom_response:
            await self.middleware.event_bus.send_middleware_event(
                event_type=EVENT_CUSTOM_REQUEST_CHECK,
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason="Custom request check returned blocking response",
                response_status=custom_response.status_code
                if hasattr(custom_response, "status_code")
                else "unknown",
                check_function=configured.__name__
                if hasattr(configured, "__name__")
                else "anonymous",
            )

            if not self.config.passive_mode:
                modified: GuardResponse = (
                    await self.middleware.response_factory.apply_modifier(
                        custom_response
                    )
                )
                return modified
        return None
