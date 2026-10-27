from collections.abc import Collection

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.callable_slot import CallableSlot
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.events.event_types import EVENT_CUSTOM_REQUEST_CHECK
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.middleware_protocol import SyncGuardMiddlewareProtocol
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

_NO_FACTORY = "'NoneType' object has no attribute '{}'"


class CustomRequestCheck(SecurityCheck):
    def __init__(self, middleware: "SyncGuardMiddlewareProtocol") -> None:
        super().__init__(middleware)
        self._slot: CallableSlot[SyncGuardRequest, GuardResponse | None] = CallableSlot(
            "custom_request_check", self.config.custom_request_check
        )

    @property
    def check_name(self) -> str:
        return "custom_request"

    @classmethod
    def applies_to(
        cls,
        config: SyncSecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return config.custom_request_check is not None

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        configured = self.config.custom_request_check
        if not configured:
            return None

        slot = self._slot
        if configured is not slot.source:
            slot.adopt(configured)
        custom_response = slot.invoke(request)
        if custom_response:
            self.middleware.event_bus.send_middleware_event(
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
                response_factory = self.middleware.response_factory
                if response_factory is None:
                    raise AttributeError(_NO_FACTORY.format("apply_modifier"))
                modified: GuardResponse = response_factory.apply_modifier(
                    custom_response
                )
                return modified
        return None
