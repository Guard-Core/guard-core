from abc import ABC, abstractmethod
from collections.abc import Collection
from typing import TYPE_CHECKING, Any, ClassVar

from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

if TYPE_CHECKING:
    from guard_core.decorators.base import RouteConfig
    from guard_core.models import SecurityConfig
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol


class SecurityCheck(ABC):
    requires: ClassVar[tuple[str, ...]] = ()
    container_fields: ClassVar[tuple[str, ...]] = ()
    enforced_on_excluded_paths: ClassVar[bool] = False
    defers_ban_read: ClassVar[bool] = False
    # True for a check that can leave a ban read pending or resolve one itself
    leaves_ban_pending: ClassVar[bool] = False

    def __init__(self, middleware: "GuardMiddlewareProtocol") -> None:
        self.middleware = middleware
        self.config = middleware.config
        self.logger = middleware.logger
        from guard_core.handlers.ipban_handler import ip_ban_manager_for

        self.ip_ban_manager = ip_ban_manager_for(middleware.config)

    @classmethod
    def applies_to(
        cls,
        config: "SecurityConfig",
        route_configs: "Collection[RouteConfig] | None",
    ) -> bool:
        return True

    @property
    def needs_route_identity(self) -> bool:
        return False

    @abstractmethod
    async def check(self, request: GuardRequest) -> GuardResponse | None: ...

    @property
    @abstractmethod
    def check_name(self) -> str: ...

    async def send_event(
        self,
        event_type: str,
        request: GuardRequest,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        await self.middleware.event_bus.send_middleware_event(
            event_type=event_type,
            request=request,
            action_taken=action_taken,
            reason=reason,
            **kwargs,
        )

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        return await self.middleware.create_error_response(status_code, default_message)

    def is_passive_mode(self) -> bool:
        return self.config.passive_mode

    async def log_if_allowed(
        self,
        request: GuardRequest,
        *,
        log_type: str = "request",
        reason: str = "",
        passive_mode: bool = False,
        trigger_info: str = "",
        level: Any = "WARNING",
    ) -> None:
        from guard_core.utils import log_activity

        await log_activity(
            request,
            self.logger,
            log_type=log_type,
            reason=reason,
            passive_mode=passive_mode,
            trigger_info=trigger_info,
            level=level,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )
