from abc import ABC, abstractmethod
from collections.abc import Collection
from typing import TYPE_CHECKING, Any, ClassVar

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.decorators.base import RouteConfig
    from guard_core.sync.protocols.middleware_protocol import (
        SyncGuardMiddlewareProtocol,
    )


class SecurityCheck(ABC):
    requires: ClassVar[tuple[str, ...]] = ()
    container_fields: ClassVar[tuple[str, ...]] = ()
    enforced_on_excluded_paths: ClassVar[bool] = False
    defers_ban_read: ClassVar[bool] = False
    # True for a check that can leave a ban read pending or resolve one itself
    leaves_ban_pending: ClassVar[bool] = False

    def __init__(self, middleware: "SyncGuardMiddlewareProtocol") -> None:
        self.middleware = middleware
        self.config = middleware.config
        self.logger = middleware.logger
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for

        self.ip_ban_manager = ip_ban_manager_for(middleware.config)

    @classmethod
    def applies_to(
        cls,
        config: "SyncSecurityConfig",
        route_configs: "Collection[RouteConfig] | None",
    ) -> bool:
        return True

    @property
    def needs_route_identity(self) -> bool:
        return False

    @abstractmethod
    def check(self, request: SyncGuardRequest) -> GuardResponse | None: ...

    @property
    @abstractmethod
    def check_name(self) -> str: ...

    def send_event(
        self,
        event_type: str,
        request: SyncGuardRequest,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        self.middleware.event_bus.send_middleware_event(
            event_type=event_type,
            request=request,
            action_taken=action_taken,
            reason=reason,
            **kwargs,
        )

    def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        return self.middleware.create_error_response(status_code, default_message)

    def is_passive_mode(self) -> bool:
        return self.config.passive_mode

    def log_if_allowed(
        self,
        request: SyncGuardRequest,
        *,
        log_type: str = "request",
        reason: str = "",
        passive_mode: bool = False,
        trigger_info: str = "",
        level: Any = "WARNING",
    ) -> None:
        from guard_core.sync.utils import log_activity

        log_activity(
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
