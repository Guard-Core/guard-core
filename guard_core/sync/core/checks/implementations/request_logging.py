from collections.abc import Collection

from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.decorators.base import RouteConfig
from guard_core.models import SecurityConfig, SyncSecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.utils import log_activity


class RequestLoggingCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "request_logging"

    @classmethod
    def applies_to(
        cls,
        config: SyncSecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return config.log_request_level is not None

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        log_activity(
            request,
            self.logger,
            level=self.config.log_request_level,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )
        return None
