from collections.abc import Collection
from typing import Any

from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks._verifier import resolve_verifier_result
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.helpers import (
    emit_authentication_failed_event,
    extract_credential,
    report_hostile_signal,
    route_config_applies,
)
from guard_core.sync.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity


class AuthenticationCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "authentication"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return route_config_applies(
            route_configs,
            lambda rc: (
                bool(rc.auth_required)
                or bool(rc.api_key_required)
                or bool(rc.authorization_header_required)
            ),
        )

    def _handle_auth_failure(
        self,
        request: SyncGuardRequest,
        auth_reason: str,
        route_config: RouteConfig,
        violation_type: str = "require_auth",
        auth_type: str | None = None,
    ) -> GuardResponse | None:
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Authentication failure: {auth_reason}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
            on_block=self.config.on_block,
            sensitive_headers=self.config.log_sensitive_headers,
            sensitive_params=self.config.log_sensitive_params,
            sensitive_body_fields=self.config.log_sensitive_body_fields,
        )

        auth_type = (
            auth_type
            or route_config.auth_required
            or route_config.authorization_header_required
            or "api_key"
        )
        emit_authentication_failed_event(
            self.middleware,
            request,
            event_type=EVENT_DECORATOR_VIOLATION,
            reason=auth_reason,
            auth_type=auth_type,
            violation_type=violation_type,
            passive_mode=self.config.passive_mode,
        )

        report_hostile_signal(self, request, "auth_failure", auth_reason)

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=401,
                default_message="Authentication required",
            )

        return None

    def _check_presence(
        self, request: SyncGuardRequest, route_config: RouteConfig, scheme: str
    ) -> GuardResponse | None:
        auth_header = request.headers.get("authorization", "")
        credential, reason = extract_credential(auth_header, scheme)
        if credential is None:
            return self._handle_auth_failure(
                request, reason, route_config, violation_type="authorization_header"
            )
        return None

    def _verify_credential(
        self,
        request: SyncGuardRequest,
        route_config: RouteConfig,
        *,
        credential: str | None,
        missing_reason: str,
        verifier: Any,
        auth_type: str,
        violation_type: str,
    ) -> tuple[bool, GuardResponse | None, Any]:
        def fail(reason: str) -> tuple[bool, GuardResponse | None, Any]:
            response = self._handle_auth_failure(
                request,
                reason,
                route_config,
                violation_type=violation_type,
                auth_type=auth_type,
            )
            return True, response, None

        if credential is None:
            return fail(missing_reason)
        if verifier is None:
            return fail("No auth verifier configured")
        try:
            result = resolve_verifier_result(verifier(request, credential))
        except Exception:
            return fail("Authentication error")
        if not result:
            return fail("Authentication failed")
        return False, None, result

    def _verify_bearer_credential(
        self, request: SyncGuardRequest, route_config: RouteConfig
    ) -> tuple[bool, GuardResponse | None, Any]:
        scheme = route_config.auth_required or ""
        credential, reason = extract_credential(
            request.headers.get("authorization", ""), scheme
        )
        return self._verify_credential(
            request,
            route_config,
            credential=credential,
            missing_reason=reason,
            verifier=route_config.auth_verifier or self.config.auth_verifier,
            auth_type=scheme,
            violation_type="require_auth",
        )

    def _verify_api_key_credential(
        self, request: SyncGuardRequest, route_config: RouteConfig
    ) -> tuple[bool, GuardResponse | None, Any]:
        key = request.headers.get(route_config.api_key_header or "", "")
        return self._verify_credential(
            request,
            route_config,
            credential=key or None,
            missing_reason="Missing API key",
            verifier=route_config.api_key_verifier or self.config.auth_verifier,
            auth_type="api_key",
            violation_type="api_key_required",
        )

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)
        if not route_config:
            return None

        presence_scheme = route_config.authorization_header_required
        if presence_scheme:
            return self._check_presence(request, route_config, presence_scheme)

        principal: Any = None
        if route_config.auth_required:
            failed, response, principal = self._verify_bearer_credential(
                request, route_config
            )
            if failed:
                return response
        if route_config.api_key_required:
            failed, response, key_principal = self._verify_api_key_credential(
                request, route_config
            )
            if failed:
                return response
            principal = principal or key_principal

        if principal is not None:
            request.state.auth_principal = principal
        return None
