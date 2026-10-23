import base64
import binascii
import contextlib
import traceback
from collections.abc import Collection
from typing import Any

from guard_core.core.checks._pending_ban import resolve_pending_ban
from guard_core.core.checks._verifier import resolve_verifier_result
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.helpers import (
    emit_authentication_failed_event,
    extract_credential,
    report_hostile_signal,
    route_config_applies,
)
from guard_core.core.events.event_types import (
    EVENT_AUTH_VERIFIER_ERROR,
    EVENT_DECORATOR_VIOLATION,
)
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity

_CHALLENGES = {
    "basic": 'Basic realm="Restricted"',
    "api_key": "ApiKey",
}


def _challenge_for(auth_type: str) -> str:
    return _CHALLENGES.get(auth_type, auth_type.title())


def _secrets_in_credential(credential: str, auth_type: str) -> list[str]:
    secrets = [credential]
    if auth_type == "basic":
        with contextlib.suppress(binascii.Error, UnicodeDecodeError):
            user_pass = base64.b64decode(credential).decode()
            secrets += [user_pass, user_pass.partition(":")[2]]
    # Longest first, so the password inside user:password is never redacted alone.
    return sorted(filter(None, secrets), key=len, reverse=True)


def _describe_verifier_error(exc: Exception, credential: str, auth_type: str) -> str:
    trace = "".join(traceback.format_exception(exc))
    for secret in _secrets_in_credential(credential, auth_type):
        trace = trace.replace(secret, "[REDACTED]")
    return f"Authentication verifier raised {type(exc).__name__}\n{trace}"


class AuthenticationCheck(SecurityCheck):
    defers_ban_read = True
    leaves_ban_pending = True

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

    async def _handle_auth_failure(
        self,
        request: GuardRequest,
        auth_reason: str,
        route_config: RouteConfig,
        violation_type: str = "require_auth",
        auth_type: str | None = None,
        verifier_error: bool = False,
        **metadata: Any,
    ) -> GuardResponse | None:
        auth_type = (
            auth_type
            or route_config.auth_required
            or route_config.authorization_header_required
            or "api_key"
        )
        if verifier_error:
            return await self._report_verifier_error(
                request, auth_reason, violation_type, auth_type
            )
        banned = await resolve_pending_ban(request, "auth_failure")
        if banned is not None:
            return banned

        await log_activity(
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
        await emit_authentication_failed_event(
            self.middleware,
            request,
            event_type=EVENT_DECORATOR_VIOLATION,
            reason=auth_reason,
            auth_type=auth_type,
            violation_type=violation_type,
            passive_mode=self.config.passive_mode,
            **metadata,
        )
        await report_hostile_signal(self, request, "auth_failure", auth_reason)

        if not self.config.passive_mode:
            response: GuardResponse = await self.middleware.create_error_response(
                status_code=401,
                default_message="Authentication required",
            )
            response.headers["WWW-Authenticate"] = _challenge_for(auth_type)
            return response

        return None

    async def _report_verifier_error(
        self,
        request: GuardRequest,
        auth_reason: str,
        violation_type: str,
        auth_type: str,
    ) -> GuardResponse | None:
        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_AUTH_VERIFIER_ERROR,
            request=request,
            action_taken="logged_only"
            if self.config.passive_mode
            else "request_blocked",
            reason=auth_reason,
            decorator_type="authentication",
            violation_type=violation_type,
            auth_type=auth_type,
        )
        return await self._respond_to_verifier_error()

    async def _respond_to_verifier_error(self) -> GuardResponse | None:
        if self.config.passive_mode:
            return None
        return await self.middleware.create_error_response(
            status_code=503,
            default_message="Authentication service unavailable",
        )

    async def _check_presence(
        self, request: GuardRequest, route_config: RouteConfig, scheme: str
    ) -> GuardResponse | None:
        auth_header = request.headers.get("authorization", "")
        credential, reason = extract_credential(auth_header, scheme)
        if credential is None:
            return await self._handle_auth_failure(
                request, reason, route_config, violation_type="authorization_header"
            )
        return None

    async def _verify_credential(
        self,
        request: GuardRequest,
        route_config: RouteConfig,
        *,
        credential: str | None,
        missing_reason: str,
        verifier: Any,
        auth_type: str,
        violation_type: str,
        missing_metadata: dict[str, Any] | None = None,
    ) -> tuple[bool, GuardResponse | None, Any]:
        missing_metadata = missing_metadata or {}

        async def fail(
            reason: str, verifier_error: bool = False, **metadata: Any
        ) -> tuple[bool, GuardResponse | None, Any]:
            response = await self._handle_auth_failure(
                request,
                reason,
                route_config,
                violation_type=violation_type,
                auth_type=auth_type,
                verifier_error=verifier_error,
                **metadata,
            )
            return True, response, None

        if credential is None:
            return await fail(missing_reason, **missing_metadata)
        if verifier is None:
            return await fail("No auth verifier configured")
        banned = await resolve_pending_ban(request)
        if banned is not None:
            return True, banned, None
        try:
            result = await resolve_verifier_result(verifier(request, credential))
        except Exception as exc:
            self.logger.error(
                "%s", _describe_verifier_error(exc, credential, auth_type)
            )
            return await fail("Authentication error", verifier_error=True)
        if not result:
            return await fail("Authentication failed")
        return False, None, result

    async def _verify_bearer_credential(
        self, request: GuardRequest, route_config: RouteConfig
    ) -> tuple[bool, GuardResponse | None, Any]:
        scheme = route_config.auth_required or ""
        auth_header = request.headers.get("authorization", "")
        credential, reason = extract_credential(auth_header, scheme)
        return await self._verify_credential(
            request,
            route_config,
            credential=credential,
            missing_reason=reason,
            verifier=route_config.auth_verifier or self.config.auth_verifier,
            auth_type=scheme,
            violation_type="require_auth",
        )

    async def _verify_api_key_credential(
        self, request: GuardRequest, route_config: RouteConfig
    ) -> tuple[bool, GuardResponse | None, Any]:
        key = request.headers.get(route_config.api_key_header or "", "")
        return await self._verify_credential(
            request,
            route_config,
            credential=key or None,
            missing_reason="Missing API key",
            verifier=route_config.api_key_verifier or self.config.auth_verifier,
            auth_type="api_key",
            violation_type="api_key_required",
            missing_metadata={"missing_header": route_config.api_key_header},
        )

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)
        if not route_config:
            return None

        presence_scheme = route_config.authorization_header_required
        if presence_scheme:
            return await self._check_presence(request, route_config, presence_scheme)

        principal: Any = None
        if route_config.auth_required:
            failed, response, principal = await self._verify_bearer_credential(
                request, route_config
            )
            if failed:
                return response
        if route_config.api_key_required:
            failed, response, key_principal = await self._verify_api_key_credential(
                request, route_config
            )
            if failed:
                return response
            principal = principal or key_principal

        if principal is not None:
            request.state.auth_principal = principal
        return None
