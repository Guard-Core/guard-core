import logging
from dataclasses import dataclass, field

from guard_core._misconfiguration import (
    report_misconfiguration,
    wildcard_cors_credentials_problems,
)
from guard_core._security_headers_override import CorsParams, cors_params_of
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequestHeaders

cors_logger = logging.getLogger("guard_core.handlers.cors_handler")

ALLOWED_PREFLIGHT_REQUEST_HEADER = "access-control-request-method"


@dataclass(frozen=True)
class CorsPreflightResponse:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""


def is_preflight(method: str, headers: GuardRequestHeaders) -> bool:
    if method.upper() != "OPTIONS":
        return False
    return ALLOWED_PREFLIGHT_REQUEST_HEADER in {k.lower() for k in headers.keys()}


def _lower_headers(headers: GuardRequestHeaders) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def _merge_vary(existing: str | None) -> str:
    if not existing or not existing.strip():
        return "Origin"
    tokens = {token.strip().lower() for token in existing.split(",")}
    if tokens & {"origin", "*"}:
        return existing
    return f"{existing}, Origin"


class CorsHandler:
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self._security_headers = SecurityHeadersManager.isolated()
        self._applied_override: object | None = None
        self._enabled = False
        self._init_disabled()
        self._check_wildcard_with_credentials(config)
        self._apply(cors_params_of(config))

    def _init_disabled(self) -> None:
        self._allow_all = False
        self._allow_origins: set[str] = set()
        self._allow_methods: list[str] = []
        self._allow_headers: list[str] = []
        self._allow_all_headers = False
        self._allow_credentials = False
        self._max_age = 600
        self._expose_headers: list[str] = []

    def _check_wildcard_with_credentials(self, config: SecurityConfig) -> None:
        if config._misconfigurations_checked:
            return
        for problem in wildcard_cors_credentials_problems(config):
            report_misconfiguration(config, problem, logger=cors_logger, stacklevel=4)

    def _apply(self, params: CorsParams) -> None:
        self._enabled = params.enabled
        if not params.enabled:
            self._init_disabled()
            return
        origins = list(params.origins)
        self._allow_all = "*" in origins
        self._allow_origins = {origin.rstrip("/") for origin in origins}
        self._allow_methods = [m.upper() for m in (params.methods or ["GET"])]
        self._allow_headers = [h.lower() for h in params.headers]
        self._allow_all_headers = "*" in self._allow_headers
        self._allow_credentials = bool(params.credentials) and not self._allow_all
        self._max_age = int(params.max_age)
        self._expose_headers = list(params.expose)

    def _refresh(self) -> None:
        # The override a flagged configure() set, in this process or pulled from Redis,
        # is applied when its record changes (a record is replaced, never edited).
        override = self._security_headers.override_for_reader(self.config)
        if override is self._applied_override:
            return
        self._applied_override = override
        self._apply(self._security_headers.cors_params_for(self.config))

    def is_enabled(self) -> bool:
        self._refresh()
        return self._enabled

    def is_origin_allowed(self, origin: str) -> bool:
        self._refresh()
        return self._origin_allowed(origin)

    def _origin_allowed(self, origin: str) -> bool:
        if not self._enabled:
            return False
        if self._allow_all:
            return True
        return origin in self._allow_origins

    def _validate_preflight_origin(
        self,
        origin: str,
        response_headers: dict[str, str],
        failures: list[str],
    ) -> None:
        if self._origin_allowed(origin):
            response_headers["Access-Control-Allow-Origin"] = (
                "*" if self._allow_all and not self._allow_credentials else origin
            )
        else:
            failures.append("origin")

    def _validate_preflight_method(
        self,
        requested_method: str,
        failures: list[str],
    ) -> None:
        if requested_method not in self._allow_methods:
            failures.append("method")

    def _validate_preflight_headers(
        self,
        requested_headers: list[str],
        requested_headers_raw: str,
        response_headers: dict[str, str],
        failures: list[str],
    ) -> None:
        if self._allow_all_headers:
            if requested_headers_raw:
                response_headers["Access-Control-Allow-Headers"] = requested_headers_raw
        elif any(h not in self._allow_headers for h in requested_headers):
            failures.append("headers")

    def build_preflight_response(
        self, request_headers: GuardRequestHeaders
    ) -> CorsPreflightResponse:
        self._refresh()
        headers = _lower_headers(request_headers)
        origin = headers.get("origin", "")
        requested_method = headers.get("access-control-request-method", "").upper()
        requested_headers_raw = headers.get("access-control-request-headers", "")
        requested_headers = [
            h.strip().lower() for h in requested_headers_raw.split(",") if h.strip()
        ]

        failures: list[str] = []
        response_headers: dict[str, str] = {
            **self._security_headers.resolve_headers(self.config),
            "Vary": "Origin",
        }

        self._validate_preflight_origin(origin, response_headers, failures)
        self._validate_preflight_method(requested_method, failures)
        self._validate_preflight_headers(
            requested_headers, requested_headers_raw, response_headers, failures
        )

        response_headers["Access-Control-Allow-Methods"] = ", ".join(
            self._allow_methods
        )
        response_headers["Access-Control-Max-Age"] = str(self._max_age)

        if self._allow_credentials:
            response_headers["Access-Control-Allow-Credentials"] = "true"

        if failures:
            return CorsPreflightResponse(
                status_code=400,
                headers=response_headers,
                body=f"Disallowed CORS: {', '.join(failures)}",
            )
        return CorsPreflightResponse(
            status_code=200,
            headers=response_headers,
            body="OK",
        )

    def build_response_headers(
        self, request_headers: GuardRequestHeaders, existing_vary: str | None = None
    ) -> dict[str, str]:
        self._refresh()
        if not self._enabled:
            return {}
        headers = _lower_headers(request_headers)
        origin = headers.get("origin", "")

        result: dict[str, str] = {"Vary": _merge_vary(existing_vary)}
        if not origin:
            return result

        if self._allow_all and not self._allow_credentials:
            result["Access-Control-Allow-Origin"] = "*"
        elif self._origin_allowed(origin):
            result["Access-Control-Allow-Origin"] = origin
        else:
            return result

        if self._allow_credentials:
            result["Access-Control-Allow-Credentials"] = "true"

        if self._expose_headers:
            result["Access-Control-Expose-Headers"] = ", ".join(self._expose_headers)

        return result
