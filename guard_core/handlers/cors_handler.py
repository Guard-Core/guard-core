from collections.abc import Mapping
from dataclasses import dataclass, field

from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig

ALLOWED_PREFLIGHT_REQUEST_HEADER = "access-control-request-method"


@dataclass(frozen=True)
class CorsPreflightResponse:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""


def is_preflight(method: str, headers: Mapping[str, str]) -> bool:
    if method.upper() != "OPTIONS":
        return False
    return ALLOWED_PREFLIGHT_REQUEST_HEADER in {k.lower() for k in headers}


def _lower_headers(headers: Mapping[str, str]) -> dict[str, str]:
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
        self._enabled = bool(config.enable_cors)
        if not self._enabled:
            self._init_disabled()
        else:
            self._init_enabled(config)

    def _init_disabled(self) -> None:
        self._allow_all = False
        self._allow_origins: set[str] = set()
        self._allow_methods: list[str] = []
        self._allow_headers: list[str] = []
        self._allow_all_headers = False
        self._allow_credentials = False
        self._max_age = 600
        self._expose_headers: list[str] = []

    def _init_enabled(self, config: SecurityConfig) -> None:
        origins = list(config.cors_allow_origins or [])
        self._allow_all = "*" in origins
        if self._allow_all and config.cors_allow_credentials:
            raise ValueError(
                "CORS misconfiguration: wildcard origin '*' is incompatible "
                "with cors_allow_credentials=True"
            )
        self._allow_origins = {origin.rstrip("/") for origin in origins}
        self._allow_methods = [
            m.upper() for m in (config.cors_allow_methods or ["GET"])
        ]
        self._allow_headers = [h.lower() for h in (config.cors_allow_headers or [])]
        self._allow_all_headers = "*" in self._allow_headers
        self._allow_credentials = bool(config.cors_allow_credentials)
        self._max_age = int(config.cors_max_age)
        self._expose_headers = list(config.cors_expose_headers or [])

    def is_origin_allowed(self, origin: str) -> bool:
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
        if self.is_origin_allowed(origin):
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
        self, request_headers: Mapping[str, str]
    ) -> CorsPreflightResponse:
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
        self, request_headers: Mapping[str, str], existing_vary: str | None = None
    ) -> dict[str, str]:
        if not self._enabled:
            return {}
        headers = _lower_headers(request_headers)
        origin = headers.get("origin", "")

        result: dict[str, str] = {"Vary": _merge_vary(existing_vary)}
        if not origin:
            return result

        if self._allow_all and not self._allow_credentials:
            result["Access-Control-Allow-Origin"] = "*"
        elif self.is_origin_allowed(origin):
            result["Access-Control-Allow-Origin"] = origin
        else:
            return result

        if self._allow_credentials:
            result["Access-Control-Allow-Credentials"] = "true"

        if self._expose_headers:
            result["Access-Control-Expose-Headers"] = ", ".join(self._expose_headers)

        return result
