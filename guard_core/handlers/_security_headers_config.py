import logging
from abc import abstractmethod
from collections.abc import Mapping

from cachetools import TTLCache

from guard_core._security_headers_defaults import (
    SECURITY_HEADER_NAMES,
    default_security_headers_config,
    effective_security_headers_config,
)
from guard_core._security_headers_override import (
    NOT_PASSED,
    PERMISSIONS_POLICY_NOT_PASSED,
    PULLED_OVERRIDES,
    CorsParams,
    OverrideRecord,
    _NotPassed,
    apply_override,
    checked_header_name,
    checked_header_value,
    override_from_call,
    passed_or,
    validate_cors_override,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.redis_protocol import RedisHandlerProtocol


class SecurityHeadersConfigMixin:
    logger: logging.Logger
    enabled: bool
    custom_headers: dict[str, str]
    csp_config: dict[str, list[str]] | None
    hsts_config: dict[str, object] | None
    cors_config: dict[str, object] | None
    default_headers: dict[str, str]
    headers_cache: TTLCache
    redis_handler: RedisHandlerProtocol | None
    _startup_hash: str | None
    _own_state_dirty: bool

    @abstractmethod
    def _current_override(self) -> OverrideRecord: ...

    @abstractmethod
    def pulled_override_for(self, config: SecurityConfig) -> OverrideRecord | None: ...

    @abstractmethod
    def cors_params_for(
        self, config: SecurityConfig, current: OverrideRecord | None = None
    ) -> CorsParams: ...

    @abstractmethod
    def _record_override_from_call(self, passed: dict[str, object]) -> None: ...

    def _validate_header_name(self, name: str) -> str:
        return checked_header_name(name)

    def _validate_header_value(self, value: str) -> str:
        return checked_header_value(value)

    def _compute_csp_config(self, csp: object) -> dict[str, list[str]] | None:
        if not csp:
            return None
        if not isinstance(csp, dict):
            raise TypeError("the csp setting must map each directive to its sources")

        for directive, sources in csp.items():
            if "'unsafe-inline'" in sources or "'unsafe-eval'" in sources:
                self.logger.warning(
                    f"CSP directive '{directive}' contains unsafe sources"
                )
        return csp

    def _configure_csp(self, csp: dict[str, list[str]] | None) -> None:
        self.csp_config = self._compute_csp_config(csp)

    def _compute_hsts_config(
        self,
        hsts_max_age: int | None,
        hsts_include_subdomains: bool,
        hsts_preload: bool,
    ) -> dict[str, object] | None:
        if hsts_max_age is None:
            return None

        if hsts_preload:
            if hsts_max_age < 31536000:
                self.logger.warning("HSTS preload requires max_age >= 31536000")
                hsts_preload = False
            if not hsts_include_subdomains:
                self.logger.warning("HSTS preload requires includeSubDomains")
                hsts_include_subdomains = True

        return {
            "max_age": hsts_max_age,
            "include_subdomains": hsts_include_subdomains,
            "preload": hsts_preload,
        }

    def _configure_hsts(
        self,
        hsts_max_age: int | None,
        hsts_include_subdomains: bool,
        hsts_preload: bool,
    ) -> None:
        self.hsts_config = self._compute_hsts_config(
            hsts_max_age, hsts_include_subdomains, hsts_preload
        )

    def _compute_cors_config(
        self,
        cors_origins: list[str] | None,
        cors_allow_credentials: bool,
        cors_allow_methods: list[str] | None,
        cors_allow_headers: list[str] | None,
        cors_max_age: int | None = None,
    ) -> dict[str, object] | None:
        if not cors_origins:
            return None

        if "*" in cors_origins and cors_allow_credentials:
            self.logger.error(
                "CORS config error: Wildcard origin disallowed with credentials"
            )
            cors_allow_credentials = False

        return {
            "origins": [origin.rstrip("/") for origin in cors_origins],
            "allow_credentials": cors_allow_credentials,
            "allow_methods": cors_allow_methods or ["GET", "POST"],
            "allow_headers": ["*"]
            if cors_allow_headers is None
            else list(cors_allow_headers),
            "max_age": 3600 if cors_max_age is None else cors_max_age,
        }

    def _configure_cors(
        self,
        cors_origins: list[str] | None,
        cors_allow_credentials: bool,
        cors_allow_methods: list[str] | None,
        cors_allow_headers: list[str] | None,
        cors_max_age: int | None = None,
    ) -> None:
        self.cors_config = self._compute_cors_config(
            cors_origins,
            cors_allow_credentials,
            cors_allow_methods,
            cors_allow_headers,
            cors_max_age,
        )

    def _reset_or_apply_header(
        self,
        headers: dict[str, str],
        header_name: str,
        override: str | None,
        class_default: str,
    ) -> None:
        headers[header_name] = (
            self._validate_header_value(override)
            if override is not None
            else class_default
        )

    def _compute_default_headers(
        self,
        frame_options: str | None,
        content_type_options: str | None,
        xss_protection: str | None,
        referrer_policy: str | None,
        permissions_policy: str | None,
    ) -> dict[str, str]:
        class_defaults = self.__class__.default_headers
        headers = class_defaults.copy()
        self._reset_or_apply_header(
            headers, "X-Frame-Options", frame_options, class_defaults["X-Frame-Options"]
        )
        self._reset_or_apply_header(
            headers,
            "X-Content-Type-Options",
            content_type_options,
            class_defaults["X-Content-Type-Options"],
        )
        self._reset_or_apply_header(
            headers,
            "X-XSS-Protection",
            xss_protection,
            class_defaults["X-XSS-Protection"],
        )
        self._reset_or_apply_header(
            headers,
            "Referrer-Policy",
            referrer_policy,
            class_defaults["Referrer-Policy"],
        )

        if permissions_policy == "UNSET":
            headers["Permissions-Policy"] = class_defaults["Permissions-Policy"]
        elif permissions_policy:
            headers["Permissions-Policy"] = self._validate_header_value(
                permissions_policy
            )
        else:
            headers.pop("Permissions-Policy", None)

        return headers

    def _update_default_headers(
        self,
        frame_options: str | None,
        content_type_options: str | None,
        xss_protection: str | None,
        referrer_policy: str | None,
        permissions_policy: str | None,
    ) -> None:
        self.default_headers = self._compute_default_headers(
            frame_options,
            content_type_options,
            xss_protection,
            referrer_policy,
            permissions_policy,
        )

    def _compute_custom_headers(self, custom_headers: object) -> dict[str, str]:
        if not custom_headers:
            return {}
        if not isinstance(custom_headers, dict):
            raise TypeError("the custom setting must map header names to values")

        return {
            self._validate_header_name(name): self._validate_header_value(value)
            for name, value in custom_headers.items()
        }

    def _add_custom_headers(self, custom_headers: dict[str, str] | None) -> None:
        self.custom_headers = self._compute_custom_headers(custom_headers)

    def _resolve_headers_state(
        self, config: SecurityConfig | None, current: OverrideRecord | None = None
    ) -> tuple[
        dict[str, list[str]] | None,
        dict[str, object] | None,
        dict[str, str],
        dict[str, str],
    ]:
        if config is None:
            return (
                self.csp_config,
                self.hsts_config,
                self.default_headers,
                self.custom_headers,
            )

        override = (self._current_override() if current is None else current).keys
        base = effective_security_headers_config(config.security_headers)
        if base is None:
            base = default_security_headers_config() if override.get("enabled") else {}
        effective = apply_override(base, override)
        hsts_cfg = effective.get("hsts") or {}
        if not isinstance(hsts_cfg, dict):
            raise TypeError("the hsts setting must be a mapping of its options")

        csp_config = self._compute_csp_config(effective.get("csp"))
        hsts_config = self._compute_hsts_config(
            hsts_cfg.get("max_age"),
            hsts_cfg.get("include_subdomains", True),
            hsts_cfg.get("preload", False),
        )
        default_headers = self._compute_configured_headers(effective)
        custom_headers = self._compute_custom_headers(effective.get("custom"))

        return csp_config, hsts_config, default_headers, custom_headers

    def _compute_configured_headers(
        self, effective: Mapping[str, object]
    ) -> dict[str, str]:
        headers: dict[str, str] = {}
        for key, header_name in SECURITY_HEADER_NAMES.items():
            value = effective.get(key)
            if value is None or (key == "permissions_policy" and not value):
                continue
            if not isinstance(value, str):
                raise TypeError(f"the {key} setting must be a string")
            headers[header_name] = self._validate_header_value(value)
        return headers

    def _resolve_cors_state(
        self, config: SecurityConfig | None, override: OverrideRecord | None = None
    ) -> dict[str, object] | None:
        if config is None:
            return self.cors_config

        if (
            override is not None
            and not override.keys
            and not (PULLED_OVERRIDES and self.pulled_override_for(config) is not None)
        ):
            # No override: the app's own CORS, without the merge.
            return self._compute_cors_config(
                list(config.cors_allow_origins or ()) if config.enable_cors else None,
                bool(config.cors_allow_credentials),
                list(config.cors_allow_methods or ()),
                list(config.cors_allow_headers or ()),
                int(config.cors_max_age),
            )
        params = self.cors_params_for(config, override)
        return self._compute_cors_config(
            list(params.origins) if params.enabled else None,
            params.credentials,
            list(params.methods),
            list(params.headers),
            params.max_age,
        )

    def configure(
        self,
        *,
        enabled: bool | _NotPassed = NOT_PASSED,
        csp: dict[str, list[str]] | None | _NotPassed = NOT_PASSED,
        hsts_max_age: int | None | _NotPassed = NOT_PASSED,
        hsts_include_subdomains: bool | _NotPassed = NOT_PASSED,
        hsts_preload: bool | _NotPassed = NOT_PASSED,
        frame_options: str | None | _NotPassed = NOT_PASSED,
        content_type_options: str | None | _NotPassed = NOT_PASSED,
        xss_protection: str | None | _NotPassed = NOT_PASSED,
        referrer_policy: str | None | _NotPassed = NOT_PASSED,
        permissions_policy: str | None = PERMISSIONS_POLICY_NOT_PASSED,
        custom_headers: dict[str, str] | None | _NotPassed = NOT_PASSED,
        cors_origins: list[str] | None | _NotPassed = NOT_PASSED,
        cors_allow_credentials: bool | _NotPassed = NOT_PASSED,
        cors_allow_methods: list[str] | None | _NotPassed = NOT_PASSED,
        cors_allow_headers: list[str] | None | _NotPassed = NOT_PASSED,
        enable_cors: bool | _NotPassed = NOT_PASSED,
        cors_max_age: int | None | _NotPassed = NOT_PASSED,
        cors_expose_headers: list[str] | None | _NotPassed = NOT_PASSED,
        override_apps: bool = False,
    ) -> None:
        passed = override_from_call(
            enabled=enabled,
            csp=csp,
            hsts_max_age=hsts_max_age,
            hsts_include_subdomains=hsts_include_subdomains,
            hsts_preload=hsts_preload,
            frame_options=frame_options,
            content_type_options=content_type_options,
            xss_protection=xss_protection,
            referrer_policy=referrer_policy,
            permissions_policy=permissions_policy,
            custom_headers=custom_headers,
            enable_cors=enable_cors,
            cors_origins=cors_origins,
            cors_allow_credentials=cors_allow_credentials,
            cors_allow_methods=cors_allow_methods,
            cors_allow_headers=cors_allow_headers,
            cors_max_age=cors_max_age,
            cors_expose_headers=cors_expose_headers,
        )
        if override_apps:
            validate_cors_override(passed)
        self.enabled = passed_or(enabled, True)
        self.headers_cache.clear()

        self._configure_csp(passed_or(csp, None))
        self._configure_hsts(
            passed_or(hsts_max_age, None),
            passed_or(hsts_include_subdomains, True),
            passed_or(hsts_preload, False),
        )
        self._configure_cors(
            passed_or(cors_origins, None),
            passed_or(cors_allow_credentials, False),
            passed_or(cors_allow_methods, None),
            passed_or(cors_allow_headers, None),
            passed_or(cors_max_age, None),
        )
        self._update_default_headers(
            passed_or(frame_options, None),
            passed_or(content_type_options, None),
            passed_or(xss_protection, None),
            passed_or(referrer_policy, None),
            permissions_policy,
        )
        self._add_custom_headers(passed_or(custom_headers, None))
        if self._startup_hash is not None and self.redis_handler is not None:
            self._own_state_dirty = True
        if override_apps:
            self._record_override_from_call(passed)
