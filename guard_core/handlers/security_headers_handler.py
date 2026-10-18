import logging
import threading
from typing import Any

from cachetools import TTLCache

from guard_core._security_headers_defaults import security_headers_are_off
from guard_core.handlers._security_headers_cache import SecurityHeadersCacheMixin
from guard_core.handlers._security_headers_config import SecurityHeadersConfigMixin
from guard_core.handlers._security_headers_cors import SecurityHeadersCorsMixin
from guard_core.handlers._security_headers_events import SecurityHeadersEventsMixin
from guard_core.models import SecurityConfig


class ResolvedHeaders(dict[str, str]):
    forced: frozenset[str] = frozenset()


class SecurityHeadersManager(
    SecurityHeadersConfigMixin,
    SecurityHeadersCacheMixin,
    SecurityHeadersCorsMixin,
    SecurityHeadersEventsMixin,
):
    _instance: "SecurityHeadersManager | None" = None
    _lock = threading.Lock()
    headers_cache: TTLCache
    redis_handler: Any = None
    agent_handler: Any = None
    logger: logging.Logger
    enabled: bool
    custom_headers: dict[str, str]
    csp_config: dict[str, list[str]] | None
    hsts_config: dict[str, Any] | None
    cors_config: dict[str, Any] | None

    default_headers: dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "X-XSS-Protection": "0",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "X-Permitted-Cross-Domain-Policies": "none",
        "X-Download-Options": "noopen",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-site",
    }

    def __new__(cls: type["SecurityHeadersManager"]) -> "SecurityHeadersManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialize_state()
                    cls._instance = instance
        return cls._instance

    @classmethod
    def isolated(cls) -> "SecurityHeadersManager":
        instance = super().__new__(cls)
        instance._initialize_state()
        return instance

    def _initialize_state(self) -> None:
        self.headers_cache = TTLCache(maxsize=1000, ttl=300)
        self.redis_handler = None
        self.agent_handler = None
        self.logger = logging.getLogger("guard_core.handlers.security_headers")
        self.enabled = True
        self.custom_headers = {}
        self.csp_config = None
        self.hsts_config = None
        self.cors_config = None
        self.default_headers = self.__class__.default_headers.copy()

    def _build_csp(self, csp_config: dict[str, list[str]]) -> str:
        directives = []
        for directive, sources in csp_config.items():
            if sources:
                sources_str = " ".join(sources)
                directives.append(f"{directive} {sources_str}")
            else:
                directives.append(directive)
        return "; ".join(directives)

    def _build_hsts(self, hsts_config: dict[str, Any]) -> str:
        parts = [f"max-age={hsts_config['max_age']}"]
        if hsts_config.get("include_subdomains"):
            parts.append("includeSubDomains")
        if hsts_config.get("preload"):
            parts.append("preload")
        return "; ".join(parts)

    def _forced_header_names(
        self,
        csp_config: dict[str, list[str]] | None,
        hsts_config: dict[str, Any] | None,
        default_headers: dict[str, str],
        custom_headers: dict[str, str],
    ) -> frozenset[str]:
        class_defaults = self.__class__.default_headers
        forced = {name.lower() for name in custom_headers}
        forced.update(
            name.lower()
            for name, value in default_headers.items()
            if class_defaults.get(name) != value
        )
        if csp_config:
            forced.add("content-security-policy")
        if hsts_config:
            forced.add("strict-transport-security")
        return frozenset(forced)

    def _headers_for(
        self, config: SecurityConfig | None, cache_key: str
    ) -> tuple[dict[str, str], bool]:
        cached = self.headers_cache.get(cache_key)
        if isinstance(cached, dict):
            return cached, False

        csp_config, hsts_config, default_headers, custom_headers = (
            self._resolve_headers_state(config)
        )

        headers = ResolvedHeaders(default_headers)

        if csp_config:
            headers["Content-Security-Policy"] = self._build_csp(csp_config)

        if hsts_config:
            headers["Strict-Transport-Security"] = self._build_hsts(hsts_config)

        headers.update(custom_headers)
        headers.forced = self._forced_header_names(
            csp_config, hsts_config, default_headers, custom_headers
        )

        self.headers_cache[cache_key] = headers
        return headers, True

    def resolve_headers(self, config: SecurityConfig) -> dict[str, str]:
        if security_headers_are_off(config.security_headers):
            return {}
        headers, _ = self._headers_for(config, self._generate_cache_key(None, config))
        return headers

    async def get_headers(
        self,
        request_path: str | None = None,
        config: SecurityConfig | None = None,
    ) -> dict[str, str]:
        if config is not None:
            if security_headers_are_off(config.security_headers):
                return {}
        elif not self.enabled:
            return {}

        cache_key = self._generate_cache_key(request_path, config)
        headers, is_new = self._headers_for(config, cache_key)

        if is_new and self.agent_handler and request_path:
            await self._send_headers_applied_event(request_path, headers)

        return headers

    async def get_headers_and_forced(
        self,
        request_path: str | None = None,
        config: SecurityConfig | None = None,
    ) -> tuple[dict[str, str], frozenset[str]]:
        headers = await self.get_headers(request_path, config)
        forced = headers.forced if isinstance(headers, ResolvedHeaders) else frozenset()
        return headers, forced


security_headers_manager = SecurityHeadersManager()


async def reset_global_state() -> None:
    global security_headers_manager
    manager = SecurityHeadersManager()
    await manager.reset()
    security_headers_manager = manager
