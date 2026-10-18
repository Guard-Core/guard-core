import logging
import threading
from typing import Any

from cachetools import TTLCache

from guard_core.handlers._security_headers_cache import SecurityHeadersCacheMixin
from guard_core.handlers._security_headers_config import SecurityHeadersConfigMixin
from guard_core.handlers._security_headers_cors import SecurityHeadersCorsMixin
from guard_core.handlers._security_headers_events import SecurityHeadersEventsMixin
from guard_core.models import SecurityConfig


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
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "X-Permitted-Cross-Domain-Policies": "none",
        "X-Download-Options": "noopen",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }

    def __new__(cls: type["SecurityHeadersManager"]) -> "SecurityHeadersManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.headers_cache = TTLCache(maxsize=1000, ttl=300)
                    cls._instance.redis_handler = None
                    cls._instance.agent_handler = None
                    cls._instance.logger = logging.getLogger(
                        "guard_core.handlers.security_headers"
                    )
                    cls._instance.enabled = True
                    cls._instance.custom_headers = {}
                    cls._instance.csp_config = None
                    cls._instance.hsts_config = None
                    cls._instance.cors_config = None
                    cls._instance.default_headers = cls.default_headers.copy()
        return cls._instance

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

    def _headers_for(
        self, config: SecurityConfig | None, cache_key: str
    ) -> tuple[dict[str, str], bool]:
        cached = self.headers_cache.get(cache_key)
        if isinstance(cached, dict):
            return cached, False

        csp_config, hsts_config, default_headers, custom_headers = (
            self._resolve_headers_state(config)
        )

        headers = default_headers.copy()

        if csp_config:
            headers["Content-Security-Policy"] = self._build_csp(csp_config)

        if hsts_config:
            headers["Strict-Transport-Security"] = self._build_hsts(hsts_config)

        headers.update(custom_headers)

        self.headers_cache[cache_key] = headers
        return headers, True

    async def get_headers(
        self,
        request_path: str | None = None,
        config: SecurityConfig | None = None,
    ) -> dict[str, str]:
        if config is not None:
            if not config.security_headers or not config.security_headers.get(
                "enabled", True
            ):
                return {}
        elif not self.enabled:
            return {}

        cache_key = self._generate_cache_key(request_path, config)
        headers, is_new = self._headers_for(config, cache_key)

        if is_new and self.agent_handler and request_path:
            await self._send_headers_applied_event(request_path, headers)

        return headers


security_headers_manager = SecurityHeadersManager()


async def reset_global_state() -> None:
    global security_headers_manager
    manager = SecurityHeadersManager()
    await manager.reset()
    security_headers_manager = manager
