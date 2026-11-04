import logging
import threading

from cachetools import TTLCache

from guard_core._redis_enablement import redis_is_configured
from guard_core._security_headers_override import OverrideRecord
from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers._security_headers_cache import (
    HotHeadersCache,
    SecurityHeadersCacheMixin,
)
from guard_core.sync.handlers._security_headers_config import SecurityHeadersConfigMixin
from guard_core.sync.handlers._security_headers_cors import SecurityHeadersCorsMixin
from guard_core.sync.handlers._security_headers_events import SecurityHeadersEventsMixin
from guard_core.sync.handlers._security_headers_override_state import (
    SecurityHeadersOverrideMixin,
)
from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol


class ResolvedHeaders(dict[str, str]):
    forced: frozenset[str] = frozenset()
    plan: tuple[tuple[str, str, bool], ...] | None = None

    def plan_merge(self) -> None:
        lowered = [name.lower() for name in self]
        if len(set(lowered)) == len(lowered):
            self.plan = tuple(
                (name, low, low in self.forced)
                for name, low in zip(self, lowered, strict=True)
            )


class SecurityHeadersManager(
    SecurityHeadersOverrideMixin,
    SecurityHeadersConfigMixin,
    SecurityHeadersCacheMixin,
    SecurityHeadersCorsMixin,
    SecurityHeadersEventsMixin,
):
    _instance: "SecurityHeadersManager | None" = None
    _lock = threading.Lock()
    headers_cache: TTLCache
    redis_handler: SyncRedisHandlerProtocol | None = None
    agent_handler: SyncAgentHandlerProtocol | None = None
    logger: logging.Logger
    enabled: bool
    custom_headers: dict[str, str]
    csp_config: dict[str, list[str]] | None
    hsts_config: dict[str, object] | None
    cors_config: dict[str, object] | None

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
        self.headers_cache = HotHeadersCache(maxsize=1000, ttl=300)
        self.redis_handler = None
        self.agent_handler = None
        self.logger = logging.getLogger("guard_core.sync.handlers.security_headers")
        self.enabled = True
        self.custom_headers = {}
        self.csp_config = None
        self.hsts_config = None
        self.cors_config = None
        self.default_headers = self.__class__.default_headers.copy()
        self._initialize_override_state()

    def _build_csp(self, csp_config: dict[str, list[str]]) -> str:
        directives = []
        for directive, sources in csp_config.items():
            if sources:
                sources_str = " ".join(sources)
                directives.append(f"{directive} {sources_str}")
            else:
                directives.append(directive)
        return "; ".join(directives)

    def _build_hsts(self, hsts_config: dict[str, object]) -> str:
        parts = [f"max-age={hsts_config['max_age']}"]
        if hsts_config.get("include_subdomains"):
            parts.append("includeSubDomains")
        if hsts_config.get("preload"):
            parts.append("preload")
        return "; ".join(parts)

    def _forced_header_names(
        self,
        csp_config: dict[str, list[str]] | None,
        hsts_config: dict[str, object] | None,
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
        self,
        config: SyncSecurityConfig | None,
        cache_key: str,
        override: OverrideRecord | None = None,
    ) -> tuple[dict[str, str], bool]:
        cached = self.headers_cache.get(cache_key)
        if isinstance(cached, dict):
            return cached, False

        csp_config, hsts_config, default_headers, custom_headers = (
            self._resolve_headers_state(config, override)
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
        headers.plan_merge()

        self.headers_cache[cache_key] = headers
        return headers, True

    def headers_enabled_for(
        self, config: SyncSecurityConfig, override: OverrideRecord | None = None
    ) -> bool:
        keys = (self._current_override() if override is None else override).keys
        if "enabled" in keys:
            return bool(keys["enabled"])
        raw = config.security_headers
        return bool(raw and raw.get("enabled", True))

    def _headers_off(
        self, config: SyncSecurityConfig, override: OverrideRecord | None = None
    ) -> bool:
        return not self.headers_enabled_for(config, override)

    def resolve_headers(self, config: SyncSecurityConfig) -> dict[str, str]:
        override = self.override_for_reader(config)
        if self._headers_off(config, override):
            return {}
        headers, _ = self._headers_for(
            config, self._generate_cache_key(None, config, override), override
        )
        return headers

    def get_headers(
        self,
        request_path: str | None = None,
        config: SyncSecurityConfig | None = None,
        override: OverrideRecord | None = None,
        checked: bool = False,
    ) -> dict[str, str]:
        if config is None:
            return self._get_global_headers(request_path)
        before = self._current_override() if override is None else override
        override = (
            before
            if self.redis_handler is None
            and not redis_is_configured(config)
            and before.event is None
            else self._sync_override(config, before)
        )
        if (not checked or override is not before) and self._headers_off(
            config, override
        ):
            return {}

        cache_key = self._generate_cache_key(request_path, config, override)
        cached = self._cached_headers(cache_key)
        if cached is None:
            cached = self._build_headers_and_announce(
                request_path, config, cache_key, override
            )
        self._remember_hot_headers(override, cache_key, cached)
        return cached

    def _remember_hot_headers(
        self,
        override: OverrideRecord,
        cache_key: str,
        headers: dict[str, str],
    ) -> None:
        memo = self._headers_json_memo
        cache = self.headers_cache
        if (
            memo is not None
            and not override.keys
            and isinstance(cache, HotHeadersCache)
        ):
            cache.remember_hot(cache_key, memo[0], headers)

    def hot_headers(
        self, config: SyncSecurityConfig, override: OverrideRecord
    ) -> dict[str, str] | None:
        """The headers the last quiet response resolved, or None when anything that
        could change them may have happened: the cache changed or expired, the
        config's security headers changed, an override, an event or Redis is in
        play."""
        hot: tuple[object, dict[str, str], float] | None = getattr(
            self.headers_cache, "hot", None
        )
        if (
            hot is None
            or override.keys
            or override.event is not None
            or self.redis_handler is not None
            or config.enable_redis
            or hot[0] != config.security_headers
            or self.headers_cache.timer() >= hot[2]
        ):
            return None
        return hot[1]

    def _cached_headers(self, cache_key: str) -> dict[str, str] | None:
        try:
            # Indexing, not .get(): the same lookup in about half the calls.
            cached = self.headers_cache[cache_key]
        except KeyError:
            return None
        return cached if isinstance(cached, dict) else None

    def _get_global_headers(self, request_path: str | None) -> dict[str, str]:
        if not self.enabled:
            return {}
        cache_key = self._generate_cache_key(request_path, None, None)
        cached = self.headers_cache.get(cache_key)
        if isinstance(cached, dict):
            return cached
        return self._build_headers_and_announce(request_path, None, cache_key, None)

    def _build_headers_and_announce(
        self,
        request_path: str | None,
        config: SyncSecurityConfig | None,
        cache_key: str,
        override: OverrideRecord | None,
    ) -> dict[str, str]:
        headers, is_new = self._headers_for(config, cache_key, override)
        if is_new and self.agent_handler and request_path:
            self._send_headers_applied_event(request_path, headers)
        return headers

    def get_headers_and_forced(
        self,
        request_path: str | None = None,
        config: SyncSecurityConfig | None = None,
        override: OverrideRecord | None = None,
        checked: bool = False,
    ) -> tuple[dict[str, str], frozenset[str]]:
        headers = self.get_headers(request_path, config, override, checked)
        forced = headers.forced if isinstance(headers, ResolvedHeaders) else frozenset()
        return headers, forced


security_headers_manager = SecurityHeadersManager()


def reset_global_state() -> None:
    global security_headers_manager
    manager = SecurityHeadersManager()
    manager.reset()
    security_headers_manager = manager
