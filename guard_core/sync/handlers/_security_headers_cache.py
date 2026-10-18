import hashlib
import json
import logging
from abc import abstractmethod
from typing import Any

from cachetools import TTLCache

from guard_core._security_headers_override import (
    OverrideRecord,
    override_fingerprint,
)
from guard_core.models import SecurityConfig
from guard_core.sync._utils.logging_utils import _sanitize_for_log


class SecurityHeadersCacheMixin:
    headers_cache: TTLCache
    redis_handler: Any
    agent_handler: Any
    logger: logging.Logger
    enabled: bool
    custom_headers: dict[str, str]
    csp_config: dict[str, list[str]] | None
    hsts_config: dict[str, Any] | None
    cors_config: dict[str, Any] | None
    default_headers: dict[str, str]

    @abstractmethod
    def _validate_header_name(self, name: str) -> str: ...

    @abstractmethod
    def _current_override(self) -> OverrideRecord: ...

    @abstractmethod
    def _reset_override(self) -> None: ...

    @abstractmethod
    def _validate_header_value(self, value: str) -> str: ...

    def _generate_cache_key(
        self, request_path: str | None, config: SecurityConfig | None = None
    ) -> str:
        if config is not None:
            content = json.dumps(config.security_headers, sort_keys=True, default=str)
            content += override_fingerprint(self._current_override().keys)
            return f"cfg_{hashlib.sha256(content.encode()).hexdigest()[:32]}"
        if not request_path:
            return "default"
        normalized = request_path.lower().strip("/")
        return f"path_{hashlib.sha256(normalized.encode()).hexdigest()[:16]}"

    def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler
        self._load_cached_config()
        self._cache_configuration()

    def _load_cached_config(self) -> None:
        if not self.redis_handler:
            return

        try:
            csp_config = self.redis_handler.get_key("security_headers", "csp_config")
            if csp_config:
                self.csp_config = json.loads(csp_config)

            hsts_config = self.redis_handler.get_key("security_headers", "hsts_config")
            if hsts_config:
                self.hsts_config = json.loads(hsts_config)

            custom_headers = self.redis_handler.get_key(
                "security_headers", "custom_headers"
            )
            if custom_headers:
                loaded_custom_headers = json.loads(custom_headers)
                validated_custom_headers = {
                    self._validate_header_name(name): self._validate_header_value(value)
                    for name, value in loaded_custom_headers.items()
                }
                self.custom_headers = validated_custom_headers

        except Exception as e:
            self.logger.warning(
                f"Failed to load cached header config: {_sanitize_for_log(str(e))}"
            )

    def _cache_configuration(self) -> None:
        if not self.redis_handler:
            return

        try:
            if self.csp_config:
                self.redis_handler.set_key(
                    "security_headers",
                    "csp_config",
                    json.dumps(self.csp_config),
                    ttl=86400,
                )
            if self.hsts_config:
                self.redis_handler.set_key(
                    "security_headers",
                    "hsts_config",
                    json.dumps(self.hsts_config),
                    ttl=86400,
                )
            if self.custom_headers:
                self.redis_handler.set_key(
                    "security_headers",
                    "custom_headers",
                    json.dumps(self.custom_headers),
                    ttl=86400,
                )
        except Exception as e:
            self.logger.warning(f"Failed to cache header configuration: {e}")

    def reset(self) -> None:
        self.headers_cache.clear()
        self.custom_headers.clear()
        self.csp_config = None
        self.hsts_config = None
        self.cors_config = None
        self.enabled = True
        self.default_headers = self.__class__.default_headers.copy()
        self._reset_override()

        if self.redis_handler:
            try:
                with self.redis_handler.get_connection() as conn:
                    keys = conn.keys(
                        f"{self.redis_handler.config.redis_prefix}security_headers:*"
                    )
                    if keys:
                        conn.delete(*keys)
            except Exception as e:
                self.logger.warning(f"Failed to clear Redis cache: {e}")

        self.redis_handler = None
        self.agent_handler = None
