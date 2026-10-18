import hashlib
import json
import logging
from abc import abstractmethod
from typing import Any

from cachetools import TTLCache

from guard_core._security_headers_override import (
    OverrideRecord,
    config_fingerprint,
    override_fingerprint,
)
from guard_core._utils.logging_utils import _sanitize_for_log
from guard_core.models import SecurityConfig


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
    _instance: Any
    _startup_hash: str | None
    _redis_initialized: bool

    @abstractmethod
    async def _pull_override(self) -> None: ...

    @abstractmethod
    async def _save_override_record(self) -> None: ...

    @abstractmethod
    def _validate_header_name(self, name: str) -> str: ...

    @abstractmethod
    def _current_override(self) -> OverrideRecord: ...

    @abstractmethod
    def _reset_override(self) -> None: ...

    @abstractmethod
    def _validate_header_value(self, value: str) -> str: ...

    def _generate_cache_key(
        self,
        request_path: str | None,
        config: SecurityConfig | None = None,
        override: OverrideRecord | None = None,
    ) -> str:
        if config is not None:
            content = json.dumps(config.security_headers, sort_keys=True, default=str)
            current = self._current_override() if override is None else override
            if current.keys:
                content += override_fingerprint(current.keys)
            return f"cfg_{hashlib.sha256(content.encode()).hexdigest()[:32]}"
        if not request_path:
            return "default"
        normalized = request_path.lower().strip("/")
        return f"path_{hashlib.sha256(normalized.encode()).hexdigest()[:16]}"

    async def initialize_redis(
        self, redis_handler: Any, config: SecurityConfig | None = None
    ) -> None:
        self.redis_handler = redis_handler
        self._redis_initialized = True
        if config is not None and self._startup_hash is None:
            self._startup_hash = config_fingerprint(config)
        own_state = self._owns_state()
        await self._load_cached_config(own_state)
        await self._cache_configuration(own_state)

    def _owns_state(self) -> bool:
        # An unbound manager keeps the 4.4.0 behavior. Bound to an app's config, only
        # the process-wide manager owns the cached csp, hsts and custom headers: an
        # app builds its headers from its config and never reads them.
        return self._startup_hash is None or bool(type(self)._instance is self)

    def _encode_own_state(self, value: Any) -> str:
        if self._startup_hash is None:
            return json.dumps(value)
        return json.dumps({"fingerprint": self._startup_hash, "value": value})

    def _decode_own_state(self, raw: Any) -> Any:
        data = json.loads(raw)
        if self._startup_hash is None:
            return data
        if isinstance(data, dict) and data.get("fingerprint") == self._startup_hash:
            return data.get("value")
        return None

    def _apply_own_state(self, csp: Any, hsts: Any, custom: Any) -> None:
        if csp:
            loaded = self._decode_own_state(csp)
            if loaded:
                self.csp_config = loaded
        if hsts:
            loaded = self._decode_own_state(hsts)
            if loaded:
                self.hsts_config = loaded
        if custom:
            loaded = self._decode_own_state(custom)
            if loaded:
                self.custom_headers = {
                    self._validate_header_name(name): self._validate_header_value(value)
                    for name, value in loaded.items()
                }

    async def _load_cached_config(self, own_state: bool = True) -> None:
        if not self.redis_handler:
            return

        if own_state:
            try:
                self._apply_own_state(
                    await self.redis_handler.get_key("security_headers", "csp_config"),
                    await self.redis_handler.get_key("security_headers", "hsts_config"),
                    await self.redis_handler.get_key(
                        "security_headers", "custom_headers"
                    ),
                )
            except Exception as e:
                self.logger.warning(
                    f"Failed to load cached header config: {_sanitize_for_log(str(e))}"
                )

        if self._startup_hash is not None:
            await self._pull_override()

    async def _cache_configuration(self, own_state: bool = True) -> None:
        if not self.redis_handler:
            return

        if own_state:
            try:
                if self.csp_config:
                    await self.redis_handler.set_key(
                        "security_headers",
                        "csp_config",
                        self._encode_own_state(self.csp_config),
                        ttl=86400,
                    )
                if self.hsts_config:
                    await self.redis_handler.set_key(
                        "security_headers",
                        "hsts_config",
                        self._encode_own_state(self.hsts_config),
                        ttl=86400,
                    )
                if self.custom_headers:
                    await self.redis_handler.set_key(
                        "security_headers",
                        "custom_headers",
                        self._encode_own_state(self.custom_headers),
                        ttl=86400,
                    )
            except Exception as e:
                self.logger.warning(f"Failed to cache header configuration: {e}")

        if self._startup_hash is not None:
            await self._save_override_record()

    async def reset(self) -> None:
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
                async with self.redis_handler.get_connection() as conn:
                    keys = await conn.keys(
                        f"{self.redis_handler.config.redis_prefix}security_headers:*"
                    )
                    if keys:
                        await conn.delete(*keys)
            except Exception as e:
                self.logger.warning(f"Failed to clear Redis cache: {e}")

        self.redis_handler = None
        self.agent_handler = None
