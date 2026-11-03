import copy
import hashlib
import json
import logging
from abc import abstractmethod
from collections.abc import Callable
from typing import TypeVar

from cachetools import TTLCache

from guard_core._security_headers_override import (
    OverrideRecord,
    config_fingerprint,
    override_fingerprint,
)
from guard_core._security_headers_record_validation import (
    validate_cached_csp,
    validate_cached_hsts,
)
from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.logging_utils import _sanitize_for_log
from guard_core.sync.handlers.redis_handler import scan_unlink
from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol

_Validated = TypeVar("_Validated")


class SecurityHeadersCacheMixin:
    headers_cache: TTLCache
    redis_handler: SyncRedisHandlerProtocol | None
    agent_handler: SyncAgentHandlerProtocol | None
    logger: logging.Logger
    enabled: bool
    custom_headers: dict[str, str]
    csp_config: dict[str, list[str]] | None
    hsts_config: dict[str, object] | None
    cors_config: dict[str, object] | None
    default_headers: dict[str, str]
    _instance: object
    _startup_hash: str | None
    _redis_initialized: bool
    _headers_json_memo: tuple[object, str] | None = None
    _config_key_memo: tuple[str, str] | None = None

    @abstractmethod
    def _pull_override(self) -> None: ...

    @abstractmethod
    def _save_override_record(self) -> None: ...

    @abstractmethod
    def _validate_header_name(self, name: str) -> str: ...

    @abstractmethod
    def _current_override(self) -> OverrideRecord: ...

    @abstractmethod
    def _reset_override(self) -> None: ...

    @abstractmethod
    def _validate_header_value(self, value: str) -> str: ...

    def _serialize_and_memoize_security_headers(self, headers: object) -> str:
        content = json.dumps(headers, sort_keys=True, default=str)
        try:
            self._headers_json_memo = (copy.deepcopy(headers), content)
        except Exception:
            self._headers_json_memo = None
        return content

    def _generate_cache_key(
        self,
        request_path: str | None,
        config: SyncSecurityConfig | None = None,
        override: OverrideRecord | None = None,
    ) -> str:
        if config is not None:
            headers = config.security_headers
            memo = self._headers_json_memo
            content = (
                memo[1]
                if memo is not None and memo[0] == headers
                else self._serialize_and_memoize_security_headers(headers)
            )
            current = self._current_override() if override is None else override
            if current.keys:
                content += override_fingerprint(current.keys)
            # The key is a pure function of the content: hash it once per content.
            hashed = self._config_key_memo
            if hashed is not None and hashed[0] == content:
                return hashed[1]
            key = f"cfg_{hashlib.sha256(content.encode()).hexdigest()[:32]}"
            self._config_key_memo = (content, key)
            return key
        if not request_path:
            return "default"
        normalized = request_path.lower().strip("/")
        return f"path_{hashlib.sha256(normalized.encode()).hexdigest()[:16]}"

    def initialize_redis(
        self,
        redis_handler: SyncRedisHandlerProtocol,
        config: SyncSecurityConfig | None = None,
    ) -> None:
        self.redis_handler = redis_handler
        self._redis_initialized = True
        if config is not None and self._startup_hash is None:
            self._startup_hash = config_fingerprint(config)
        own_state = self._owns_state()
        self._load_cached_config(own_state)
        self._cache_configuration(own_state)

    def _owns_state(self) -> bool:
        # An unbound manager keeps the 4.4.0 behavior. Bound to an app's config, only
        # the process-wide manager owns the cached csp, hsts and custom headers: an
        # app builds its headers from its config and never reads them.
        return self._startup_hash is None or bool(type(self)._instance is self)

    def _encode_own_state(self, value: object) -> str:
        if self._startup_hash is None:
            return json.dumps(value)
        return json.dumps({"fingerprint": self._startup_hash, "value": value})

    def _decode_own_state(self, raw: str | bytes) -> object:
        data = json.loads(raw)
        if self._startup_hash is None:
            return data
        if isinstance(data, dict) and data.get("fingerprint") == self._startup_hash:
            return data.get("value")
        return None

    def _validated_cached_record(
        self, name: str, loaded: object, validate: Callable[[object], _Validated]
    ) -> _Validated | None:
        try:
            return validate(loaded)
        except ValueError as error:
            self.logger.warning(
                "Ignored cached %s from Redis, keeping this manager's own config: %s",
                name,
                _sanitize_for_log(str(error)),
            )
            return None

    def _apply_own_state(
        self,
        csp: str | bytes | None,
        hsts: str | bytes | None,
        custom: str | bytes | None,
    ) -> None:
        if csp:
            loaded = self._decode_own_state(csp)
            if loaded:
                self.csp_config = (
                    self._validated_cached_record(
                        "csp_config", loaded, validate_cached_csp
                    )
                    or self.csp_config
                )
        if hsts:
            loaded = self._decode_own_state(hsts)
            if loaded:
                self.hsts_config = (
                    self._validated_cached_record(
                        "hsts_config", loaded, validate_cached_hsts
                    )
                    or self.hsts_config
                )
        if custom:
            self._apply_own_custom_headers(custom)

    def _apply_own_custom_headers(self, custom: str | bytes) -> None:
        loaded = self._decode_own_state(custom)
        if not loaded:
            return
        if not isinstance(loaded, dict):
            raise ValueError("cached custom headers are not a JSON object")
        self.custom_headers = {
            self._validate_header_name(name): self._validate_header_value(value)
            for name, value in loaded.items()
        }

    def _load_cached_config(self, own_state: bool = True) -> None:
        if not self.redis_handler:
            return

        if own_state:
            try:
                self._apply_own_state(
                    self.redis_handler.get_key("security_headers", "csp_config"),
                    self.redis_handler.get_key("security_headers", "hsts_config"),
                    self.redis_handler.get_key("security_headers", "custom_headers"),
                )
            except Exception as e:
                self.logger.warning(
                    f"Failed to load cached header config: {_sanitize_for_log(str(e))}"
                )

        if self._startup_hash is not None:
            self._pull_override()

    def _cache_configuration(self, own_state: bool = True) -> None:
        if not self.redis_handler:
            return

        if own_state:
            try:
                if self.csp_config:
                    self.redis_handler.set_key(
                        "security_headers",
                        "csp_config",
                        self._encode_own_state(self.csp_config),
                        ttl=86400,
                    )
                if self.hsts_config:
                    self.redis_handler.set_key(
                        "security_headers",
                        "hsts_config",
                        self._encode_own_state(self.hsts_config),
                        ttl=86400,
                    )
                if self.custom_headers:
                    self.redis_handler.set_key(
                        "security_headers",
                        "custom_headers",
                        self._encode_own_state(self.custom_headers),
                        ttl=86400,
                    )
            except Exception as e:
                self.logger.warning(f"Failed to cache header configuration: {e}")

        if self._startup_hash is not None:
            self._save_override_record()

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
                    scan_unlink(
                        conn,
                        f"{self.redis_handler.config.redis_prefix}security_headers:*",
                    )
            except Exception as e:
                self.logger.warning(f"Failed to clear Redis cache: {e}")

        self.redis_handler = None
        self.agent_handler = None
