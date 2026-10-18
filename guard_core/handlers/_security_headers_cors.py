import logging
from abc import abstractmethod
from typing import Any

from guard_core._security_headers_override import OverrideRecord
from guard_core.models import SecurityConfig


class SecurityHeadersCorsMixin:
    logger: logging.Logger
    cors_config: dict[str, Any] | None

    @abstractmethod
    async def send_cors_override_event(
        self, config: SecurityConfig, current: OverrideRecord | None = None
    ) -> None: ...

    @abstractmethod
    def _resolve_cors_state(
        self, config: SecurityConfig | None, override: OverrideRecord | None = None
    ) -> dict[str, Any] | None: ...

    def _is_wildcard_with_credentials(
        self, allowed_origins: list[str], cors_config: dict[str, Any] | None = None
    ) -> bool:
        if "*" not in allowed_origins:
            return False

        effective_cors_config = (
            cors_config if cors_config is not None else self.cors_config
        )
        if effective_cors_config and effective_cors_config.get("allow_credentials"):
            self.logger.warning(
                "Credentials cannot be used with wildcard origin - blocking CORS"
            )
            return True

        return False

    def _is_origin_allowed(self, origin: str, allowed_origins: list[str]) -> bool:
        return "*" in allowed_origins or origin in allowed_origins

    def _get_validated_cors_config(
        self, cors_config: dict[str, Any] | None = None
    ) -> tuple[list[str], list[str]]:
        effective_cors_config = (
            cors_config if cors_config is not None else self.cors_config
        )
        if not effective_cors_config:
            return ["GET", "POST"], ["*"]

        allow_methods = effective_cors_config.get("allow_methods", ["GET", "POST"])
        allow_headers = effective_cors_config.get("allow_headers", ["*"])

        if not isinstance(allow_methods, list):
            allow_methods = ["GET", "POST"]
        if not isinstance(allow_headers, list):
            allow_headers = ["*"]

        return allow_methods, allow_headers

    def _build_cors_headers(
        self,
        origin: str,
        allowed_origins: list[str],
        allow_methods: list[str],
        allow_headers: list[str],
        cors_config: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        effective_cors_config = (
            cors_config if cors_config is not None else self.cors_config
        )
        cors_headers = {
            "Access-Control-Allow-Origin": origin if origin in allowed_origins else "*",
            "Access-Control-Allow-Methods": ", ".join(allow_methods),
            "Access-Control-Max-Age": str(
                effective_cors_config.get("max_age", 3600)
                if effective_cors_config
                else 3600
            ),
        }
        if allow_headers:
            cors_headers["Access-Control-Allow-Headers"] = ", ".join(allow_headers)

        if effective_cors_config and effective_cors_config.get("allow_credentials"):
            cors_headers["Access-Control-Allow-Credentials"] = "true"

        return cors_headers

    async def get_cors_headers(
        self,
        origin: str,
        config: SecurityConfig | None = None,
        override: OverrideRecord | None = None,
    ) -> dict[str, str]:
        cors_config = self._resolve_cors_state(config, override)
        if config is not None:
            await self.send_cors_override_event(config, override)
        if not cors_config:
            return {}

        allowed_origins = cors_config.get("origins", [])
        if not isinstance(allowed_origins, list):
            return {}

        if self._is_wildcard_with_credentials(allowed_origins, cors_config):
            return {}

        if not self._is_origin_allowed(origin, allowed_origins):
            return {}

        allow_methods, allow_headers = self._get_validated_cors_config(cors_config)
        return self._build_cors_headers(
            origin, allowed_origins, allow_methods, allow_headers, cors_config
        )
