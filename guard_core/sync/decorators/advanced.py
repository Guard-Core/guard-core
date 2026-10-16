import json
import logging
from collections.abc import Callable, MutableMapping
from typing import Any
from urllib.parse import parse_qs

from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.decorators.base import BaseSecurityMixin, DecoratedFunction
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import _read_capped_body

logger = logging.getLogger(__name__)


class _SimpleResponse:
    def __init__(self, content: str, status_code: int) -> None:
        self._status_code = status_code
        self._headers: dict[str, str] = {}
        self._body = content.encode()

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def headers(self) -> MutableMapping[str, str]:
        return self._headers

    @property
    def body(self) -> bytes:
        return self._body


class AdvancedMixin(BaseSecurityMixin):
    config: SecurityConfig

    def time_window(
        self, start_time: str, end_time: str, timezone: str = "UTC"
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
            route_config = self._ensure_route_config(func)
            route_config.time_restrictions = {
                "start": start_time,
                "end": end_time,
                "timezone": timezone,
            }
            return self._apply_route_config(func)

        return decorator

    def suspicious_detection(
        self, enabled: bool = True
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
            route_config = self._ensure_route_config(func)
            route_config.enable_suspicious_detection = enabled
            return self._apply_route_config(func)

        return decorator

    def honeypot_detection(
        self, trap_fields: list[str]
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        config = self.config

        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
            def honeypot_validator(
                request: SyncGuardRequest,
            ) -> GuardResponse | None:
                def _has_trap_field_filled(data: dict[str, Any]) -> bool:
                    return any(field in data and data[field] for field in trap_fields)

                def _validate_form_data(raw_body: bytes) -> GuardResponse | None:
                    parsed = parse_qs(
                        raw_body.decode("utf-8", errors="surrogateescape")
                    )
                    flat = {k: v[0] for k, v in parsed.items() if v}
                    if _has_trap_field_filled(flat):
                        return _SimpleResponse("Forbidden", 403)
                    return None

                def _validate_json_data(raw_body: bytes) -> GuardResponse | None:
                    try:
                        json_data = json.loads(
                            raw_body.decode("utf-8", errors="surrogateescape")
                        )
                        if _has_trap_field_filled(json_data):
                            return _SimpleResponse("Forbidden", 403)
                    except (json.JSONDecodeError, TypeError, RecursionError) as exc:
                        logger.debug(
                            "honeypot_detection: skipping unparsable JSON body: %s",
                            exc,
                        )
                    return None

                if request.method not in ["POST", "PUT", "PATCH"]:
                    return None

                raw_body = _read_capped_body(request, config)
                if raw_body is None:
                    return None

                content_type = request.headers.get("content-type", "")

                if "application/x-www-form-urlencoded" in content_type:
                    return _validate_form_data(raw_body)
                elif "application/json" in content_type:
                    return _validate_json_data(raw_body)

                return None

            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(honeypot_validator)
            route_config.honeypot_validators.append(honeypot_validator)
            return self._apply_route_config(func)

        return decorator
