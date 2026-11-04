import logging
from collections.abc import Callable, MutableMapping
from urllib.parse import urlsplit

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.body_reader import _parse_content_length
from guard_core.sync.decorators.base import (
    BaseSecurityMixin,
    GuardedParams,
    GuardedReturn,
)
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


_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


def _warn_if_body_not_fully_inspected(
    request: SyncGuardRequest, raw_body: bytes | None, config: SyncSecurityConfig
) -> None:
    max_bytes = config.detection_max_body_inspect_bytes
    declared = _parse_content_length(request.headers.get("content-length", ""))
    if declared is not None:
        cut_short = declared > max_bytes or raw_body is None
    elif raw_body is None:
        cut_short = request.method in _BODY_METHODS
    else:
        cut_short = len(raw_body) >= max_bytes
    if cut_short:
        logger.warning(
            "honeypot_detection: a request body larger than "
            "detection_max_body_inspect_bytes (%d) or unreadable was not fully "
            "inspected for trap fields",
            max_bytes,
        )


def _log_unparsable_json(error: Exception | None) -> None:
    if isinstance(error, RecursionError):
        logger.warning(
            "honeypot_detection: a JSON body nested too deeply to parse was not "
            "fully inspected for trap fields"
        )
    elif error is not None:
        logger.debug("honeypot_detection: skipping unparsable JSON body: %s", error)


class AdvancedMixin(BaseSecurityMixin):
    config: SyncSecurityConfig

    def time_window(
        self, start_time: str, end_time: str, timezone: str = "UTC"
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            from guard_core.sync.decorators._route_arguments import (
                invalid_time_of_day,
                unknown_time_zone,
            )

            for name, value in (("start_time", start_time), ("end_time", end_time)):
                if invalid_time_of_day(value):
                    self._report_misconfiguration(
                        f"@time_window {name} {value!r} is not a valid HH:MM "
                        "time, so the window is evaluated on a broken value."
                    )
            if unknown_time_zone(timezone):
                self._report_misconfiguration(
                    f"@time_window timezone {timezone!r} is not a known IANA "
                    "time zone, so the window silently falls back to UTC."
                )
            route_config = self._ensure_route_config(func)
            route_config.store_attribute(
                "time_restrictions",
                {"start": start_time, "end": end_time, "timezone": timezone},
            )
            return self._apply_route_config(func)

        return decorator

    def suspicious_detection(
        self, enabled: bool = True
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            route_config = self._ensure_route_config(func)
            route_config.enable_suspicious_detection = enabled
            return self._apply_route_config(func)

        return decorator

    def honeypot_detection(
        self, trap_fields: list[str]
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        config = self.config
        trap_names = frozenset(field.lower() for field in trap_fields)

        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            from guard_core.sync._utils.honeypot_fields import (
                FORM_MEDIA_TYPE,
                JSON_MEDIA_TYPE,
                MULTIPART_MEDIA_TYPE,
                form_has_filled_trap,
                json_has_filled_trap,
                media_type_of,
                multipart_has_filled_trap,
                query_has_filled_trap,
            )

            def honeypot_validator(
                request: SyncGuardRequest,
            ) -> GuardResponse | None:
                query = urlsplit(request.url_full).query
                if query_has_filled_trap(query, trap_names):
                    return _SimpleResponse("Forbidden", 403)

                raw_body = _read_capped_body(request, config)
                _warn_if_body_not_fully_inspected(request, raw_body, config)
                if raw_body is None:
                    return None

                content_type = request.headers.get("content-type", "")
                media_type = media_type_of(content_type)
                if media_type == FORM_MEDIA_TYPE:
                    filled = form_has_filled_trap(raw_body, trap_names)
                elif media_type == MULTIPART_MEDIA_TYPE:
                    filled = multipart_has_filled_trap(
                        raw_body, content_type, trap_names
                    )
                elif media_type == JSON_MEDIA_TYPE:
                    filled, error = json_has_filled_trap(raw_body, trap_names)
                    _log_unparsable_json(error)
                else:
                    filled = False
                return _SimpleResponse("Forbidden", 403) if filled else None

            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(honeypot_validator)
            route_config.honeypot_validators.append(honeypot_validator)
            return self._apply_route_config(func)

        return decorator
