import json
from typing import Any

from guard_core._utils.body_json_scan import _redact_sensitive_json, _scan_json_value
from guard_core._utils.detection_scan import (
    _embedded_json_scan,
    _json_depth_cap_value,
    _warn_json_depth_cap_reached_once,
)
from guard_core.handlers._suspatterns_sources import _EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX


def _parse_embedded_json(value: str, client_ip: str) -> Any | None:
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        return None
    except RecursionError:
        _warn_json_depth_cap_reached_once(client_ip)
        return None
    if not isinstance(data, dict | list):
        return None
    return data


def _embedded_json_display(
    data: Any,
    sensitive_body_fields: frozenset[str],
    redact_all: bool,
    sensitive_params: frozenset[str] = frozenset(),
) -> str:
    if redact_all:
        return "[REDACTED]"
    return json.dumps(
        _redact_sensitive_json(
            data, sensitive_params, sensitive_body_fields, _json_depth_cap_value()
        ),
        separators=(",", ":"),
        ensure_ascii=False,
    )


async def _check_embedded_json(
    value: str,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None,
    excluded_body_fields: frozenset[str],
    sensitive_body_fields: frozenset[str],
    redact_all: bool,
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict], str | None] | None:
    data = _parse_embedded_json(value, client_ip)
    if data is None:
        return None

    with _embedded_json_scan():
        detected, trigger, threats = await _scan_json_value(
            data,
            "",
            set(excluded_body_fields),
            enabled_categories,
            client_ip,
            correlation_id,
            None,
            sensitive_body_fields,
            context=f"{context}{_EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX}",
            preview_override="[REDACTED]" if redact_all else None,
            redact_keys=redact_all,
            sensitive_params=sensitive_params,
        )
    if not detected:
        return False, "", [], None

    display = _embedded_json_display(
        data, sensitive_body_fields, redact_all, sensitive_params
    )
    return True, trigger, threats, display
