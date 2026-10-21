import json
import re
from typing import Any

from guard_core._utils.body_json_scan import _redact_sensitive_json, _scan_json_value
from guard_core._utils.detection_scan import (
    _embedded_json_scan,
    _json_depth_cap_value,
    _scan_budget_spent,
)
from guard_core.handlers._suspatterns_sources import _EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX

# json.loads accepts 993 nested arrays on 3.10 and 3.11 (951 under a 40 frame call
# stack), 9997 on 3.12, 9998 on 3.13 and 74373 on 3.14. One fixed limit below the
# lowest keeps every interpreter on the same path.
_EMBEDDED_JSON_MAX_PARSE_DEPTH = 512

_QUOTE_RUN = re.compile(r'(?<!\\)\\*"')
_QUOTE_RUN_OR_BRACKET = re.compile(r'(?<!\\)\\*"|[\[\]{}]')
_TOO_DEEP_TO_PARSE = object()


def _nests_deeper_than(value: str, limit: int) -> bool:
    if value.count("[") + value.count("{") <= limit:
        return False
    depth = 0
    in_string = False
    for found in _QUOTE_RUN_OR_BRACKET.finditer(value):
        token = found.group()
        if token[-1] == '"':
            in_string ^= len(token) % 2 == 1
        elif not in_string:
            depth += 1 if token in "[{" else -1
            if depth > limit:
                return True
    return False


def _escaped_string_literals(value: str) -> list[str]:
    # shortcut: a literal with no backslash decodes to its own text, which the
    # caller's scan of the whole value already covers, so only the escaped ones
    # are returned (their decoded text is what the whole-value scan cannot see).
    if "\\" not in value:
        return []
    quotes = [
        found
        for found in _QUOTE_RUN.finditer(value)
        if (found.end() - found.start()) % 2
    ]
    return [
        literal
        for opened, closed in zip(quotes[::2], quotes[1::2], strict=False)
        if "\\" in (literal := value[opened.end() : closed.end() - 1])
    ]


def _decoded_string_literal(literal: str) -> str:
    try:
        decoded = json.loads(f'"{literal}"', strict=False)
    except ValueError:
        return literal
    return str(decoded)


def _parse_embedded_json(value: str) -> Any | None:
    if _nests_deeper_than(value, _EMBEDDED_JSON_MAX_PARSE_DEPTH):
        return _TOO_DEEP_TO_PARSE
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        return None
    except RecursionError:
        return _TOO_DEEP_TO_PARSE
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


async def _scan_string_literals(
    value: str,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None,
    sensitive_body_fields: frozenset[str],
    redact_all: bool,
    sensitive_params: frozenset[str],
) -> tuple[bool, str, list[dict], str | None] | None:
    from guard_core._utils.body_content_scan import _scan_body_field

    with _embedded_json_scan():
        for literal in _escaped_string_literals(value):
            if _scan_budget_spent():
                return None
            detected, trigger, threats = await _scan_body_field(
                _decoded_string_literal(literal),
                "",
                enabled_categories,
                client_ip,
                correlation_id,
                None,
                sensitive_body_fields,
                context=f"{context}{_EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX}",
                preview_override="[REDACTED]" if redact_all else None,
                sensitive_params=sensitive_params,
            )
            if detected:
                return True, trigger, threats, "[REDACTED]"
    return None


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
    data = _parse_embedded_json(value)
    if data is None:
        return None
    if data is _TOO_DEEP_TO_PARSE:
        return await _scan_string_literals(
            value,
            context,
            client_ip,
            correlation_id,
            enabled_categories,
            sensitive_body_fields,
            redact_all,
            sensitive_params,
        )

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
