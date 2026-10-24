import json
import re
from typing import TYPE_CHECKING, Any

from guard_core.sync._utils.body_json_scan import (
    _json_object_with_every_pair,
    _redact_sensitive_json,
    _scan_json_value,
)
from guard_core.sync._utils.detection_scan import (
    _embedded_json_scan,
    _json_depth_cap_value,
    _scan_budget_spent,
)
from guard_core.sync._utils.json_nesting import _nests_deeper_than
from guard_core.sync._utils.kept_value_paths import _NOTHING_TO_KEEP, _keep_only_values
from guard_core.sync.handlers._suspatterns_sources import (
    _EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX,
)

if TYPE_CHECKING:
    from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

# One fixed limit below the lowest json.loads limit (see json_nesting) keeps every
# interpreter on the same path for a value that already sits inside a parsed body.
_EMBEDDED_JSON_MAX_PARSE_DEPTH = 512

_QUOTE_RUN = re.compile(r'(?<!\\)\\*"')
_TOO_DEEP_TO_PARSE = object()


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


def _decoded_string_literals(literals: list[str]) -> frozenset[str]:
    # One parse for all of them; a literal the strict parser refuses falls back to the
    # one-by-one decode, which is lenient about control characters.
    try:
        return frozenset(json.loads('["' + '","'.join(literals) + '"]'))
    except ValueError:
        return frozenset(map(_decoded_string_literal, literals))


def _parse_embedded_json(value: str, every_pair: bool = False) -> Any | None:
    if _nests_deeper_than(value, _EMBEDDED_JSON_MAX_PARSE_DEPTH):
        return _TOO_DEEP_TO_PARSE
    try:
        data = json.loads(
            value,
            object_pairs_hook=_json_object_with_every_pair if every_pair else None,
        )
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


def _scan_string_literals(
    value: str,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None,
    sensitive_body_fields: frozenset[str],
    redact_all: bool,
    sensitive_params: frozenset[str],
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict], str | None] | None:
    from guard_core.sync._utils.body_content_scan import _scan_body_field

    with _embedded_json_scan():
        for literal in _escaped_string_literals(value):
            if _scan_budget_spent():
                return None
            detected, trigger, threats = _scan_body_field(
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
                patterns=patterns,
            )
            if detected:
                return True, trigger, threats, "[REDACTED]"
    return None


def _check_embedded_json(
    value: str,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None,
    excluded_body_fields: frozenset[str],
    sensitive_body_fields: frozenset[str],
    redact_all: bool,
    sensitive_params: frozenset[str] = frozenset(),
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict], str | None] | None:
    data = _parse_embedded_json(value)
    if data is None:
        return None
    if data is _TOO_DEEP_TO_PARSE:
        return _scan_string_literals(
            value,
            context,
            client_ip,
            correlation_id,
            enabled_categories,
            sensitive_body_fields,
            redact_all,
            sensitive_params,
            patterns=patterns,
        )
    return _walk_parsed_embedded_json(
        data,
        context,
        client_ip,
        correlation_id,
        enabled_categories,
        excluded_body_fields,
        sensitive_body_fields,
        redact_all,
        sensitive_params,
        patterns=patterns,
    )


def _walk_parsed_embedded_json(
    data: Any,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None,
    excluded_body_fields: frozenset[str],
    sensitive_body_fields: frozenset[str],
    redact_all: bool,
    sensitive_params: frozenset[str],
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict], str | None]:
    with _embedded_json_scan():
        detected, trigger, threats = _scan_json_value(
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
            patterns=patterns,
        )
    if not detected:
        return False, "", [], None

    display = _embedded_json_display(
        data, sensitive_body_fields, redact_all, sensitive_params
    )
    return True, trigger, threats, display


def _scan_escaped_literals_through_exclusions(
    value: str,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None,
    excluded_body_fields: frozenset[str],
    sensitive_body_fields: frozenset[str],
    redact_all: bool,
    sensitive_params: frozenset[str],
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict], str | None] | None:
    literals = _escaped_string_literals(value)
    if not literals:
        return None
    data = _parse_embedded_json(value, every_pair=True)
    if not isinstance(data, dict | list):
        return _scan_string_literals(
            value,
            context,
            client_ip,
            correlation_id,
            enabled_categories,
            sensitive_body_fields,
            redact_all,
            sensitive_params,
            patterns=patterns,
        )
    kept = _keep_only_values(data, _decoded_string_literals(literals))
    if kept is _NOTHING_TO_KEEP:
        return None
    return _walk_parsed_embedded_json(
        kept,
        context,
        client_ip,
        correlation_id,
        enabled_categories,
        excluded_body_fields,
        sensitive_body_fields,
        redact_all,
        sensitive_params,
        patterns=patterns,
    )
