from collections import Counter
from collections.abc import Collection, Iterator, Mapping
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl

from guard_core._utils.body_form_scan import (
    _multipart_part_entries,
    _multipart_text_parts,
    _scan_form_body,
    _scan_multipart_body,
    _scan_multipart_part,
)
from guard_core._utils.body_json_scan import (
    _MONGO_OPERATOR_KEY_RE,
    _mongo_operator_key_hit,
    _redact_sensitive_json,
    _scan_capped_json_subtree,
    _scan_json_container_frame,
    _scan_json_content,
    _scan_json_dict_entry_key,
    _scan_json_entry_frame,
    _scan_json_value,
)
from guard_core._utils.detection_config import (
    _excluded_header_effective_categories,
    _host_header_names_an_internal_host,
    _param_scan_categories,
)
from guard_core._utils.detection_scan import (
    _JSON_CONTAINER_START,
    LazyPreview,
    _body_field_category_skips,
    _budget_that_is_never_spent,
    _check_always_scan_header,
    _check_request_component,
    _log_detected_component,
    _resolve_preview,
    _scan_component_name,
    _skip_counter,
    _skipping_whole_value_path_rows,
)
from guard_core._utils.embedded_json_scan import (
    _scan_escaped_literals_through_exclusions,
    _scan_string_literals,
)
from guard_core._utils.request_logging import redact_blob_for_display
from guard_core._utils.scan_remainder import (
    _scan_surface_remainder,
    _SurfaceRemainder,
    _wire_pair,
)
from guard_core._utils.sensitive_names import (
    has_sensitive_name_token,
    name_is_sensitive,
)
from guard_core.protocols.request_protocol import GuardRequest

if TYPE_CHECKING:
    from guard_core.handlers.suspatterns_handler import SusPatternsManager

__all__ = [
    "_MONGO_OPERATOR_KEY_RE",
    "_mongo_operator_key_hit",
    "_multipart_part_entries",
    "_multipart_text_parts",
    "_redact_sensitive_json",
    "_scan_blob_body",
    "_scan_body_field",
    "_scan_capped_json_subtree",
    "_scan_excluded_header_component",
    "_scan_form_body",
    "_scan_headers",
    "_scan_json_container_frame",
    "_scan_json_content",
    "_scan_json_dict_entry_key",
    "_scan_json_entry_frame",
    "_scan_json_value",
    "_scan_multipart_body",
    "_scan_multipart_part",
    "_scan_normal_header_component",
    "_scan_query_param_value",
    "_scan_query_params",
    "_scan_request_body",
    "_scan_sensitive_header",
]


def _non_sensitive_display(
    value: str,
    sensitive_params: frozenset[str],
    sensitive_body_fields: frozenset[str],
    sensitive_headers: frozenset[str] = frozenset(),
) -> tuple[str | None, bool | None]:
    redacted = redact_blob_for_display(
        value, sensitive_params, sensitive_body_fields, sensitive_headers
    )
    if redacted == value:
        return None, None
    return redacted, False


def _lazy_display(
    value: str,
    sensitive_params: frozenset[str],
    sensitive_body_fields: frozenset[str],
    sensitive_headers: frozenset[str] = frozenset(),
) -> LazyPreview:
    return LazyPreview(
        lambda: _non_sensitive_display(
            value, sensitive_params, sensitive_body_fields, sensitive_headers
        )[0]
    )


def _query_name_is_sensitive(
    key: str, sensitive_params: frozenset[str], sensitive_headers: frozenset[str]
) -> bool:
    normalized_key = key.strip().lower()
    return (
        normalized_key in sensitive_params
        or normalized_key in sensitive_headers
        or has_sensitive_name_token(key.strip())
    )


async def _scan_query_param_value(
    key: str,
    key_preview: str,
    value: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_params: frozenset[str],
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
    sensitive_headers: frozenset[str] = frozenset(),
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]]:
    is_sensitive = _query_name_is_sensitive(key, sensitive_params, sensitive_headers)
    content_preview: str | LazyPreview = (
        "[REDACTED]"
        if is_sensitive
        else _lazy_display(
            value, sensitive_params, sensitive_body_fields, sensitive_headers
        )
    )
    json_redact_all = None if is_sensitive else False
    detected, trigger, threats = await _check_request_component(
        value,
        f"query_param:{key_preview}",
        f"query param '{key_preview}'",
        client_ip,
        correlation_id,
        enabled_categories,
        None if is_sensitive else log_level,
        content_preview=content_preview,
        sensitive_body_fields=sensitive_body_fields,
        excluded_body_fields=excluded_body_fields,
        json_redact_all=json_redact_all,
        sensitive_params=sensitive_params,
        patterns=patterns,
    )
    if detected and is_sensitive:
        _log_detected_component(
            "[REDACTED]", f"query param '{key_preview}'", client_ip, log_level
        )
    return detected, trigger, threats


def _query_pairs_with_repeats(request: GuardRequest) -> list[tuple[str, str]]:
    pairs = list(request.query_params.items())
    full_url = getattr(request, "url_full", None)
    if not isinstance(full_url, str):
        return pairs
    query = full_url.partition("?")[2].partition("#")[0]
    if not query:
        return pairs
    unscanned = Counter(pairs)
    for pair in parse_qsl(query, keep_blank_values=True, separator="&"):
        if unscanned[pair] > 0:
            unscanned[pair] -= 1
        else:
            pairs.append(pair)
    return pairs


async def _scan_query_pair(
    key: str,
    value: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_params: frozenset[str],
    sensitive_body_fields: frozenset[str],
    excluded_body_fields: frozenset[str],
    sensitive_headers: frozenset[str],
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]] | None:
    key_preview = redact_blob_for_display(
        key, sensitive_params, sensitive_body_fields, sensitive_headers
    )
    detected, trigger, threats = await _scan_component_name(
        key,
        f"query_param:{key_preview}",
        f"query param name '{key_preview}'",
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        content_preview=key_preview,
        patterns=patterns,
    )
    if detected:
        return True, f"Query param name '{key_preview}': {trigger}", threats
    detected, trigger, threats = await _scan_query_param_value(
        key,
        key_preview,
        value,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        sensitive_params,
        sensitive_body_fields,
        excluded_body_fields,
        sensitive_headers,
        patterns=patterns,
    )
    if detected:
        return True, f"Query param '{key_preview}': {trigger}", threats
    return None


async def _scan_query_params(
    request: GuardRequest,
    excluded_params: Collection[str] | Mapping[str, frozenset[str]],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_params: frozenset[str] = frozenset(),
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
    sensitive_headers: frozenset[str] = frozenset(),
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]]:
    all_enabled_categories = enabled_categories
    remainder = _SurfaceRemainder()
    skips = _skip_counter()
    for key, value in _query_pairs_with_repeats(request):
        scanned, enabled_categories = _param_scan_categories(
            key, excluded_params, all_enabled_categories
        )
        if not scanned:
            continue
        skipped_before = skips.count
        hit = await _scan_query_pair(
            key,
            value,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_params,
            sensitive_body_fields,
            excluded_body_fields,
            sensitive_headers,
            patterns=patterns,
        )
        if hit is not None:
            return hit
        if skips.count != skipped_before:
            remainder.add(
                _wire_pair(key, value),
                _query_name_is_sensitive(key, sensitive_params, sensitive_headers),
                (key, value),
            )
    if not remainder:
        return False, "", []
    return await _scan_surface_remainder(
        remainder,
        "&",
        "query_param",
        "Remaining query params",
        client_ip,
        correlation_id,
        log_level,
        lambda piece: redact_blob_for_display(
            piece, sensitive_params, sensitive_body_fields, sensitive_headers
        ),
        patterns=patterns,
    )


async def _scan_excluded_header_component(
    key: str,
    value: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_params: frozenset[str] = frozenset(),
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
    sensitive_headers: frozenset[str] = frozenset(),
    internal_host: bool = False,
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]] | None:
    if enabled_categories is None or "cmd_injection" in enabled_categories:
        detected, trigger, threats = _check_always_scan_header(key)
        if detected:
            _log_detected_component(key, f"header name '{key}'", client_ip, log_level)
            return True, f"Header name '{key}': {trigger}", threats
        detected, trigger, threats = _check_always_scan_header(value)
        if detected:
            display = redact_blob_for_display(
                value, sensitive_params, sensitive_body_fields, sensitive_headers
            )
            _log_detected_component(display, f"header '{key}'", client_ip, log_level)
            return True, f"Header '{key}': {trigger}", threats

    effective_categories = _excluded_header_effective_categories(
        key, value, enabled_categories, internal_host
    )
    if effective_categories is not None and not effective_categories:
        return None
    return await _scan_normal_header_component(
        key,
        value,
        effective_categories,
        client_ip,
        correlation_id,
        log_level,
        sensitive_body_fields=sensitive_body_fields,
        excluded_body_fields=excluded_body_fields,
        sensitive_params=sensitive_params,
        sensitive_headers=sensitive_headers,
        patterns=patterns,
    )


async def _scan_normal_header_component(
    key: str,
    value: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    content_preview: str | LazyPreview | None = None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
    sensitive_params: frozenset[str] = frozenset(),
    sensitive_headers: frozenset[str] = frozenset(),
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]] | None:
    detected, trigger, threats = await _scan_component_name(
        key,
        f"header:{key}",
        f"header name '{key}'",
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        patterns=patterns,
    )
    if detected:
        return True, f"Header name '{key}': {trigger}", threats
    json_redact_all = None
    if content_preview is None:
        content_preview = _lazy_display(
            value, sensitive_params, sensitive_body_fields, sensitive_headers
        )
        json_redact_all = False
    detected, trigger, threats = await _check_request_component(
        value,
        f"header:{key}",
        f"header '{key}'",
        client_ip,
        correlation_id,
        enabled_categories,
        log_level,
        content_preview=content_preview,
        sensitive_body_fields=sensitive_body_fields,
        excluded_body_fields=excluded_body_fields,
        json_redact_all=json_redact_all,
        sensitive_params=sensitive_params,
        patterns=patterns,
    )
    if detected:
        return True, f"Header '{key}': {trigger}", threats
    return None


async def _scan_sensitive_header(
    key: str,
    value: str,
    excluded_headers: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]] | None:
    if key.strip().lower() in excluded_headers:
        hit = await _scan_excluded_header_component(
            key,
            value,
            enabled_categories,
            client_ip,
            correlation_id,
            None,
            sensitive_body_fields=sensitive_body_fields,
            excluded_body_fields=excluded_body_fields,
            patterns=patterns,
        )
    else:
        hit = await _scan_normal_header_component(
            key,
            value,
            enabled_categories,
            client_ip,
            correlation_id,
            None,
            content_preview="[REDACTED]",
            sensitive_body_fields=sensitive_body_fields,
            excluded_body_fields=excluded_body_fields,
            patterns=patterns,
        )
    if hit is not None:
        _log_detected_component("[REDACTED]", f"header '{key}'", client_ip, log_level)
    return hit


def _header_items_to_scan(headers: Mapping[str, str]) -> Iterator[tuple[str, str]]:
    for key, value in headers.items():
        if key.strip().lower() != "cookie":
            yield key, value
            continue
        for pair in value.split(";"):
            if stripped := pair.strip(" "):
                yield key, stripped


async def _scan_header_item(
    key: str,
    value: str,
    internal_host: bool,
    excluded_headers: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_headers: frozenset[str],
    sensitive_body_fields: frozenset[str],
    excluded_body_fields: frozenset[str],
    sensitive_params: frozenset[str],
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]] | None:
    if name_is_sensitive(key, sensitive_headers):
        return await _scan_sensitive_header(
            key,
            value,
            excluded_headers,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            excluded_body_fields,
            patterns=patterns,
        )
    if key.strip().lower() in excluded_headers:
        return await _scan_excluded_header_component(
            key,
            value,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_params,
            sensitive_body_fields,
            excluded_body_fields,
            sensitive_headers,
            internal_host,
            patterns=patterns,
        )
    return await _scan_normal_header_component(
        key,
        value,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        sensitive_body_fields=sensitive_body_fields,
        excluded_body_fields=excluded_body_fields,
        sensitive_params=sensitive_params,
        sensitive_headers=sensitive_headers,
        patterns=patterns,
    )


async def _scan_headers(
    request: GuardRequest,
    excluded_headers: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_headers: frozenset[str] = frozenset(),
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
    sensitive_params: frozenset[str] = frozenset(),
    operator_excluded_headers: frozenset[str] = frozenset(),
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]]:
    items = list(_header_items_to_scan(request.headers))
    internal_host = any(
        key.strip().lower() == "host" and _host_header_names_an_internal_host(value)
        for key, value in items
    )
    remainder = _SurfaceRemainder()
    skips = _skip_counter()
    for key, value in items:
        if key.strip().lower() in operator_excluded_headers:
            continue
        skipped_before = skips.count
        hit = await _scan_header_item(
            key,
            value,
            internal_host,
            excluded_headers,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_headers,
            sensitive_body_fields,
            excluded_body_fields,
            sensitive_params,
            patterns=patterns,
        )
        if hit is not None:
            return hit
        if skips.count != skipped_before:
            remainder.add(
                f"{key}: {value}\r\n",
                name_is_sensitive(key, sensitive_headers),
                (key, value),
            )
    if not remainder:
        return False, "", []
    return await _scan_surface_remainder(
        remainder,
        "",
        "header",
        "Remaining headers",
        client_ip,
        correlation_id,
        log_level,
        lambda piece: redact_blob_for_display(
            piece, sensitive_params, sensitive_body_fields, sensitive_headers
        ),
        patterns=patterns,
    )


def _field_log_value(
    preview_override: str | None, is_sensitive: bool, display: str | None
) -> str | None:
    if preview_override is not None:
        return preview_override
    return "[REDACTED]" if is_sensitive else display


async def _scan_body_field(
    value: str,
    label: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    display: str | None = None,
    context: str = "request_body",
    preview_override: str | None = None,
    sensitive_params: frozenset[str] = frozenset(),
    scan_embedded_json: bool = True,
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]]:
    is_sensitive = name_is_sensitive(label, sensitive_body_fields)
    log_value: str | LazyPreview | None = _field_log_value(
        preview_override, is_sensitive, display
    )
    if log_value is None:
        log_value = _lazy_display(value, sensitive_params, sensitive_body_fields)
    detected, trigger, threats = await _check_request_component(
        value,
        context,
        label,
        client_ip,
        correlation_id,
        enabled_categories,
        None,
        scan_embedded_json=scan_embedded_json,
        content_preview=log_value,
        sensitive_params=sensitive_params,
        patterns=patterns,
    )
    if not detected:
        return False, "", []
    resolved = _resolve_preview(log_value)
    _log_detected_component(
        resolved if resolved is not None else value, label, client_ip, log_level
    )
    return True, f"Request body field '{label}': {trigger}", threats


async def _scan_blob_body_leaves(
    raw_body: str,
    excluded_body_fields: frozenset[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    sensitive_params: frozenset[str],
    sensitive_body_fields: frozenset[str],
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]] | None:
    if _JSON_CONTAINER_START(raw_body) is None:
        return None
    with _budget_that_is_never_spent(), _skipping_whole_value_path_rows():
        if excluded_body_fields or _body_field_category_skips.get():
            json_hit = await _scan_escaped_literals_through_exclusions(
                raw_body,
                "request_body",
                client_ip,
                correlation_id,
                enabled_categories,
                excluded_body_fields,
                sensitive_body_fields,
                True,
                sensitive_params,
                patterns=patterns,
            )
        else:
            json_hit = await _scan_string_literals(
                raw_body,
                "request_body",
                client_ip,
                correlation_id,
                enabled_categories,
                sensitive_body_fields,
                True,
                sensitive_params,
                patterns=patterns,
            )
    if json_hit is None or not json_hit[0]:
        return None
    return True, json_hit[1], json_hit[2]


async def _scan_blob_body(
    raw_body: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_params: frozenset[str] = frozenset(),
    sensitive_body_fields: frozenset[str] = frozenset(),
    force_redacted: bool = False,
    excluded_body_fields: frozenset[str] = frozenset(),
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]]:
    content_preview: str | LazyPreview = (
        "[REDACTED]"
        if force_redacted
        else LazyPreview(
            lambda: redact_blob_for_display(
                raw_body, sensitive_params, sensitive_body_fields
            )
        )
    )
    leaf_hit = await _scan_blob_body_leaves(
        raw_body,
        excluded_body_fields,
        enabled_categories,
        client_ip,
        correlation_id,
        sensitive_params,
        sensitive_body_fields,
        patterns=patterns,
    )
    if leaf_hit is not None:
        _log_detected_component(
            _resolve_preview(content_preview) or "",
            "request body",
            client_ip,
            log_level,
        )
        return leaf_hit
    with _budget_that_is_never_spent():
        detected, trigger, threats = await _check_request_component(
            raw_body,
            "request_body",
            "request body",
            client_ip,
            correlation_id,
            enabled_categories,
            log_level,
            scan_embedded_json=False,
            content_preview=content_preview,
            patterns=patterns,
        )
    if detected:
        return True, f"Request body: {trigger}", threats
    return False, "", []


async def _scan_request_body(
    raw_body: str,
    content_type: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    sensitive_params: frozenset[str] = frozenset(),
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]]:
    lowered = content_type.lower()
    if "application/x-www-form-urlencoded" in lowered:
        return await _scan_form_body(
            raw_body,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            sensitive_params,
            patterns=patterns,
        )
    if "multipart/form-data" in lowered:
        return await _scan_multipart_body(
            raw_body,
            content_type,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            sensitive_params,
            patterns=patterns,
        )

    if "json" in lowered:
        json_hit = await _scan_json_content(
            raw_body,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            sensitive_params,
            patterns=patterns,
        )
        if json_hit is not None:
            return json_hit
    return await _scan_blob_body(
        raw_body,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        sensitive_params,
        sensitive_body_fields,
        excluded_body_fields=frozenset(excluded_body_fields),
        patterns=patterns,
    )
