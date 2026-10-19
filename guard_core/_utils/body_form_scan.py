from typing import Any

from guard_core._utils.detection_scan import (
    _binary_island_min_run_length,
    _body_remainder_display,
    _scan_component_name,
    _scan_surface_remainder,
    _skipped_values_so_far,
    _SurfaceRemainder,
    _wire_pair,
)
from guard_core._utils.sensitive_names import name_is_sensitive
from guard_core.detection_engine.binary_islands import (
    extract_binary_islands,
    value_is_binary_like,
)

_FORM_FIELD_CONTEXT = "request_body:form_field"
_MULTIPART_FIELD_CONTEXT = "request_body:multipart_field"


async def _scan_form_field(
    name: str,
    value: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str],
    sensitive_params: frozenset[str],
) -> tuple[bool, str, list[dict]] | None:
    from guard_core._utils.body_content_scan import _scan_body_field

    name_hit = await _scan_component_name(
        name,
        "request_body",
        f"form field name '{name}'",
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
    )
    if name_hit[0]:
        return True, f"Form field name '{name}': {name_hit[1]}", name_hit[2]
    hit = await _scan_body_field(
        value,
        name,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        sensitive_body_fields,
        context=_FORM_FIELD_CONTEXT,
        sensitive_params=sensitive_params,
    )
    return hit if hit[0] else None


async def _scan_form_body(
    raw_body: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]]:
    from urllib.parse import parse_qsl

    remainder = _SurfaceRemainder()
    for name, value in parse_qsl(
        raw_body, keep_blank_values=True, errors="surrogateescape"
    ):
        if name.lower() in excluded_body_fields:
            continue
        skipped_before = _skipped_values_so_far()
        hit = await _scan_form_field(
            name,
            value,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            sensitive_params,
        )
        if hit is not None:
            return hit
        if _skipped_values_so_far() != skipped_before:
            remainder.add(
                _wire_pair(name, value),
                name_is_sensitive(name, sensitive_body_fields),
            )
    if not remainder:
        return False, "", []
    return await _scan_surface_remainder(
        remainder,
        "&",
        "request_body",
        "Remaining form fields",
        client_ip,
        correlation_id,
        log_level,
        _body_remainder_display(sensitive_params, sensitive_body_fields),
    )


def _island_payload_entries(
    exclusion_key: str | None, label: str, payload: str
) -> list[tuple[str | None, str, str]]:
    return [
        (exclusion_key, label, island)
        for island in extract_binary_islands(payload, _binary_island_min_run_length())
    ]


def _part_payload_entries(
    exclusion_key: str | None, label: str, filename: str | None, payload: Any
) -> list[tuple[str | None, str, str]]:
    if not isinstance(payload, str):
        return []
    if filename is not None and value_is_binary_like(payload):
        return _island_payload_entries(exclusion_key, label, payload)
    if not payload:
        return []
    return [(exclusion_key, label, payload)]


def _multipart_part_entries(part: Any) -> list[tuple[str | None, str, str]]:
    entries: list[tuple[str | None, str, str]] = []
    name = part.get_param("name", header="content-disposition")
    filename = part.get_filename()
    exclusion_key = str(name) if name is not None else None
    label = exclusion_key if exclusion_key is not None else "file"
    if filename is not None:
        sanitized_filename = filename.replace('"', "").replace("'", "")
        entries.append((exclusion_key, label, f'filename="{sanitized_filename}"'))
    for header_name, header_value in part.items():
        entries.append((exclusion_key, label, f"{header_name}: {header_value}"))
    entries.extend(
        _part_payload_entries(
            exclusion_key, label, filename, getattr(part, "_payload", None)
        )
    )
    return entries


def _multipart_leaf_parts(raw_body: str, content_type: str) -> list[Any] | None:
    from email.parser import Parser
    from email.policy import compat32

    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n"
    message = Parser(policy=compat32).parsestr(header + raw_body)
    if not message.is_multipart():
        return None
    return [part for part in message.walk() if not part.is_multipart()]


def _multipart_text_parts(
    raw_body: str, content_type: str
) -> list[tuple[str | None, str, str]] | None:
    leaves = _multipart_leaf_parts(raw_body, content_type)
    if leaves is None:
        return None
    parts: list[tuple[str | None, str, str]] = []
    for part in leaves:
        parts.extend(_multipart_part_entries(part))
    return parts


def _multipart_field_values(
    raw_body: str, content_type: str
) -> list[tuple[str, str]] | None:
    leaves = _multipart_leaf_parts(raw_body, content_type)
    if leaves is None:
        return None
    fields = []
    for part in leaves:
        name = part.get_param("name", header="content-disposition")
        payload = getattr(part, "_payload", None)
        if name is not None and isinstance(payload, str):
            fields.append((str(name), payload))
    return fields


async def _scan_multipart_part(
    exclusion_key: str | None,
    label: str,
    value: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]] | None:
    from guard_core._utils.body_content_scan import _scan_body_field

    if exclusion_key is not None and exclusion_key.lower() in excluded_body_fields:
        return None
    name_hit = await _scan_component_name(
        label,
        "request_body",
        f"multipart field name '{label}'",
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
    )
    if name_hit[0]:
        return True, f"Multipart field name '{label}': {name_hit[1]}", name_hit[2]
    hit = await _scan_body_field(
        value,
        label,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        sensitive_body_fields,
        context=_MULTIPART_FIELD_CONTEXT,
        sensitive_params=sensitive_params,
    )
    if hit[0]:
        return hit
    return None


async def _scan_multipart_body(
    raw_body: str,
    content_type: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]]:
    from guard_core._utils.body_content_scan import _scan_blob_body

    parts = _multipart_text_parts(raw_body, content_type)
    if parts is None:
        return await _scan_blob_body(
            raw_body,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            force_redacted=True,
        )
    remainder = _SurfaceRemainder()
    for exclusion_key, label, value in parts:
        skipped_before = _skipped_values_so_far()
        hit = await _scan_multipart_part(
            exclusion_key,
            label,
            value,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            sensitive_params,
        )
        if hit is not None:
            return hit
        if _skipped_values_so_far() != skipped_before:
            sensitive = name_is_sensitive(label, sensitive_body_fields)
            remainder.add(label, False)
            remainder.add(value, sensitive)
    if not remainder:
        return False, "", []
    return await _scan_surface_remainder(
        remainder,
        "\r\n",
        "request_body",
        "Remaining multipart parts",
        client_ip,
        correlation_id,
        log_level,
        _body_remainder_display(sensitive_params, sensitive_body_fields),
    )
