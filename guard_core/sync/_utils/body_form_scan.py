from email.message import Message
from email.utils import collapse_rfc2231_value
from typing import TYPE_CHECKING, Protocol

from guard_core.sync._utils.detection_scan import (
    _binary_island_min_run_length,
    _body_field_category_skips,
    _body_field_scan_categories,
    _scan_component_name,
    _skip_counter,
)
from guard_core.sync._utils.form_pairs import iter_form_pairs
from guard_core.sync._utils.scan_remainder import (
    _body_remainder_display,
    _scan_surface_remainder,
    _SurfaceRemainder,
    _wire_pair,
)
from guard_core.sync._utils.sensitive_names import name_is_sensitive
from guard_core.sync.detection_engine.binary_islands import (
    extract_binary_islands,
    value_is_binary_like,
)

if TYPE_CHECKING:
    from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

_FORM_FIELD_CONTEXT = "request_body:form_field"
_MULTIPART_FIELD_CONTEXT = "request_body:multipart_field"


def _scan_form_field(
    name: str,
    value: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str],
    sensitive_params: frozenset[str],
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]] | None:
    from guard_core.sync._utils.body_content_scan import _scan_body_field

    name_hit = _scan_component_name(
        name,
        "request_body",
        f"form field name '{name}'",
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        patterns=patterns,
    )
    if name_hit[0]:
        return True, f"Form field name '{name}': {name_hit[1]}", name_hit[2]
    hit = _scan_body_field(
        value,
        name,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        sensitive_body_fields,
        context=_FORM_FIELD_CONTEXT,
        sensitive_params=sensitive_params,
        patterns=patterns,
    )
    return hit if hit[0] else None


def _scan_form_body(
    raw_body: str,
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
    remainder = _SurfaceRemainder()
    skips = _skip_counter()
    category_skips = _body_field_category_skips.get()
    for name, value in iter_form_pairs(raw_body):
        if name.lower() in excluded_body_fields:
            continue
        skipped_before = skips.count
        hit = _scan_form_field(
            name,
            value,
            _body_field_scan_categories(name, enabled_categories)
            if category_skips
            else enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            sensitive_params,
            patterns=patterns,
        )
        if hit is not None:
            return hit
        if skips.count != skipped_before:
            remainder.add(
                _wire_pair(name, value),
                name_is_sensitive(name, sensitive_body_fields),
                (name, value),
            )
    if not remainder:
        return False, "", []
    return _scan_surface_remainder(
        remainder,
        "&",
        "request_body",
        "Remaining form fields",
        client_ip,
        correlation_id,
        log_level,
        _body_remainder_display(sensitive_params, sensitive_body_fields),
        patterns=patterns,
    )


def _island_payload_entries(
    exclusion_key: str | None, label: str, payload: str
) -> list[tuple[str | None, str, str]]:
    return [
        (exclusion_key, label, island)
        for island in extract_binary_islands(payload, _binary_island_min_run_length())
    ]


class _MultipartPart(Protocol):
    def get_param(self, param: str, /, *, header: str) -> object: ...

    def get_filename(self) -> str | None: ...

    def get_params(self, *, header: str) -> list[tuple[str, str]] | None: ...

    def items(self) -> list[tuple[str, str]]: ...


def _part_payload_entries(
    exclusion_key: str | None, label: str, filename: str | None, payload: object
) -> list[tuple[str | None, str, str]]:
    if not isinstance(payload, str):
        return []
    if filename is not None and value_is_binary_like(payload):
        return _island_payload_entries(exclusion_key, label, payload)
    if not payload:
        return []
    return [(exclusion_key, label, payload)]


def _further_filenames(part: _MultipartPart, filenames: list[str]) -> list[str]:
    for key, value in part.get_params(header="content-disposition") or []:
        if key.lower() == "filename":
            decoded = collapse_rfc2231_value(value).strip()
            if decoded not in filenames:
                filenames.append(decoded)
    return filenames


def _multipart_part_entries(part: _MultipartPart) -> list[tuple[str | None, str, str]]:
    entries: list[tuple[str | None, str, str]] = []
    name = part.get_param("name", header="content-disposition")
    filename = part.get_filename()
    exclusion_key = str(name) if name is not None else None
    label = exclusion_key if exclusion_key is not None else "file"
    filenames = [] if filename is None else [filename]
    header_entries = []
    for header_name, header_value in part.items():
        header_entries.append((exclusion_key, label, f"{header_name}: {header_value}"))
        lowered = header_value.lower()
        if header_name.lower() == "content-disposition" and (
            "filename*" in lowered or lowered.count("filename") > 1
        ):
            filenames = _further_filenames(part, filenames)
    for each_filename in filenames:
        sanitized_filename = each_filename.replace('"', "").replace("'", "")
        entries.append((exclusion_key, label, f'filename="{sanitized_filename}"'))
    entries.extend(header_entries)
    entries.extend(
        _part_payload_entries(
            exclusion_key, label, filename, getattr(part, "_payload", None)
        )
    )
    return entries


class _HeaderThenBody:
    def __init__(self, header: str, body: str) -> None:
        self._header = header
        self._body = body
        self._position = 0

    def read(self, size: int = -1, /) -> str:
        header_length = len(self._header)
        start = self._position
        stop = start + size if size >= 0 else header_length + len(self._body)
        self._position = stop
        if start >= header_length:
            return self._body[start - header_length : stop - header_length]
        if stop <= header_length:
            return self._header[start:stop]
        return self._header[start:] + self._body[: stop - header_length]


def _multipart_leaf_parts(raw_body: str, content_type: str) -> list[Message] | None:
    from email.parser import Parser
    from email.policy import compat32

    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n"
    message = Parser(policy=compat32).parse(_HeaderThenBody(header, raw_body))
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


def _scan_multipart_part(
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
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]] | None:
    from guard_core.sync._utils.body_content_scan import _scan_body_field

    if exclusion_key is not None and exclusion_key.lower() in excluded_body_fields:
        return None
    if exclusion_key is not None and _body_field_category_skips.get():
        enabled_categories = _body_field_scan_categories(
            exclusion_key, enabled_categories
        )
    name_hit = _scan_component_name(
        label,
        "request_body",
        f"multipart field name '{label}'",
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        patterns=patterns,
    )
    if name_hit[0]:
        return True, f"Multipart field name '{label}': {name_hit[1]}", name_hit[2]
    hit = _scan_body_field(
        value,
        label,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        sensitive_body_fields,
        context=_MULTIPART_FIELD_CONTEXT,
        sensitive_params=sensitive_params,
        patterns=patterns,
    )
    if hit[0]:
        return hit
    return None


def _scan_multipart_body(
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
    from guard_core.sync._utils.body_content_scan import _scan_blob_body

    parts = _multipart_text_parts(raw_body, content_type)
    if parts is None:
        return _scan_blob_body(
            raw_body,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            force_redacted=True,
            patterns=patterns,
        )
    remainder = _SurfaceRemainder()
    skips = _skip_counter()
    for exclusion_key, label, value in parts:
        skipped_before = skips.count
        hit = _scan_multipart_part(
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
            patterns=patterns,
        )
        if hit is not None:
            return hit
        if skips.count != skipped_before:
            sensitive = name_is_sensitive(label, sensitive_body_fields)
            remainder.add(label, False)
            remainder.add(value, sensitive)
    if not remainder:
        return False, "", []
    return _scan_surface_remainder(
        remainder,
        "\r\n",
        "request_body",
        "Remaining multipart parts",
        client_ip,
        correlation_id,
        log_level,
        _body_remainder_display(sensitive_params, sensitive_body_fields),
        patterns=patterns,
    )
