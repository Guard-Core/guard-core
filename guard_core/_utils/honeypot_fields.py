import json
from collections.abc import Collection, Iterable
from typing import Any
from urllib.parse import parse_qsl

from guard_core._utils.body_form_scan import _multipart_field_values
from guard_core._utils.json_nesting import MAX_JSON_PARSE_DEPTH, _offset_nesting_exceeds

FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"
JSON_MEDIA_TYPE = "application/json"
MULTIPART_MEDIA_TYPE = "multipart/form-data"


def media_type_of(content_type: str) -> str:
    return content_type.split(";")[0].strip().lower()


def _value_is_filled(value: Any) -> bool:
    if value is None:
        return False
    return not (isinstance(value, str) and not value.strip())


def _any_trap_filled(
    fields: Iterable[tuple[str, Any]], trap_names: Collection[str]
) -> bool:
    return any(
        name.lower() in trap_names and _value_is_filled(value) for name, value in fields
    )


def _decode_text(raw_body: bytes) -> str:
    return raw_body.decode("utf-8", errors="surrogateescape")


def query_has_filled_trap(query: str, trap_names: Collection[str]) -> bool:
    return _any_trap_filled(
        parse_qsl(query, keep_blank_values=True, errors="surrogateescape"),
        trap_names,
    )


def form_has_filled_trap(raw_body: bytes, trap_names: Collection[str]) -> bool:
    return query_has_filled_trap(_decode_text(raw_body), trap_names)


def multipart_has_filled_trap(
    raw_body: bytes, content_type: str, trap_names: Collection[str]
) -> bool:
    fields = _multipart_field_values(_decode_text(raw_body), content_type)
    return fields is not None and _any_trap_filled(fields, trap_names)


def _decode_json_text(raw_body: bytes) -> str:
    encoding = json.detect_encoding(raw_body)
    errors = "surrogateescape" if encoding.startswith("utf-8") else "replace"
    return raw_body.decode(encoding, errors=errors)


def json_has_filled_trap(
    raw_body: bytes, trap_names: Collection[str]
) -> tuple[bool, Exception | None]:
    """Report whether any JSON object in the body fills a trap field.

    Every object is visited, nested objects and arrays included, and a key that
    repeats inside one object counts through each of its occurrences. A body that
    fails to parse still reports the traps filled before the failure, together
    with the error.
    """
    filled = False

    def inspect_object(pairs: list[tuple[str, Any]]) -> list[tuple[str, Any]]:
        nonlocal filled
        filled = filled or _any_trap_filled(pairs, trap_names)
        return pairs

    text = _decode_json_text(raw_body)
    too_deep_at = _offset_nesting_exceeds(text, MAX_JSON_PARSE_DEPTH)
    if too_deep_at is not None:
        text = text[:too_deep_at]
    try:
        json.loads(text, object_pairs_hook=inspect_object)
    except (ValueError, RecursionError) as error:
        if too_deep_at is not None:
            return filled, RecursionError("JSON nesting beyond the parse depth limit")
        return filled, error
    return filled, None
