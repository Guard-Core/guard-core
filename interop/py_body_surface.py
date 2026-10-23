"""Python-side participants for the body extraction differential.

`surface_entries` rebuilds the STATIC scan-value list the reference engine
derives from one request body, in scan order, using the exact same helper
functions the production path uses (guard_core/_utils/body_form_scan.py,
body_json_scan.py, embedded_json_scan.py, binary_islands.py). The list is
the worst-case scan surface: every value the engine WOULD scan when nothing
matched earlier, which is what the ports' extractors emit as their value
lists.

`body_verdict` runs the live end-to-end request scan
(detect_penetration_attempt) for detect-level expectations.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl

from guard_core._utils.body_json_scan import (
    _MONGO_OPERATOR_KEY_RE,
    _json_object_with_every_pair,
)
from guard_core._utils.detection_scan import (
    _JSON_CONTAINER_START,
    _binary_island_min_run_length,
    _json_depth_cap_value,
)
from guard_core._utils.embedded_json_scan import (
    _TOO_DEEP_TO_PARSE,
    _decoded_string_literal,
    _escaped_string_literals,
    _parse_embedded_json,
)
from guard_core.detection_engine.binary_islands import (
    extract_binary_islands,
    value_is_binary_like,
)
from guard_core.handlers._suspatterns_sources import (
    _EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX,
)

FORM_FIELD_CONTEXT = "request_body:form_field"
MULTIPART_FIELD_CONTEXT = "request_body:multipart_field"
REQUEST_BODY_CONTEXT = "request_body"
# An embedded walk is always redacting (redact_keys=redact_all), so its key
# contexts carry this label in place of the key text.
_REDACTED_KEY = "[REDACTED]"


@dataclass
class Entry:
    """One extracted scan value with reporting annotations."""

    value: str
    context: str
    forced: str | None = None
    role: str = "value"
    island: bool = False


def _escaped_literal_entries(value: str, suffixed_context: str) -> list[Entry]:
    """_scan_string_literals: each backslash-bearing string literal, decoded.

    A decoded literal is scanned like any body field: its own embedded-JSON
    check first, then its text, both under the suffixed context.
    """
    entries: list[Entry] = []
    for literal in _escaped_string_literals(value):
        decoded = _decoded_string_literal(literal)
        entries.extend(_embedded_entries(decoded, suffixed_context))
        entries.append(Entry(decoded, suffixed_context, role="literal"))
    return entries


def _embedded_entries(value: str, context: str) -> list[Entry]:
    """What _check_embedded_json scans for one string value, before the raw value.

    A value that starts a JSON container and parses (within the parser depth
    bound) is walked with the embedded suffix on its context. A value nested
    past that bound is not parsed: only its string literals that contain a
    backslash are scanned, decoded, under the same suffixed context.
    """
    if _JSON_CONTAINER_START(value) is None:
        return []
    data = _parse_embedded_json(value)
    if data is None:
        return []
    suffixed = context + _EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX
    if data is _TOO_DEEP_TO_PARSE:
        return _escaped_literal_entries(value, suffixed)
    return _walk_entries(data, suffixed)


def _signature_of(kind: str, current: Any, label: Any) -> tuple[Any, ...] | None:
    """The frame's dedupe signature (_signature_of_frame, no exclusions)."""
    if kind == "entry":
        return ("key", str(current))
    if isinstance(current, dict | list):
        return None
    return ("leaf", str(current), label)


def _walk_entries(data: Any, context: str) -> list[Entry]:
    """Mirror of _scan_json_value's traversal, collecting static entries.

    An embedded walk (context ends with the embedded suffix) has no depth cap
    and skips a key or a leaf it already scanned clean (D-124 item 1); the
    declared body's walk keeps the depth cap and scans everything.
    """
    entries: list[Entry] = []
    embedded = context.endswith(_EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX)
    max_depth = sys.maxsize if embedded else _json_depth_cap_value()
    clean: set[tuple[Any, ...]] | None = set() if embedded else None
    stack: list[tuple[str, Any, Any, int]] = [("value", data, "", 1)]
    while stack:
        kind, current, label, depth = stack.pop()
        signature = _signature_of(kind, current, label) if clean is not None else None
        known_clean = clean is not None and signature in clean
        if known_clean and kind == "value":
            continue
        if kind == "entry":
            key_str = str(current)
            item = label
            if _MONGO_OPERATOR_KEY_RE.match(key_str):
                entries.append(
                    Entry(key_str, REQUEST_BODY_CONTEXT, forced="nosql", role="key")
                )
                return entries
            if not known_clean:
                key_display = _REDACTED_KEY if embedded else key_str
                entries.append(Entry(key_str, f"{context}:{key_display}", role="key"))
            stack.append(("value", item, key_str, depth + 1))
        elif isinstance(current, dict | list):
            if depth >= max_depth:
                serialized = json.dumps(
                    current, separators=(",", ":"), ensure_ascii=False
                )
                entries.append(Entry(serialized, context, role="capped"))
            elif isinstance(current, dict):
                for key, item in reversed(list(current.items())):
                    stack.append(("entry", key, item, depth))
            else:
                for item in reversed(current):
                    stack.append(("value", item, label, depth + 1))
        else:
            leaf = str(current)
            entries.extend(_embedded_entries(leaf, context))
            entries.append(Entry(leaf, context, role="leaf"))
        if clean is not None and signature is not None:
            clean.add(signature)
    return entries


def _embedded_or_raw(value: str, context: str) -> list[Entry]:
    """The scan list of one form/multipart field value: embedded walk, then raw."""
    return [*_embedded_entries(value, context), Entry(value, context, role="raw")]


def _blob_entries(raw_body: str) -> list[Entry]:
    """An undeclared (or unparsed) body: escaped literals, then the whole text.

    Only the string literals that contain a backslash are scanned on their own,
    decoded, under the embedded context; a body without one is not walked
    (D-124 item 2). The raw body is scanned once afterwards.
    """
    entries: list[Entry] = []
    if _JSON_CONTAINER_START(raw_body) is not None:
        suffixed = REQUEST_BODY_CONTEXT + _EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX
        entries.extend(_escaped_literal_entries(raw_body, suffixed))
    entries.append(Entry(raw_body, REQUEST_BODY_CONTEXT, role="blob"))
    return entries


def _per_part_entry_tuples(
    raw_body: str, content_type: str
) -> list[list[tuple[str | None, str, str]]] | None:
    """The engine's entry tuples grouped per leaf part (walk order).

    The engine's _multipart_text_parts flattens these groups into one list
    and _scan_multipart_part re-scans the label before every entry, so a
    part with k entries scans its label k times. The ports emit the label
    once per part. The re-scans are first-hit-identical (a threat in the
    label stops both engines at the first scan), so the repeated
    occurrences are annotated `name_repeat` and excluded from the
    extraction multiset comparison; the first scan per part stays.
    """
    from email.parser import Parser
    from email.policy import compat32

    from guard_core._utils.body_form_scan import _multipart_part_entries

    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n"
    message = Parser(policy=compat32).parsestr(header + raw_body)
    if not message.is_multipart():
        return None
    groups: list[list[tuple[str | None, str, str]]] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        groups.append(_multipart_part_entries(part))
    return groups


def _flag_islands(
    raw_body: str, content_type: str, entries: list[Entry]
) -> list[Entry]:
    """Recover the island flag for multipart entries.

    The engine's _multipart_part_entries reduces binary-like file-part
    payloads with extract_binary_islands before scanning; the flag is
    recovered by walking the parsed parts again and recording which values
    the reduction produced. The flag is reporting-only: the (value, context)
    multiset already captures the reduction outcome.
    """
    from email.parser import Parser
    from email.policy import compat32

    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n"
    message = Parser(policy=compat32).parsestr(header + raw_body)
    if not message.is_multipart():
        return entries
    island_values: set[str] = set()
    min_run = _binary_island_min_run_length()
    for part in message.walk():
        if part.is_multipart():
            continue
        payload = getattr(part, "_payload", None)
        filename = part.get_filename()
        if not isinstance(payload, str) or filename is None:
            continue
        if not value_is_binary_like(payload):
            continue
        for island in extract_binary_islands(payload, min_run):
            island_values.add(island)
    for entry in entries:
        if entry.context == MULTIPART_FIELD_CONTEXT and entry.value in island_values:
            entry.island = True
    return entries


def surface_entries(raw_body: str, content_type: str) -> list[Entry]:
    """The static scan list for one body, mirroring _scan_request_body."""
    lowered = content_type.lower()
    if "application/x-www-form-urlencoded" in lowered:
        entries: list[Entry] = []
        for name, value in parse_qsl(
            raw_body, keep_blank_values=True, errors="surrogateescape"
        ):
            entries.append(Entry(name, REQUEST_BODY_CONTEXT, role="name"))
            entries.extend(_embedded_or_raw(value, FORM_FIELD_CONTEXT))
        return entries

    if "multipart/form-data" in lowered:
        groups = _per_part_entry_tuples(raw_body, content_type)
        if groups is not None:
            listed = []
            for part_tuples in groups:
                for entry_index, (_key, label, value) in enumerate(part_tuples):
                    listed.append(
                        Entry(
                            label,
                            REQUEST_BODY_CONTEXT,
                            role="name" if entry_index == 0 else "name_repeat",
                        )
                    )
                    listed.extend(_embedded_or_raw(value, MULTIPART_FIELD_CONTEXT))
            return _flag_islands(raw_body, content_type, listed)
        return _blob_entries(raw_body)

    if "json" in lowered:
        try:
            parsed = json.loads(
                raw_body, object_pairs_hook=_json_object_with_every_pair
            )
        except Exception:
            parsed = None
        if isinstance(parsed, dict | list):
            return _walk_entries(parsed, REQUEST_BODY_CONTEXT)

    return _blob_entries(raw_body)


async def body_verdict(
    body_bytes: bytes,
    content_type: str,
    query: dict[str, str] | None = None,
    url_path: str = "/",
) -> dict[str, Any]:
    """The live end-to-end scan verdict for one request (reference truth)."""
    from typing import cast

    from guard_core._utils.penetration_detection import detect_penetration_attempt
    from guard_core.models import SecurityConfig
    from guard_core.protocols.request_protocol import GuardRequest

    config = SecurityConfig(detection_max_body_inspect_bytes=65536)

    class _BodyRequest:
        def __init__(self, body: bytes) -> None:
            self._body = body
            self.query_params: dict[str, str] = query or {}
            self.headers: dict[str, str] = {
                "content-type": content_type,
                "content-length": str(len(body)),
            }
            self.url_path = url_path
            self.method = "POST"
            self.client_host = "127.0.0.1"
            self.state = type("S", (), {})()

        async def body(self) -> bytes:
            return self._body

    result = await detect_penetration_attempt(
        cast(GuardRequest, _BodyRequest(body_bytes)), config
    )
    return {
        "is_threat": result.is_threat,
        "trigger_info": result.trigger_info,
        "categories": sorted(result.threat_categories),
    }
