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
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl

from guard_core._utils.body_json_scan import _MONGO_OPERATOR_KEY_RE
from guard_core._utils.detection_scan import (
    _binary_island_min_run_length,
    _json_depth_cap_value,
)
from guard_core._utils.embedded_json_scan import _parse_embedded_json
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


@dataclass
class Entry:
    """One extracted scan value with reporting annotations."""

    value: str
    context: str
    forced: str | None = None
    role: str = "value"
    island: bool = False


def _walk_entries(data: Any, context: str) -> list[Entry]:
    """Mirror of _scan_json_value's traversal, collecting static entries."""
    entries: list[Entry] = []
    max_depth = _json_depth_cap_value()
    stack: list[tuple[str, Any, Any, int]] = [("value", data, "", 1)]
    while stack:
        kind, current, label, depth = stack.pop()
        if kind == "entry":
            key_str = str(current)
            item = label
            if _MONGO_OPERATOR_KEY_RE.match(key_str):
                entries.append(
                    Entry(key_str, REQUEST_BODY_CONTEXT, forced="nosql", role="key")
                )
                continue
            entries.append(Entry(key_str, f"{context}:{key_str}", role="key"))
            stack.append(("value", item, key_str, depth + 1))
            continue
        if isinstance(current, dict):
            if depth >= max_depth:
                serialized = json.dumps(
                    current, separators=(",", ":"), ensure_ascii=False
                )
                entries.append(Entry(serialized, context, role="capped"))
                continue
            for key, item in reversed(list(current.items())):
                stack.append(("entry", key, item, depth))
            continue
        if isinstance(current, list):
            if depth >= max_depth:
                serialized = json.dumps(
                    current, separators=(",", ":"), ensure_ascii=False
                )
                entries.append(Entry(serialized, context, role="capped"))
                continue
            for item in reversed(current):
                stack.append(("value", item, label, depth + 1))
            continue
        # Scalar leaf: when the walk context is not the plain body context,
        # the engine's _check_value_enhanced runs the embedded-JSON check on
        # the leaf string first (a leaf that parses as an object or array
        # walks again with another ':embedded_json' suffix) and then scans
        # the raw leaf unless that walk detected.
        inner = None
        if isinstance(current, str) and context != REQUEST_BODY_CONTEXT:
            inner = _parse_embedded_json(current)
            if isinstance(inner, dict | list):
                entries.extend(
                    _walk_entries(inner, context + _EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX)
                )
        entries.append(Entry(str(current), context, role="leaf"))
    return entries


def _embedded_or_raw(value: str, context: str) -> list[Entry]:
    """The scan list of one form/multipart field value.

    The reference scans the embedded JSON walk first (context plus the
    ':embedded_json' suffix) and then the raw value; the raw scan only
    short-circuits when the walk itself detects, so the static worst-case
    list always contains both.
    """
    data = _parse_embedded_json(value)
    if not isinstance(data, dict | list):
        return [Entry(value, context, role="raw")]
    return [
        *_walk_entries(data, context + _EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX),
        Entry(value, context, role="raw"),
    ]


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

    if "json" in lowered:
        try:
            parsed = json.loads(raw_body)
        except Exception:
            parsed = None
        if isinstance(parsed, dict | list):
            return _walk_entries(parsed, REQUEST_BODY_CONTEXT)

    return [Entry(raw_body, REQUEST_BODY_CONTEXT, role="blob")]


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
