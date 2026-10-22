import json
import re
import sys
from typing import Any

from guard_core.sync._utils.detection_scan import (
    _json_depth_cap_value,
    _scan_component_name,
    _skip_counter,
    _warn_json_depth_cap_reached_once,
)
from guard_core.sync._utils.logging_utils import (
    _redact_sensitive_json,
    _sanitize_for_reporting,
)
from guard_core.sync._utils.scan_remainder import (
    _body_remainder_display,
    _scan_surface_remainder,
    _SurfaceRemainder,
)
from guard_core.sync._utils.sensitive_names import name_is_sensitive
from guard_core.sync._utils.source_path_shapes import (
    SHAPE_KEYS,
    BenignShapePath,
    BenignShapePaths,
    benign_shape_grants,
    benign_shape_keys,
    enter_benign_shape,
    leave_benign_shape,
    mark_benign_shape,
    mark_benign_shape_path,
)
from guard_core.sync.handlers._suspatterns_sources import (
    _EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX,
)


class _RepeatedKey(str):
    """A key an object repeated: equal to no other key, so the dict keeps it.

    ``json.loads`` keeps only the last value of a repeated key, so a backend that
    keeps the first one would receive a payload the walk never saw.
    """

    __slots__ = ()

    def __eq__(self, other: object) -> bool:
        return self is other

    def __hash__(self) -> int:
        return id(self)


def _json_object_with_every_pair(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    merged = dict(pairs)
    if len(merged) == len(pairs):
        return merged
    every_pair: dict[str, Any] = {}
    for key, value in pairs:
        every_pair[_RepeatedKey(key) if key in every_pair else key] = value
    return every_pair


_MONGO_OPERATOR_KEY_RE = re.compile(
    r"^\$(?:ne|gt|gte|lt|lte|eq|in|nin|nor|and|or|not|all|size|exists|type|"
    r"mod|options|where|regex|expr|function|elemMatch)$"
)


def _mongo_operator_key_hit(key_str: str) -> tuple[bool, str, list[dict]]:
    threat = {
        "type": "regex",
        "pattern": _MONGO_OPERATOR_KEY_RE.pattern,
        "match": _sanitize_for_reporting(key_str),
        "position": 0,
        "category": "nosql",
    }
    return (
        True,
        f"JSON operator key '{key_str}': matched pattern "
        f"'{_MONGO_OPERATOR_KEY_RE.pattern}'",
        [threat],
    )


def _scan_json_dict_entry_key(
    key: Any,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    context: str = "request_body",
    redact_keys: bool = False,
) -> tuple[bool, str, list[dict]] | None:
    key_str = str(key)
    if key_str.lower() in excluded_body_fields:
        return None
    if _MONGO_OPERATOR_KEY_RE.match(key_str):
        return _mongo_operator_key_hit(key_str)
    key_display = "[REDACTED]" if redact_keys else key_str
    name_hit = _scan_component_name(
        key_str,
        f"{context}:{key_display}",
        f"JSON key '{key_display}'",
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        content_preview="[REDACTED]" if redact_keys else None,
    )
    if name_hit[0]:
        return True, f"JSON key '{key_display}': {name_hit[1]}", name_hit[2]
    return False, "", []


def _scan_capped_json_subtree(
    value: Any,
    key_label: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    context: str = "request_body",
    preview_override: str | None = None,
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]]:
    from guard_core.sync._utils.body_content_scan import _scan_body_field

    _warn_json_depth_cap_reached_once(client_ip)
    serialized = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    redacted = _redact_sensitive_json(
        value, sensitive_params, sensitive_body_fields, _json_depth_cap_value()
    )
    display = json.dumps(redacted, separators=(",", ":"), ensure_ascii=False)
    return _scan_body_field(
        serialized,
        key_label,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        sensitive_body_fields,
        display=display,
        context=context,
        preview_override=preview_override,
        scan_embedded_json=False,
    )


def _push_dict_entries(
    current: dict[Any, Any],
    label: str,
    depth: int,
    redact: bool,
    stack: list[tuple[str, Any, Any, int, bool]],
) -> None:
    in_shape = (
        frozenset()
        if SHAPE_KEYS.isdisjoint(current)
        else benign_shape_keys(current, label)
    )
    grants = benign_shape_grants(current, label) if in_shape else {}
    for key, item in reversed(list(current.items())):
        stack.append(
            (
                "entry",
                key,
                mark_benign_shape(item, grants[key]) if key in in_shape else item,
                depth,
                redact,
            )
        )


def _push_list_items(
    current: list[Any],
    label: str,
    depth: int,
    redact: bool,
    stack: list[tuple[str, Any, Any, int, bool]],
) -> None:
    in_shape = current.grants if type(current) is BenignShapePaths else None
    for item in reversed(current):
        stack.append(
            (
                "value",
                mark_benign_shape_path(item, in_shape)
                if in_shape is not None and isinstance(item, str)
                else item,
                label,
                depth + 1,
                redact,
            )
        )


def _scan_json_container_frame(
    current: Any,
    label: str,
    depth: int,
    redact: bool,
    max_depth: int,
    stack: list[tuple[str, Any, Any, int, bool]],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    context: str = "request_body",
    preview_override: str | None = None,
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]] | None:
    if depth >= max_depth:
        capped_preview = (
            preview_override
            if preview_override is not None
            else ("[REDACTED]" if redact else None)
        )
        hit = _scan_capped_json_subtree(
            current,
            label,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            context,
            capped_preview,
            sensitive_params,
        )
        return hit if hit[0] else None
    if isinstance(current, dict):
        _push_dict_entries(current, label, depth, redact, stack)
    else:
        _push_list_items(current, label, depth, redact, stack)
    return None


def _scan_json_entry_frame(
    key: Any,
    item: Any,
    depth: int,
    redact: bool,
    stack: list[tuple[str, Any, Any, int, bool]],
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    context: str = "request_body",
    redact_keys: bool = False,
    key_known_clean: bool = False,
) -> tuple[bool, str, list[dict]] | None:
    key_result = (
        (False, "", [])
        if key_known_clean
        else _scan_json_dict_entry_key(
            key,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            context,
            redact_keys,
        )
    )
    if key_result is None:
        return None
    if key_result[0]:
        return key_result
    key_str = str(key)
    own_redact = redact or name_is_sensitive(key_str, sensitive_body_fields)
    stack.append(("value", item, key_str, depth + 1, own_redact))
    return None


def _clean_signature(
    kind: str, first: Any, second: Any, excluded_body_fields: set[str]
) -> tuple[Any, ...] | None:
    # A key or a leaf an embedded walk already scanned clean gives the same verdict
    # again, so a nested value repeating one key per level is scanned once.
    if kind == "entry":
        key_text = str(first)
        return None if key_text.lower() in excluded_body_fields else ("key", key_text)
    if isinstance(first, dict | list):
        return None
    return (
        "leaf",
        str(first),
        second,
        first.grants if type(first) is BenignShapePath else None,
    )


def _json_skipped_text(kind: str, first: Any) -> str:
    if kind != "entry" and isinstance(first, dict | list):
        return json.dumps(first, separators=(",", ":"), ensure_ascii=False)
    return str(first)


def _scan_json_frame(
    kind: str,
    first: Any,
    second: Any,
    depth: int,
    redact: bool,
    max_depth: int,
    stack: list[tuple[str, Any, Any, int, bool]],
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str],
    context: str,
    preview_override: str | None,
    redact_keys: bool,
    sensitive_params: frozenset[str],
    key_known_clean: bool = False,
) -> tuple[bool, str, list[dict]] | None:
    from guard_core.sync._utils.body_content_scan import _scan_body_field

    if kind == "entry":
        return _scan_json_entry_frame(
            first,
            second,
            depth,
            redact,
            stack,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            context,
            redact_keys,
            key_known_clean,
        )
    if isinstance(first, dict | list):
        return _scan_json_container_frame(
            first,
            second,
            depth,
            redact,
            max_depth,
            stack,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            context,
            preview_override,
            sensitive_params,
        )
    leaf_preview = (
        preview_override
        if preview_override is not None
        else ("[REDACTED]" if redact else None)
    )
    shape_token = (
        enter_benign_shape(first.grants) if type(first) is BenignShapePath else None
    )
    try:
        scalar_hit = _scan_body_field(
            str(first),
            second,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            context=context,
            preview_override=leaf_preview,
            sensitive_params=sensitive_params,
        )
    finally:
        if shape_token is not None:
            leave_benign_shape(shape_token)
    return scalar_hit if scalar_hit[0] else None


def _scan_json_value(
    value: Any,
    key_label: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    context: str = "request_body",
    preview_override: str | None = None,
    redact_keys: bool = False,
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]]:
    embedded = context.endswith(_EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX)
    max_depth = sys.maxsize if embedded else _json_depth_cap_value()
    clean: set[tuple[Any, ...]] | None = set() if embedded else None
    stack: list[tuple[str, Any, Any, int, bool]] = [
        ("value", value, key_label, 1, False)
    ]
    remainder = _SurfaceRemainder()
    skips = _skip_counter()
    while stack:
        kind, first, second, depth, redact = stack.pop()
        signature = (
            None
            if clean is None
            else _clean_signature(kind, first, second, excluded_body_fields)
        )
        known_clean = clean is not None and signature in clean
        if known_clean and kind == "value":
            continue
        skipped_before = skips.count
        hit = _scan_json_frame(
            kind,
            first,
            second,
            depth,
            redact,
            max_depth,
            stack,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            context,
            preview_override,
            redact_keys,
            sensitive_params,
            known_clean,
        )
        if hit is not None:
            return hit
        if skips.count != skipped_before:
            remainder.add(_json_skipped_text(kind, first), kind != "entry" and redact)
        elif clean is not None and signature is not None:
            clean.add(signature)
    if not remainder:
        return False, "", []
    return _scan_surface_remainder(
        remainder,
        "\n",
        "request_body",
        "Remaining request body",
        client_ip,
        correlation_id,
        log_level,
        _body_remainder_display(sensitive_params, sensitive_body_fields),
    )


def _scan_json_content(
    raw_body: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]] | None:
    try:
        parsed_body = json.loads(
            raw_body, object_pairs_hook=_json_object_with_every_pair
        )
    except Exception:
        parsed_body = None
    if isinstance(parsed_body, dict | list):
        return _scan_json_value(
            parsed_body,
            "",
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            sensitive_params=sensitive_params,
        )
    return None
