import json
import re
from typing import Any

from guard_core._utils.detection_scan import (
    _json_depth_cap_value,
    _scan_component_name,
    _warn_json_depth_cap_reached_once,
)
from guard_core._utils.logging_utils import (
    _redact_sensitive_json,
    _sanitize_for_reporting,
)
from guard_core._utils.sensitive_names import name_is_sensitive


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


async def _scan_json_dict_entry_key(
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
    name_hit = await _scan_component_name(
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


async def _scan_capped_json_subtree(
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
    from guard_core._utils.body_content_scan import _scan_body_field

    _warn_json_depth_cap_reached_once(client_ip)
    serialized = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    redacted = _redact_sensitive_json(
        value, sensitive_params, sensitive_body_fields, _json_depth_cap_value()
    )
    display = json.dumps(redacted, separators=(",", ":"), ensure_ascii=False)
    return await _scan_body_field(
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
    )


async def _scan_json_container_frame(
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
        hit = await _scan_capped_json_subtree(
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
        for key, item in reversed(list(current.items())):
            stack.append(("entry", key, item, depth, redact))
        return None
    for item in reversed(current):
        stack.append(("value", item, label, depth + 1, redact))
    return None


async def _scan_json_entry_frame(
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
) -> tuple[bool, str, list[dict]] | None:
    key_result = await _scan_json_dict_entry_key(
        key,
        excluded_body_fields,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        context,
        redact_keys,
    )
    if key_result is None:
        return None
    if key_result[0]:
        return key_result
    key_str = str(key)
    own_redact = redact or name_is_sensitive(key_str, sensitive_body_fields)
    stack.append(("value", item, key_str, depth + 1, own_redact))
    return None


async def _scan_json_value(
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
    from guard_core._utils.body_content_scan import _scan_body_field

    max_depth = _json_depth_cap_value()
    stack: list[tuple[str, Any, Any, int, bool]] = [
        ("value", value, key_label, 1, False)
    ]
    while stack:
        kind, first, second, depth, redact = stack.pop()
        if kind == "entry":
            hit = await _scan_json_entry_frame(
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
            )
            if hit is not None:
                return hit
            continue
        current, label = first, second
        if isinstance(current, dict | list):
            hit = await _scan_json_container_frame(
                current,
                label,
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
            if hit is not None:
                return hit
            continue
        leaf_preview = (
            preview_override
            if preview_override is not None
            else ("[REDACTED]" if redact else None)
        )
        scalar_hit = await _scan_body_field(
            str(current),
            label,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            context=context,
            preview_override=leaf_preview,
            sensitive_params=sensitive_params,
        )
        if scalar_hit[0]:
            return scalar_hit
    return False, "", []


async def _scan_json_content(
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
        return await _scan_json_value(
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
