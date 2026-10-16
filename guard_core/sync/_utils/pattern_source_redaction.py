import re

_PATTERN_SOURCE_NON_TOKEN_RE = re.compile(r"[^a-z0-9_-]+")
_PATTERN_SOURCE_ESCAPE_RE = re.compile(
    r"\\(?:[xX]([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|([0-7]{1,3}))"
)


def _decode_pattern_source_escape(match: re.Match[str]) -> str:
    hex_body = match.group(1) or match.group(2) or match.group(3)
    code = int(hex_body, 16) if hex_body else int(match.group(4), 8)
    return chr(code) if code <= 0x10FFFF else match.group(0)


def _pattern_source_names_a_sensitive_field(
    pattern_source: str, sensitive_names: frozenset[str]
) -> bool:
    decoded = _PATTERN_SOURCE_ESCAPE_RE.sub(
        _decode_pattern_source_escape, pattern_source
    )
    normalized = _PATTERN_SOURCE_NON_TOKEN_RE.sub("", decoded.lower())
    return any(name in normalized for name in sensitive_names)


def _redact_pattern_source(pattern_source: str) -> str:
    from guard_core.sync._utils.request_logging import (
        _merge_sensitive_log_body_fields,
        _merged_sensitive_names,
        redact_blob_for_display,
    )
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    sensitive_params = sus_patterns_handler._sensitive_params_union
    sensitive_body_fields = sus_patterns_handler._sensitive_body_fields_union
    sensitive_headers = sus_patterns_handler._sensitive_headers_union

    sensitive_names = _merged_sensitive_names(
        sensitive_params,
        _merge_sensitive_log_body_fields(sensitive_body_fields),
        sensitive_headers,
    )
    if _pattern_source_names_a_sensitive_field(pattern_source, sensitive_names):
        return "[REDACTED]"

    return redact_blob_for_display(
        pattern_source, sensitive_params, sensitive_body_fields, sensitive_headers
    )
