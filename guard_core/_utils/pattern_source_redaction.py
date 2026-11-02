import re
from contextvars import ContextVar
from typing import TYPE_CHECKING, Protocol

from guard_core._lazy_patterns import LazyPatterns, module_attribute_lookup

if TYPE_CHECKING:
    from guard_core._security_config_fields import RequestT
    from guard_core.handlers.suspatterns_handler import SusPatternsManager
    from guard_core.models import SecurityConfig


class _SensitiveNameSets(Protocol):
    _sensitive_headers_union: frozenset[str]
    _sensitive_params_union: frozenset[str]
    _sensitive_body_fields_union: frozenset[str]


_PATTERNS = LazyPatterns(
    {
        "_PATTERN_SOURCE_NON_TOKEN_RE": (r"[^a-z0-9_-]+", 0),
        "_PATTERN_SOURCE_ESCAPE_RE": (
            r"\\(?:[xX]([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|([0-7]{1,3}))",
            0,
        ),
    }
)
__getattr__ = module_attribute_lookup(_PATTERNS)


# The manager of the app whose request is being scanned: its own sensitive names
# redact the pattern text, never another app's.
_redacting_patterns: ContextVar["SusPatternsManager | None"] = ContextVar(
    "guard_core_redacting_patterns", default=None
)


def _decode_pattern_source_escape(match: re.Match[str]) -> str:
    hex_body = match.group(1) or match.group(2) or match.group(3)
    code = int(hex_body, 16) if hex_body else int(match.group(4), 8)
    return chr(code) if code <= 0x10FFFF else match.group(0)


def _pattern_source_names_a_sensitive_field(
    pattern_source: str, sensitive_names: frozenset[str]
) -> bool:
    decoded = _PATTERNS["_PATTERN_SOURCE_ESCAPE_RE"].sub(
        _decode_pattern_source_escape, pattern_source
    )
    normalized = _PATTERNS["_PATTERN_SOURCE_NON_TOKEN_RE"].sub("", decoded.lower())
    return any(name in normalized for name in sensitive_names)


class _ConfigSensitiveNames:
    """The sensitive names a config declares, before any manager exists for it."""

    def __init__(
        self, config: "SecurityConfig[RequestT]", **overrides: frozenset[str]
    ) -> None:
        def names(field: str) -> frozenset[str]:
            return overrides.get(field, getattr(config, field, frozenset()))

        self._sensitive_headers_union = names("log_sensitive_headers")
        self._sensitive_params_union = names("log_sensitive_params")
        self._sensitive_body_fields_union = names("log_sensitive_body_fields")


def _redact_pattern_source_of_app(
    pattern_source: str, config: "SecurityConfig[RequestT]"
) -> str:
    from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for

    return _redact_pattern_source(pattern_source, sus_patterns_manager_for(config))


def _redact_pattern_source(
    pattern_source: str, patterns: "_SensitiveNameSets | None" = None
) -> str:
    from guard_core._utils.request_logging import (
        _merge_sensitive_log_body_fields,
        _merged_sensitive_names,
        redact_blob_for_display,
    )
    from guard_core.handlers.suspatterns_handler import active_sus_patterns

    patterns = patterns or _redacting_patterns.get() or active_sus_patterns()
    sensitive_params = patterns._sensitive_params_union
    sensitive_body_fields = patterns._sensitive_body_fields_union
    sensitive_headers = patterns._sensitive_headers_union

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
