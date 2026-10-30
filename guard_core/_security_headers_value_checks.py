"""Value checks of a security-headers override: the record pulled from Redis and the
CSP and HSTS settings, so a value the headers builder cannot read is refused when it
is read, not on every response build."""

import re
from collections.abc import Mapping

from guard_core._security_headers_defaults import SECURITY_HEADER_NAMES


def _is_string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


_OVERRIDE_STRING_KEYS = tuple(
    key for key in SECURITY_HEADER_NAMES if key not in ("hsts", "csp", "custom")
)


def _hsts_values_readable(hsts: Mapping[str, object]) -> bool:
    max_age = hsts.get("max_age")
    age_ok = max_age is None or (
        isinstance(max_age, int) and not isinstance(max_age, bool)
    )
    return age_ok and all(
        isinstance(hsts.get(flag, False), bool)
        for flag in ("include_subdomains", "preload")
    )


def _require_readable_csp(csp: object) -> None:
    if csp is not None and not (
        isinstance(csp, dict) and all(_is_string_list(v) for v in csp.values())
    ):
        raise ValueError(
            "the csp override must map each directive to a list of sources"
        )


def _require_object_or_none(keys: Mapping[str, object], name: str) -> None:
    value = keys.get(name)
    if value is not None and not isinstance(value, dict):
        raise ValueError(f"the {name} override must be an object")


def _require_readable_hsts(hsts: object) -> None:
    if isinstance(hsts, dict) and not _hsts_values_readable(hsts):
        raise ValueError("the hsts override holds a value of the wrong type")


def _require_readable_custom(custom: object) -> None:
    if isinstance(custom, dict) and not all(
        isinstance(v, str) for v in custom.values()
    ):
        raise ValueError("the custom override must map header names to strings")


def _require_string_header_values(keys: Mapping[str, object]) -> None:
    for name in _OVERRIDE_STRING_KEYS:
        value = keys.get(name)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"the {name} override must be a string")


def _require_resolvable_override_keys(keys: Mapping[str, object]) -> None:
    """A record read from Redis is not trusted: a value the headers builder cannot
    read would raise on every response build, so the record is refused instead."""
    _require_readable_csp(keys.get("csp"))
    _require_object_or_none(keys, "hsts")
    _require_object_or_none(keys, "custom")
    _require_readable_hsts(keys.get("hsts"))
    _require_readable_custom(keys.get("custom"))
    _require_string_header_values(keys)


_CSP_DIRECTIVE_RE = re.compile(r"[A-Za-z0-9-]+")
_CSP_SOURCE_FORBIDDEN_RE = re.compile(r"[;\x00-\x1f\x7f]")


def require_clean_csp_directive(directive: object, sources: object) -> None:
    """A directive name or a source that carries ``;`` or a control character
    would add a directive or a header line of its own to the built policy."""
    if not isinstance(directive, str) or not _CSP_DIRECTIVE_RE.fullmatch(directive):
        raise ValueError(f"CSP directive name {directive!r} is not a token")
    if not isinstance(sources, list | tuple) or not all(
        isinstance(source, str) and not _CSP_SOURCE_FORBIDDEN_RE.search(source)
        for source in sources
    ):
        raise ValueError(
            f"the CSP sources of '{directive}' must be strings without ';' or "
            "control characters"
        )


def require_valid_hsts_max_age(max_age: object) -> None:
    if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age < 0:
        raise ValueError("the hsts max_age must be a non-negative integer")
