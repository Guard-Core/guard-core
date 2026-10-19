from typing import Any

_HSTS_FLAGS = ("include_subdomains", "preload")


def _splits_a_directive(char: str) -> bool:
    return ord(char) < 32 or ord(char) == 127 or char in ";,"


def _plain_directive_name(name: Any) -> bool:
    return (
        isinstance(name, str)
        and bool(name)
        and not any(_splits_a_directive(char) or char.isspace() for char in name)
    )


def _plain_directive_source(source: Any) -> bool:
    return isinstance(source, str) and not any(
        _splits_a_directive(char) for char in source
    )


def _plain_directive_sources(sources: Any) -> bool:
    return isinstance(sources, list) and all(map(_plain_directive_source, sources))


def validate_cached_csp(record: Any) -> dict[str, list[str]]:
    if not isinstance(record, dict):
        raise ValueError("the record is not a JSON object")
    if not all(map(_plain_directive_name, record)):
        raise ValueError(
            "a directive name is not a plain token (control character, "
            "whitespace, ';' or ',')"
        )
    if not all(map(_plain_directive_sources, record.values())):
        raise ValueError(
            "a directive's sources are not a list of strings free of control "
            "characters, ';' and ','"
        )
    return record


def _non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _hsts_flags_are_booleans(record: dict[str, Any]) -> bool:
    return all(isinstance(record.get(flag, False), bool) for flag in _HSTS_FLAGS)


def validate_cached_hsts(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError("the record is not a JSON object")
    if not _non_negative_int(record.get("max_age")):
        raise ValueError("max_age must be a non-negative integer")
    if not _hsts_flags_are_booleans(record):
        raise ValueError("include_subdomains and preload must be booleans")
    return record
