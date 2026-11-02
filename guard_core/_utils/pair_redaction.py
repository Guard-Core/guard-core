import re
from collections.abc import Callable
from urllib.parse import unquote, unquote_plus

from guard_core._lazy_patterns import LazyPatterns, module_attribute_lookup
from guard_core._utils.pair_hidden_assign import _handle_no_literal_assign
from guard_core._utils.pair_value_scan import (
    _JSON_LIKELY_CHARS,
    _QUOTE_CHARS,
    _redact_sensitive_pair_value,
    _try_redact_json_span,
)
from guard_core._utils.pair_value_scan import _PATTERNS as _PAIR_VALUE_PATTERNS
from guard_core._utils.sensitive_names import name_is_sensitive

_MAX_DECODE_ROUNDS = 3


def _bounded_percent_decode(
    text: str, decode_fn: Callable[[str], str] = unquote_plus
) -> str:
    if "%" not in text and "+" not in text:
        return text
    decoded = text
    for _ in range(_MAX_DECODE_ROUNDS):
        next_decoded = decode_fn(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    return decoded


_NAME_CHAR_CLASS = r"[A-Za-z0-9_.\-+]"
_PERCENT_ESCAPE_SOURCE = r"%[0-9A-Fa-f]{2}"
_NAME_CORE = (
    rf"(?={_NAME_CHAR_CLASS}|{_PERCENT_ESCAPE_SOURCE})"
    rf"{_NAME_CHAR_CLASS}*(?:{_PERCENT_ESCAPE_SOURCE}{_NAME_CHAR_CLASS}*)*"
)
_PAIR_HEAD_RE = re.compile(
    rf"(?P<name>\"{_NAME_CORE}\"|'{_NAME_CORE}'|{_NAME_CORE})"
    r"(?P<assign>[^\S\r\n]*[=:][=:]*(?:[^\S\r\n]+[=:]*)*)?"
)


def _advance_past_non_name(text: str, pos: int) -> int:
    non_name_match = _PATTERNS["_NON_NAME_RUN_RE"].match(text, pos)
    return non_name_match.end() if non_name_match is not None else pos + 1


_PLUS_SENTINEL = ""
_PATTERNS = LazyPatterns(
    {
        "_NON_NAME_RUN_RE": (r"[^A-Za-z0-9_.\-%+'\"]+", 0),
        "_NAME_BOUNDARY_RE": (rf"[^A-Za-z0-9_.\-%{_PLUS_SENTINEL}]", 0),
    }
)
__getattr__ = module_attribute_lookup(_PATTERNS, _PAIR_VALUE_PATTERNS)


def _finish_name_segment(segment: str) -> str:
    return segment.replace(_PLUS_SENTINEL, " ").strip()


def _decode_pair_name_slow(bare_name: str, sensitive: frozenset[str]) -> str:
    protected = bare_name.replace("+", _PLUS_SENTINEL)
    decoded = _bounded_percent_decode(protected, unquote).strip()
    boundaries = list(_PATTERNS["_NAME_BOUNDARY_RE"].finditer(decoded))
    if not boundaries:
        return _finish_name_segment(decoded)
    starts = [0] + [boundary.end() for boundary in boundaries]
    ends = [boundary.start() for boundary in boundaries] + [len(decoded)]
    candidates = [
        _finish_name_segment(decoded[start:end])
        for start, end in zip(starts, ends, strict=True)
    ]
    for candidate in candidates:
        if candidate and name_is_sensitive(candidate, sensitive):
            return candidate
    return candidates[-1] if candidates[-1] else candidates[0]


def _apply_result(
    out: list[str],
    text: str,
    flush_start: int,
    value_start: int,
    result: tuple[str, int],
) -> tuple[int, int]:
    replacement, end = result
    out.append(text[flush_start:value_start])
    out.append(replacement)
    return end, end


def _resolve_pair_result(
    text: str,
    value_start: int,
    decoded_name: str,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> tuple[str, int] | None:
    if name_is_sensitive(decoded_name, sensitive) or (
        "%" in decoded_name
        and _PAIR_VALUE_PATTERNS["_PERCENT_ESCAPE_RE"].search(decoded_name) is not None
    ):
        return _redact_sensitive_pair_value(text, value_start)
    if text[value_start : value_start + 1] in _JSON_LIKELY_CHARS:
        return _try_redact_json_span(
            text, value_start, sensitive, sensitive_body_fields, max_depth
        )
    return None


def _redact_pairs_in_text_ex(
    text: str,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str] = frozenset(),
    max_depth: int = 32,
) -> tuple[str, bool]:
    pair_head_re = _PAIR_HEAD_RE
    handle_no_literal_assign = _handle_no_literal_assign
    out: list[str] = []
    flush_start = 0
    i = 0
    n = len(text)
    dangling = False
    gap_cache: dict[int, int] = {}
    while i < n:
        dangling = False
        head_match = pair_head_re.match(text, i)
        if head_match is None:
            i = _advance_past_non_name(text, i)
            continue
        raw_run = head_match.group("name")
        assign_end = head_match.end("assign")
        if assign_end == -1:
            i, flush_start, value_start = handle_no_literal_assign(
                text,
                head_match.end("name"),
                raw_run,
                sensitive,
                out,
                flush_start,
                i,
                sensitive_body_fields,
                max_depth,
                gap_cache,
            )
            if value_start is None:
                continue
        else:
            value_start = assign_end
        bare_name = raw_run[1:-1] if raw_run[:1] in _QUOTE_CHARS else raw_run
        decoded_name = (
            bare_name
            if "%" not in bare_name and "+" not in bare_name
            else _decode_pair_name_slow(bare_name, sensitive)
        )
        result = _resolve_pair_result(
            text, value_start, decoded_name, sensitive, sensitive_body_fields, max_depth
        )
        if result is not None:
            dangling = result[1] == value_start and result[1] == n
            i, flush_start = _apply_result(out, text, flush_start, value_start, result)
            continue
        i = value_start
    out.append(text[flush_start:i])
    return "".join(out), dangling


def _redact_pairs_in_text(
    text: str,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str] = frozenset(),
    max_depth: int = 32,
) -> str:
    return _redact_pairs_in_text_ex(text, sensitive, sensitive_body_fields, max_depth)[
        0
    ]
