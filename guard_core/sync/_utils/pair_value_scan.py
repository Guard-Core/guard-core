import json
import re
from collections.abc import Callable
from urllib.parse import quote_plus, unquote_plus

_MAX_DECODE_ROUNDS = 3
_JSON_START_CHARS = frozenset("{[")


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


_EXTENDED_NAME_RUN_RE = re.compile(r"(?:[A-Za-z0-9_.\-]|%[0-9A-Fa-f]{2}|\+)+")
_ASSIGN_RE = re.compile(r"[^\S\r\n]*[=:][^\S\r\n]*")
_HARD_SEP_CHARS = frozenset("&;,?|/[]{}()\r\n<>")
_QUOTE_CHARS = frozenset("'\"")
_HARD_WS_CHARS = frozenset("\r\n")
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_REDACTED_MARKER = "[REDACTED]"


def _has_undecoded_percent_escape(text: str) -> bool:
    return "%" in text and _PERCENT_ESCAPE_RE.search(text) is not None


def _is_soft_ws(ch: str) -> bool:
    return ch.isspace() and ch not in _HARD_WS_CHARS


def _pair_starts_at(text: str, pos: int) -> bool:
    name_match = _EXTENDED_NAME_RUN_RE.match(text, pos)
    if name_match is None:
        return False
    return _ASSIGN_RE.match(text, name_match.end()) is not None


def _skip_soft_whitespace(text: str, pos: int) -> int:
    n = len(text)
    j = pos
    while j < n and _is_soft_ws(text[j]):
        j += 1
    return j


def _unquoted_value_extent(
    text: str,
    start: int,
    limit: int | None = None,
    separators: frozenset[str] = _HARD_SEP_CHARS,
    quotes: frozenset[str] = _QUOTE_CHARS,
) -> int:
    n = len(text) if limit is None else min(len(text), limit)
    i = start
    while i < n:
        ch = text[i]
        if ch in separators or ch in quotes:
            return i
        if _is_soft_ws(ch):
            j = _skip_soft_whitespace(text, i)
            if _pair_starts_at(text, j):
                return i
            i = j
            continue
        i += 1
    return i


_PAIR_END_CHARS = frozenset("&;\r\n<>")
_PAIR_OPENER_CHARS = _HARD_SEP_CHARS - _PAIR_END_CHARS
_PAIR_VALUE_NON_START_CHARS = _HARD_SEP_CHARS | {" ", "="}
_PAIR_START_RE = re.compile(_EXTENDED_NAME_RUN_RE.pattern + _ASSIGN_RE.pattern)
_SOFT_GAP_THEN_PAIR_RE = re.compile(r"([^\S\r\n]*)(" + _PAIR_START_RE.pattern + ")?")
_SECRET_STOP_RE = re.compile(r"[&;\r\n<>'\"\s,?|/\[\]{}()]")


def _pair_with_value_starts_at(text: str, pos: int) -> bool:
    pair_match = _PAIR_START_RE.match(text, pos)
    if pair_match is None:
        return False
    value_pos = pair_match.end()
    return value_pos < len(text) and text[value_pos] not in _PAIR_VALUE_NON_START_CHARS


def _secret_value_extent(text: str, start: int) -> int:
    i = start
    while True:
        stop = _SECRET_STOP_RE.search(text, i)
        if stop is None:
            return len(text)
        i = stop.start()
        ch = text[i]
        if ch in _PAIR_END_CHARS or ch in _QUOTE_CHARS:
            return i
        if ch in _PAIR_OPENER_CHARS:
            if _pair_with_value_starts_at(text, i + 1):
                return i
            i += 1
            continue
        gap = _SOFT_GAP_THEN_PAIR_RE.match(text, i)
        if gap.group(2) is not None:
            return i
        i = gap.end(1)


def _sensitive_value_extent(text: str, start: int, quote_char: str) -> int:
    if quote_char:
        idx = text.find(quote_char, start)
        return len(text) if idx == -1 else idx
    return _secret_value_extent(text, start)


def _restart_value_extent_at_quote(
    text: str, body_end: int, quote_char: str, blank_before: bool
) -> tuple[str, int]:
    candidate_quote = text[body_end]
    closing_idx = text.find(candidate_quote, body_end + 1)
    if closing_idx == -1:
        return (candidate_quote, len(text)) if blank_before else (quote_char, body_end)
    return candidate_quote, closing_idx


def _quote_char_at(text: str, pos: int) -> str:
    return text[pos] if pos < len(text) and text[pos] in _QUOTE_CHARS else ""


_ANGLE_OPEN = "<"
_ANGLE_VALUE_SEP_CHARS = _HARD_SEP_CHARS - frozenset("<>")


def _angle_value_extent(text: str, open_pos: int) -> int:
    return _unquoted_value_extent(
        text, open_pos, separators=_ANGLE_VALUE_SEP_CHARS, quotes=frozenset()
    )


def _build_redaction_result(
    text: str, quote_char: str, body_end: int
) -> tuple[str, int]:
    n = len(text)
    closed = bool(quote_char) and body_end < n and text[body_end] == quote_char
    replacement = f"{quote_char}[REDACTED]{quote_char if closed else ''}"
    end = body_end + (1 if closed else 0)
    return replacement, end


def _is_whole_redacted_marker(text: str, pos: int) -> bool:
    marker_end = pos + len(_REDACTED_MARKER)
    return (
        text.startswith(_REDACTED_MARKER, pos)
        and _secret_value_extent(text, marker_end) == marker_end
    )


def _redact_sensitive_pair_value(text: str, value_start: int) -> tuple[str, int]:
    if _is_whole_redacted_marker(text, value_start):
        return _REDACTED_MARKER, value_start + len(_REDACTED_MARKER)
    return _redact_sensitive_pair_value_extent(text, value_start)


def _redact_sensitive_pair_value_extent(text: str, value_start: int) -> tuple[str, int]:
    n = len(text)
    quote_char = _quote_char_at(text, value_start)
    body_start = value_start + (1 if quote_char else 0)
    body_end = _sensitive_value_extent(text, body_start, quote_char)
    if not quote_char and body_end < n and text[body_end] in _QUOTE_CHARS:
        blank_before = not _bounded_percent_decode(text[body_start:body_end]).strip()
        quote_char, body_end = _restart_value_extent_at_quote(
            text, body_end, quote_char, blank_before
        )
    if (
        not quote_char
        and body_end == body_start
        and body_end < n
        and text[body_end] == _ANGLE_OPEN
    ):
        return "[REDACTED]", _angle_value_extent(text, body_end)
    return _build_redaction_result(text, quote_char, body_end)


_JSON_SNIFF_WINDOW = 8


def _looks_like_json_start(text: str, pos: int) -> bool:
    if pos >= len(text):
        return False
    ch = text[pos]
    if ch in _JSON_START_CHARS:
        return True
    if ch != "%":
        return False
    decoded_prefix = _bounded_percent_decode(text[pos : pos + _JSON_SNIFF_WINDOW])
    return bool(decoded_prefix) and decoded_prefix[0] in _JSON_START_CHARS


def _redact_embedded_json_value(
    candidate: str,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> str | None:
    from guard_core.sync._utils.logging_utils import _redact_sensitive_json

    decoded = _bounded_percent_decode(candidate)
    try:
        parsed = json.loads(decoded)
    except ValueError:
        return None
    except RecursionError:
        return quote_plus("[REDACTED]")
    if not isinstance(parsed, dict | list):
        return None
    redacted = _redact_sensitive_json(
        parsed, sensitive, sensitive_body_fields, max_depth
    )
    if redacted == parsed:
        return None
    serialized = json.dumps(redacted, separators=(",", ":"), ensure_ascii=False)
    return quote_plus(serialized)


_JSON_CANDIDATE_MAX_LEN = 16384


def _redact_embedded_json_span(
    text: str,
    value_start: int,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> tuple[str, int] | None:
    value_end = _unquoted_value_extent(
        text, value_start, value_start + _JSON_CANDIDATE_MAX_LEN
    )
    redacted = _redact_embedded_json_value(
        text[value_start:value_end], sensitive, sensitive_body_fields, max_depth
    )
    if redacted is None:
        return None
    return redacted, value_end


_JSON_LIKELY_CHARS = frozenset("{[%")


def _try_redact_json_span(
    text: str,
    value_start: int,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> tuple[str, int] | None:
    if not _looks_like_json_start(text, value_start):
        return None
    return _redact_embedded_json_span(
        text, value_start, sensitive, sensitive_body_fields, max_depth
    )
