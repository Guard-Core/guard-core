import bisect
import re
from collections.abc import Iterator

from guard_core._lazy_patterns import LazyPatterns, module_attribute_lookup
from guard_core.sync.detection_engine.scan_window import bounded_finditer
from guard_core.sync.handlers._suspatterns_file_upload import (
    _FILE_UPLOAD_ATTR_EQUALS_WHITESPACE_RE,
    _FILE_UPLOAD_BENIGN_TERMINAL_ALTERNATION,
    _FILE_UPLOAD_BENIGN_TERMINAL_EXTENSIONS,
    _FILE_UPLOAD_DANGEROUS_EXT_ALTERNATION,
    _FILE_UPLOAD_DANGEROUS_EXTENSION_RE,
    _FILE_UPLOAD_DANGEROUS_EXTENSIONS,
    _FILE_UPLOAD_DECODED_TRUNCATION_RE,
    _FILE_UPLOAD_DOUBLE_EXT_ALTERNATION,
    _FILE_UPLOAD_DOUBLE_EXT_EXTENSIONS,
    _FILE_UPLOAD_DOUBLE_EXTENSION_RE,
    _FILE_UPLOAD_FILENAME_EQUALS_RE,
    _FILE_UPLOAD_FILENAME_TOKEN_RE,
    _FILE_UPLOAD_NULL_OR_SEPARATOR_TRUNCATION_RE,
    _FILE_UPLOAD_TRUNCATION_RE,
    _file_upload_double_extension_scan_matches,
    _file_upload_is_double_extension,
    _file_upload_is_truncation,
    _file_upload_kind_matches,
    _file_upload_match_start,
    _file_upload_quoted_candidate,
    _file_upload_scan_matches,
    _file_upload_scan_window,
    _file_upload_skip_whitespace,
)
from guard_core.sync.handlers._suspatterns_file_upload import (
    _PATTERNS as _FILE_UPLOAD_PATTERNS,
)
from guard_core.sync.handlers._suspatterns_sources import (
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
    _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE,
)
from guard_core.sync.handlers._suspatterns_sources import _PATTERNS as _SOURCES_PATTERNS
from guard_core.sync.handlers._suspatterns_templates import (
    template_expression_matches,
    template_keyword_matches,
)

_ATTR_EQUALS_WHITESPACE_RE = r"\s{0,20}"
_HTML_TAG_OPEN_RE = r"<[A-Za-z/]"


_CMD_INJECTION_ASSIGNMENT_PREFIX_RE = re.compile(r"\n[^\S\r\n]*")


def _cmd_injection_shell_dash_c_finditer(
    text: str, compiled: re.Pattern
) -> Iterator[re.Match]:
    last_end = 0
    for prefix_match in _CMD_INJECTION_ASSIGNMENT_PREFIX_RE.finditer(text):
        start = prefix_match.start()
        if start < last_end:
            continue
        pos = prefix_match.end()
        while True:
            token_match = _PATTERNS["_CMD_INJECTION_ASSIGNMENT_TOKEN_RE"].match(
                text, pos
            )
            if token_match is None:
                break
            pos = token_match.end()
        match = compiled.match(text, start)
        if match is not None:
            yield match
            last_end = match.end()
        else:
            last_end = pos


def _ldap_null_byte_attr_name_start(text: str, equals_pos: int) -> int | None:
    i = equals_pos
    while i > 0 and _SOURCES_PATTERNS[
        "_LDAP_NULL_BYTE_ATTR_CONTINUATION_CHAR_RE"
    ].match(text, i - 1):
        i -= 1
    if i == equals_pos or not _SOURCES_PATTERNS[
        "_LDAP_NULL_BYTE_ATTR_LEAD_CHAR_RE"
    ].match(text, i):
        return None
    return i


def _ldap_null_byte_value_start(text: str, star_pos: int) -> int:
    i = star_pos
    while i > 0 and _SOURCES_PATTERNS["_LDAP_NULL_BYTE_VALUE_CHAR_RE"].match(
        text, i - 1
    ):
        i -= 1
    return i


def _ldap_null_byte_attr_finditer(
    text: str, compiled: re.Pattern, tail_re: re.Pattern
) -> Iterator[re.Match]:
    if "*" not in text or ")" not in text:
        return
    last_end = 0
    for tail_match in tail_re.finditer(text):
        star_pos = tail_match.start()
        if star_pos < last_end:
            continue
        value_start = _ldap_null_byte_value_start(text, star_pos)
        if value_start == 0 or text[value_start - 1] != "=":
            continue
        name_start = _ldap_null_byte_attr_name_start(text, value_start - 1)
        if name_start is None:
            continue
        match = compiled.match(text, name_start, tail_match.end())
        if match is not None:
            yield match
            last_end = match.end()


_QUOTE_SPLICE_QUOTE_RUN_RE = re.compile(r"['\"]+")


def _quote_splice_word_start(text: str, pos: int) -> int | None:
    i = pos
    while i > 0 and _PATTERNS["_QUOTE_SPLICE_WORD_CHAR_RE"].match(text, i - 1):
        i -= 1
    return i if i < pos else None


def _quote_splice_finditer(text: str, compiled: re.Pattern) -> Iterator[re.Match]:
    n = len(text)
    last_end = 0
    for quote_match in _QUOTE_SPLICE_QUOTE_RUN_RE.finditer(text):
        if quote_match.start() < last_end:
            continue
        if quote_match.end() >= n or not _PATTERNS["_QUOTE_SPLICE_WORD_CHAR_RE"].match(
            text, quote_match.end()
        ):
            continue
        word_start = _quote_splice_word_start(text, quote_match.start())
        if word_start is None:
            continue
        match = compiled.match(text, word_start)
        if match is not None:
            yield match
            last_end = match.end()
        else:
            last_end = quote_match.end()


_SQLI_LOAD_FILE_RE = r"(?i)(?:LOAD_FILE\s*\([^)]+\))"
_LOAD_FILE_SCAN_TERMINATOR_RE = re.compile(r"\)")


def _load_file_scan_matches(content: str, compiled: re.Pattern) -> list[re.Match]:
    return list(
        bounded_finditer(
            content,
            compiled,
            _PATTERNS["_LOAD_FILE_SCAN_PREFIX_RE"],
            _LOAD_FILE_SCAN_TERMINATOR_RE,
        )
    )


_CMD_INJECTION_DOLLAR_SUBSTITUTION_RE = r"(?:[;&|]\s*(?:\$\([^)]+\)|\$\{[^}]+\}))"
_CMD_INJECTION_DOLLAR_PAREN_TERMINATOR_RE = re.compile(r"\)")
_CMD_INJECTION_DOLLAR_BRACE_TERMINATOR_RE = re.compile(r"\}")


def _cmd_injection_dollar_scan_matches(
    content: str, compiled: re.Pattern
) -> list[re.Match]:
    paren_matches = list(
        bounded_finditer(
            content,
            compiled,
            _PATTERNS["_CMD_INJECTION_DOLLAR_PAREN_PREFIX_RE"],
            _CMD_INJECTION_DOLLAR_PAREN_TERMINATOR_RE,
        )
    )
    brace_matches = list(
        bounded_finditer(
            content,
            compiled,
            _PATTERNS["_CMD_INJECTION_DOLLAR_BRACE_PREFIX_RE"],
            _CMD_INJECTION_DOLLAR_BRACE_TERMINATOR_RE,
        )
    )
    return paren_matches + brace_matches


_TEMPLATE_CURLY_KEYWORD_RE = (
    r"\{\{\s*[^\}]+(?:system|exec|popen|eval|require|include)\s*\}\}"
)


def _template_curly_keyword_scan_matches(
    content: str, compiled: re.Pattern
) -> list[re.Match]:
    return template_keyword_matches(content, compiled, "{{", "}}")


_TEMPLATE_DOLLAR_BRACE_CALL_RE = (
    r"\$\{[^}]*(?:@[\w.]+@|\b\w+\s*\(|\d+\s*[*/%+\-]\s*\d+)[^}]*\}"
)


def _template_dollar_brace_scan_matches(
    content: str, compiled: re.Pattern
) -> list[re.Match]:
    return template_expression_matches(content, compiled, "dollar")


_TEMPLATE_CURLY_CALL_RE = (
    r"\{\{(?![^\}]*\d{4}-\d{1,2}-\d{1,2}(?!\d))"
    r"(?=[^\}]*(?:@[\w.]+@|\b\w+\(\s*\)"
    r"|['\"]?\d+['\"]?\s*[*/%+\-]\s*['\"]?\d+['\"]?))"
    r"[^\}]*\}\}"
)


def _template_curly_call_scan_matches(
    content: str, compiled: re.Pattern
) -> list[re.Match]:
    return template_expression_matches(content, compiled, "curly")


_TEMPLATE_PERCENT_KEYWORD_RE = (
    r"\{\%\s*[^\%]+(?:system|exec|popen|eval|require|include)\s*\%\}"
)


def _template_percent_keyword_scan_matches(
    content: str, compiled: re.Pattern
) -> list[re.Match]:
    return template_keyword_matches(content, compiled, "{%", "%}")


_TEMPLATE_ASP_KEYWORD_RE = (
    r"(?i)<%[=#]?[^%]*(?:system|exec|eval|`|Runtime|IO\.|File\.|Dir\."
    r"|\d+\s*[-+*/]\s*\d+)[^%]*%>"
)


def _template_asp_keyword_scan_matches(
    content: str, compiled: re.Pattern
) -> list[re.Match]:
    return template_expression_matches(content, compiled, "asp")


def _template_hash_brace_scan_matches(
    content: str, compiled: re.Pattern
) -> list[re.Match]:
    return template_expression_matches(content, compiled, "hash")


def _brace_expansion_is_dangerous_command(match: re.Match) -> bool:
    text = match.group()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return False
    for item in text[start + 1 : end].split(","):
        if _PATTERNS["_BRACE_EXPANSION_WORD_ITEM_RE"].match(item) and _PATTERNS[
            "_BRACE_EXPANSION_LETTER_RE"
        ].search(item):
            return True
    return False


_PICKLE_GLOBAL_NEWLINE_RE = re.compile(r"\n")
_PATTERNS = LazyPatterns(
    {
        "_CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE": (
            _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
            re.IGNORECASE,
        ),
        "_CMD_INJECTION_ASSIGNMENT_TOKEN_RE": (
            r"[^=\s;|&]+=[^\s;|&]+\s+",
            re.IGNORECASE,
        ),
        "_QUOTE_SPLICE_WORD_CHAR_RE": (r"\w", 0),
        "_LOAD_FILE_SCAN_PREFIX_RE": (r"LOAD_FILE\s*\(", re.IGNORECASE),
        "_CMD_INJECTION_DOLLAR_PAREN_PREFIX_RE": (r"[;&|]\s*\$\(", 0),
        "_CMD_INJECTION_DOLLAR_BRACE_PREFIX_RE": (r"[;&|]\s*\$\{", 0),
        "_TEMPLATE_CURLY_PREFIX_RE": (r"\{\{\s*", 0),
        "_TEMPLATE_CURLY_TERMINATOR_RE": (r"\}\}", 0),
        "_TEMPLATE_DOLLAR_BRACE_PREFIX_RE": (r"\$\{", 0),
        "_TEMPLATE_DOLLAR_BRACE_TERMINATOR_RE": (r"\}", 0),
        "_TEMPLATE_PERCENT_PREFIX_RE": (r"\{\%\s*", 0),
        "_TEMPLATE_PERCENT_TERMINATOR_RE": (r"\%\}", 0),
        "_TEMPLATE_ASP_PREFIX_RE": (r"<%[=#]?", 0),
        "_TEMPLATE_ASP_TERMINATOR_RE": (r"%>", 0),
        "_BRACE_EXPANSION_WORD_ITEM_RE": (r"\A[A-Za-z0-9_./~-]+\Z", 0),
        "_BRACE_EXPANSION_LETTER_RE": (r"[A-Za-z]", 0),
        "_DESERIALIZATION_PICKLE_GLOBAL_GENERIC_COMPILED_RE": (
            _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE,
            re.IGNORECASE,
        ),
        "_PICKLE_GLOBAL_IDENT_FULL_RE": (
            r"\A[A-Za-z_][A-Za-z0-9_]{0,100}\Z",
            re.IGNORECASE,
        ),
        "_PICKLE_GLOBAL_NON_MODULE_CHAR_RE": (r"[^A-Za-z0-9_.]", re.IGNORECASE),
        "_PICKLE_GLOBAL_IDENT_START_RE": (r"[A-Za-z_]", re.IGNORECASE),
    }
)
_lookup = module_attribute_lookup(_PATTERNS, _FILE_UPLOAD_PATTERNS, _SOURCES_PATTERNS)


def __getattr__(name: str) -> re.Pattern[str]:
    return _lookup(name)


_PICKLE_GLOBAL_IDENT_MAX_LEN = 101
_PICKLE_GLOBAL_DOTTED_SEGMENTS_MAX = 20


def _pickle_global_first_valid_marker(
    text: str, lower: str, upper: str, floor: int, ceiling: int
) -> int | None:
    start = floor
    while True:
        pos_lower = text.find(lower, start, ceiling)
        pos_upper = text.find(upper, start, ceiling) if upper != lower else -1
        candidates = [pos for pos in (pos_lower, pos_upper) if pos != -1]
        if not candidates:
            return None
        pos = min(candidates)
        if _PATTERNS["_PICKLE_GLOBAL_IDENT_START_RE"].match(text, pos + 1):
            return pos
        start = pos + 1


def _pickle_global_chain_start(text: str, nl1: int, floor: int) -> int | None:
    seg_end = nl1
    earliest = None
    for _ in range(_PICKLE_GLOBAL_DOTTED_SEGMENTS_MAX + 1):
        dot_pos = text.rfind(".", floor, seg_end)
        seg_start = dot_pos + 1 if dot_pos >= floor else floor
        seg_floor = max(seg_start, seg_end - _PICKLE_GLOBAL_IDENT_MAX_LEN - 1)
        c_pos = _pickle_global_first_valid_marker(text, "c", "C", seg_floor, seg_end)
        if c_pos is not None:
            earliest = c_pos
        if dot_pos < floor or not _PATTERNS["_PICKLE_GLOBAL_IDENT_FULL_RE"].fullmatch(
            text[seg_start:seg_end]
        ):
            break
        seg_end = dot_pos
    return earliest


def _pickle_global_run_start(
    non_module_positions: list[int], nl1: int, floor: int
) -> int:
    idx = bisect.bisect_left(non_module_positions, nl1)
    return max(floor, non_module_positions[idx - 1] + 1) if idx > 0 else floor


def _pickle_global_generic_finditer(
    text: str, compiled: re.Pattern
) -> Iterator[re.Match]:
    newline_positions = [m.start() for m in _PICKLE_GLOBAL_NEWLINE_RE.finditer(text)]
    if len(newline_positions) < 2:
        return
    non_module_positions = [
        m.start() for m in _PATTERNS["_PICKLE_GLOBAL_NON_MODULE_CHAR_RE"].finditer(text)
    ]

    last_end = 0
    for nl1, nl2 in zip(newline_positions, newline_positions[1:], strict=False):
        if nl1 < last_end:
            continue
        if not _PATTERNS["_PICKLE_GLOBAL_IDENT_FULL_RE"].match(text[nl1 + 1 : nl2]):
            continue
        run_start = _pickle_global_run_start(non_module_positions, nl1, last_end)
        start = _pickle_global_chain_start(text, nl1, run_start)
        if start is None:
            continue
        match = compiled.match(text, start)
        if match is not None:
            yield match
            last_end = match.end()


__all__ = [
    "_FILE_UPLOAD_DANGEROUS_EXTENSIONS",
    "_FILE_UPLOAD_DANGEROUS_EXT_ALTERNATION",
    "_FILE_UPLOAD_DOUBLE_EXT_EXTENSIONS",
    "_FILE_UPLOAD_DOUBLE_EXT_ALTERNATION",
    "_FILE_UPLOAD_BENIGN_TERMINAL_EXTENSIONS",
    "_FILE_UPLOAD_BENIGN_TERMINAL_ALTERNATION",
    "_FILE_UPLOAD_NULL_OR_SEPARATOR_TRUNCATION_RE",
    "_FILE_UPLOAD_ATTR_EQUALS_WHITESPACE_RE",
    "_FILE_UPLOAD_FILENAME_EQUALS_RE",
    "_FILE_UPLOAD_DOUBLE_EXTENSION_RE",
    "_FILE_UPLOAD_TRUNCATION_RE",
    "_FILE_UPLOAD_DECODED_TRUNCATION_RE",
    "_FILE_UPLOAD_DANGEROUS_EXTENSION_RE",
    "_file_upload_scan_window",
    "_FILE_UPLOAD_FILENAME_TOKEN_RE",
    "_file_upload_match_start",
    "_file_upload_skip_whitespace",
    "_file_upload_quoted_candidate",
    "_file_upload_is_double_extension",
    "_file_upload_is_truncation",
    "_file_upload_kind_matches",
    "_file_upload_scan_matches",
    "_file_upload_double_extension_scan_matches",
]
