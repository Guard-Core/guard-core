import re

from guard_core._lazy_patterns import LazyPatterns, module_attribute_lookup
from guard_core.handlers._suspatterns_shell_sources import (
    _AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS,
    _BACKTICK_WINDOW_DELIMITER_CHARS,
    _GLOB_WILDCARD_CHAR_RE,
    _SHELL_SPECIAL_PARAMETER_NAMES,
)
from guard_core.handlers._suspatterns_shell_sources import (
    _PATTERNS as _SHELL_SOURCES_PATTERNS,
)


def _backtick_token_has_chained_shell_operators(token: str) -> bool:
    return len(_SHELL_SOURCES_PATTERNS["_SHELL_CHAIN_OPERATOR_RE"].findall(token)) >= 2


def _backtick_pair_glued(content: str, start: int, end: int) -> bool:
    prefix_glued = start > 0 and bool(
        _SHELL_SOURCES_PATTERNS["_GLUED_BACKTICK_ASCII_WORD_RE"].match(
            content[start - 1]
        )
    )
    suffix_glued = end < len(content) and bool(
        _SHELL_SOURCES_PATTERNS["_GLUED_BACKTICK_ASCII_WORD_RE"].match(content[end])
    )
    return prefix_glued or suffix_glued


_BACKTICK_CLAUSE_BOUNDARY_CHARS = ".!?;&|"


def _backtick_pair_tail_anchored(content: str, end: int) -> bool:
    return content[end:].strip() == ""


def _backtick_pair_clause_initial(content: str, start: int) -> bool:
    if start == 0:
        return False
    if content[start - 1] not in " \t\r\n":
        return False
    prefix = content[:start].rstrip()
    if not prefix:
        return False
    return prefix[-1] in _BACKTICK_CLAUSE_BOUNDARY_CHARS


def _backtick_pair_appended_clause(content: str, start: int, end: int) -> bool:
    return _backtick_pair_tail_anchored(content, end) and _backtick_pair_clause_initial(
        content, start
    )


def _backtick_window_start(content: str, position: int) -> int:
    index = position
    while index > 0 and content[index - 1] not in _BACKTICK_WINDOW_DELIMITER_CHARS:
        index -= 1
    return index


def _backtick_window_end(content: str, position: int) -> int:
    delimiter = _SHELL_SOURCES_PATTERNS["_BACKTICK_WINDOW_DELIMITER_RE"].search(
        content, position
    )
    return delimiter.start() if delimiter else len(content)


def _backtick_pair_context_window(content: str, start: int, end: int) -> str:
    window_start = _backtick_window_start(content, start)
    window_end = _backtick_window_end(content, end)
    return content[window_start:window_end]


def _backtick_token_is_implausible_sql_identifier(token: str) -> bool:
    return bool(
        _SHELL_SOURCES_PATTERNS["_IMPLAUSIBLE_SQL_IDENTIFIER_CHARS_RE"].search(token)
    )


_STRONG_SQL_KEYWORD_LONGEST_SINGLE_WORD = 6
_STRONG_SQL_KEYWORD_TWO_WORD_FIRST_LENGTH = 5
_LINE_BREAK_CHARS = "\r\n"


def _strong_sql_keyword_search_floor(content: str, start: int) -> int:
    floor = start - _STRONG_SQL_KEYWORD_LONGEST_SINGLE_WORD
    if _PATTERNS["_STRONG_SQL_KEYWORD_SECOND_WORD_RE"].search(
        content, start - 2, start
    ):
        gap_start = start - 2
        while (
            gap_start > 0
            and content[gap_start - 1].isspace()
            and content[gap_start - 1] not in _LINE_BREAK_CHARS
        ):
            gap_start -= 1
        floor = min(floor, gap_start - _STRONG_SQL_KEYWORD_TWO_WORD_FIRST_LENGTH)
    return max(floor, 0)


def _strong_sql_keyword_glued_to_pair(content: str, start: int, end: int) -> bool:
    floor = _strong_sql_keyword_search_floor(content, start)
    if _SHELL_SOURCES_PATTERNS["_STRONG_SQL_KEYWORD_GLUED_PREFIX_RE"].search(
        content, floor, start
    ):
        return True
    return bool(
        _SHELL_SOURCES_PATTERNS["_STRONG_SQL_KEYWORD_GLUED_SUFFIX_RE"].match(
            content, end
        )
    )


def _glued_backtick_pair_is_injection(match: re.Match, context: str) -> bool:
    content = match.string
    start, end = match.start(), match.end()
    token = content[start + 1 : end - 1]
    if not _PATTERNS["_SHELL_TEXT_PRINTABLE_ASCII_RE"].match(token):
        return False
    if _backtick_token_has_chained_shell_operators(token):
        return True
    appended_clause = _backtick_pair_appended_clause(content, start, end)
    if not _backtick_pair_glued(content, start, end) and not appended_clause:
        return False
    if _backtick_token_is_implausible_sql_identifier(token):
        return True
    window = _backtick_pair_context_window(content, start, end)
    if _PATTERNS["_SHELL_METACHARACTER_WINDOW_RE"].search(window):
        return True
    if _strong_sql_keyword_glued_to_pair(content, start, end):
        return False
    normalized = context.split(":", 1)[0]
    return (
        normalized in _AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS or appended_clause
    ) and _shell_token_is_command_with_arguments_or_known(token)


def _whole_value_backtick_pairs_are_injection(match: re.Match, _context: str) -> bool:
    return any(
        _shell_token_is_command_with_arguments_or_known(token)
        or _backtick_token_has_chained_shell_operators(token)
        for token in re.findall(r"`([^`]*)`", match.group())
    )


def shell_dash_c_argument_is_dangerous(content: str, end: int) -> bool:
    rest = content[end:].lstrip()
    quote = rest[:1] if rest[:1] in ("'", '"') else ""
    if quote:
        closing = rest.find(quote, 1)
        argument = rest[1:] if closing < 0 else rest[1:closing]
    else:
        argument = rest.partition(" ")[0]
    argument = _PATTERNS["_SHELL_DASH_C_ENV_ASSIGNMENT_RE"].sub("", argument.strip())
    if _PATTERNS["_SHELL_DASH_C_COMPOUND_RE"].search(argument):
        return True
    return bool(_PATTERNS["_SHELL_DASH_C_DANGEROUS_COMMAND_RE"].match(argument))


def _shell_token_is_command_with_arguments_or_known(token: str) -> bool:
    if _SHELL_SOURCES_PATTERNS["_SHELL_SELECTOR_STRING_RE"].match(token.strip()):
        return False
    words = token.split()
    if len(words) > 1:
        return True
    if not words:
        return False
    if _SHELL_SOURCES_PATTERNS["_SHELL_PLAIN_IDENTIFIER_RE"].match(words[0]) is None:
        return True
    return (
        _SHELL_SOURCES_PATTERNS["_SHELL_KNOWN_COMMAND_RE"].match(words[0]) is not None
    )


def _dollar_substitution_token_is_implausible(token: str, delimiter: str) -> bool:
    stripped = token.strip()
    if delimiter == "{":
        leading = re.match(r"[A-Za-z_]\w*", stripped)
        return bool(
            (leading and leading.group().lower() in _SHELL_SPECIAL_PARAMETER_NAMES)
            or _SHELL_SOURCES_PATTERNS["_SHELL_BRACE_SLICE_RE"].match(stripped)
            or stripped == "@"
        )
    return bool(
        _SHELL_SOURCES_PATTERNS["_IMPLAUSIBLE_DOLLAR_PAREN_TOKEN_CHARS_RE"].search(
            token
        )
    )


def _dollar_substitution_pair_backtick_quoted(
    content: str, start: int, end: int
) -> bool:
    prefix_quoted = start > 0 and content[start - 1] == "`"
    suffix_quoted = end < len(content) and content[end] == "`"
    return prefix_quoted or suffix_quoted


def _dollar_substitution_pair_is_injection(match: re.Match, context: str) -> bool:
    content = match.string
    start, end = match.start(), match.end()
    if _dollar_substitution_pair_backtick_quoted(content, start, end):
        return False
    delimiter = content[start + 1]
    token = content[start + 2 : end - 1]
    if _dollar_substitution_token_is_implausible(token, delimiter):
        return True
    if _strong_sql_keyword_glued_to_pair(content, start, end):
        return False
    return (
        delimiter == "("
        and context.split(":", 1)[0] in _AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS
        and _shell_token_is_command_with_arguments_or_known(token)
    )


def _quote_splice_token_is_dangerous_command(match: re.Match) -> bool:
    run = 0
    for fragment in re.split(r"['\"]+", match.group()):
        run = run + 1 if len(fragment) == 1 else 0
        if run >= 3:
            return True
    return False


_PATTERNS = LazyPatterns(
    {
        "_SHELL_METACHARACTER_WINDOW_RE": (
            r"(?:;|\|\||\||&&)\s*(?:`|[A-Za-z_][\w-]*|[~./][\w./-]*|-[\w-]*)|\$\(|\$\{",
            0,
        ),
        "_SHELL_TEXT_PRINTABLE_ASCII_RE": (r"\A[\t\x20-\x7e]*\Z", 0),
        "_STRONG_SQL_KEYWORD_SECOND_WORD_RE": (r"(?i)BY\Z", 0),
        "_SHELL_DASH_C_DANGEROUS_COMMAND_RE": (
            r"(?:ls|cat|rm|id|whoami|uname|wget|curl|nc|netcat|socat|bash|sh|python|perl)\b",
            0,
        ),
        "_SHELL_DASH_C_COMPOUND_RE": (r"[;|&`]|\$\(", 0),
        "_SHELL_DASH_C_ENV_ASSIGNMENT_RE": (r"\A(?:\w+=\S*\s+)+", 0),
        "_GLOB_WILDCARD_COMMAND_BOUNDARY_PREFIX_RE": (
            r"(?:;|\|\||\||&&|\$\(|`)\s*\Z",
            0,
        ),
    }
)
__getattr__ = module_attribute_lookup(_PATTERNS, _SHELL_SOURCES_PATTERNS)


_GLOB_WILDCARD_COMMAND_BOUNDARY_ENDINGS = (";", "|", "`", "&&", "$(")
_GLOB_WILDCARD_VALUE_START_CONTEXTS = frozenset({"request_body"})
_GLOB_WILDCARD_LETTER_RE = re.compile(r"[A-Za-z]")
_GLOB_WILDCARD_COMMAND_SUFFIX_CHARS = " \t\r\n;|&"


def _glob_wildcard_token_is_word_shaped(token: str) -> bool:
    for wildcard in _GLOB_WILDCARD_CHAR_RE.finditer(token):
        index = wildcard.start()
        left = 0
        position = index - 1
        while position >= 0 and _GLOB_WILDCARD_LETTER_RE.match(token, position):
            left += 1
            position -= 1
        right = 0
        position = index + 1
        while position < len(token) and _GLOB_WILDCARD_LETTER_RE.match(token, position):
            right += 1
            position += 1
        if left + right >= 2:
            return True
    return False


def _glob_wildcard_token_is_dangerous_command(
    match: re.Match, context: str = "unknown"
) -> bool:
    if not _glob_wildcard_token_is_word_shaped(match.group()):
        return False
    suffix = match.string[match.end() : match.end() + 1]
    if suffix and suffix not in _GLOB_WILDCARD_COMMAND_SUFFIX_CHARS:
        return False
    content = match.string
    value_start = match.start()
    while value_start > 0 and content[value_start - 1].isspace():
        value_start -= 1
    if content.endswith(_GLOB_WILDCARD_COMMAND_BOUNDARY_ENDINGS, 0, value_start):
        return True
    if context in _GLOB_WILDCARD_VALUE_START_CONTEXTS:
        return value_start == 0
    return False
