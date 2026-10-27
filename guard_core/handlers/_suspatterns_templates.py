import re
from collections.abc import Iterator
from functools import lru_cache

_KEYWORD_INDICATOR = r"(?:system|exec|popen|eval|require|include)\s*\Z"
_DOLLAR_INDICATOR = r"@[\w.]+@|\b\w+\s*\(|(?<!\d)\d+\s*[*/%+\-]\s*\d+"
_CURLY_INDICATOR = (
    r"@[\w.]+@|\b\w+\(\s*\)"
    r"|(?<!\d)['\"]?\d+['\"]?\s*[*/%+\-]\s*['\"]?\d+['\"]?"
)
_HASH_INDICATOR = (
    r"@[\w.]+@|\b\w+\s*\("
    r"|(?<!\d)['\"]?\d+['\"]?\s*[*/%+\-]\s*['\"]?\d+['\"]?"
)
_ASP_INDICATOR = (
    r"system|exec|eval|`|Runtime|IO\.|File\.|Dir\."
    r"|(?<!\d)\d+\s*[-+*/]\s*\d+"
)
_DATE_INDICATOR = r"(?=\d{4}-\d{1,2}-\d{1,2}(?!\d))"


@lru_cache(maxsize=32)
def _template_regex(source: str, flags: int) -> re.Pattern:
    return re.compile(source, flags)


def _template_regions(
    content: str, opening: str, closing: str
) -> Iterator[tuple[int, int, int]]:
    cursor = 0
    while (start := content.find(opening, cursor)) != -1:
        body_start = start + len(opening)
        barrier = content.find(closing[0], body_start)
        if barrier == -1:
            return
        cursor = max(body_start, barrier - len(opening) + 1)
        if content.startswith(closing, barrier):
            yield start, barrier, barrier + len(closing)


def _template_frame(
    content: str, opening: str, closing: str, start: int, end: int, flags: int
) -> re.Match:
    source = re.escape(opening) + "[^" + re.escape(closing[0]) + "]*"
    source += re.escape(closing)
    match = _template_regex(source, flags).match(content, start, end)
    if match is None:
        raise RuntimeError("the template frame did not match its own region")
    return match


def template_keyword_matches(
    content: str, compiled: re.Pattern, opening: str, closing: str
) -> list[re.Match]:
    indicator = _template_regex(_KEYWORD_INDICATOR, compiled.flags)
    matches = []
    for start, barrier, end in _template_regions(content, opening, closing):
        if indicator.search(content, start + len(opening) + 1, barrier):
            matches.append(
                _template_frame(content, opening, closing, start, end, compiled.flags)
            )
    return matches


def _template_after_dates(
    content: str, opening: str, start: int, barrier: int, flags: int
) -> int:
    last_date = -1
    for match in _template_regex(_DATE_INDICATOR, flags).finditer(
        content, start + 2, barrier
    ):
        last_date = match.start()
    if last_date != -1:
        return content.find(opening, last_date + 1, barrier)
    return start


def template_expression_matches(
    content: str, compiled: re.Pattern, kind: str
) -> list[re.Match]:
    opening, closing, source = {
        "dollar": ("${", "}", _DOLLAR_INDICATOR),
        "curly": ("{{", "}}", _CURLY_INDICATOR),
        "hash": ("#{", "}", _HASH_INDICATOR),
        "asp": ("<%", "%>", _ASP_INDICATOR),
    }[kind]
    indicator = _template_regex(source, compiled.flags)
    matches = []
    last_end = 0
    for start, barrier, end in _template_regions(content, opening, closing):
        if start < last_end:
            continue
        if kind in {"curly", "hash"}:
            start = _template_after_dates(
                content, opening, start, barrier, compiled.flags
            )
        if start != -1 and indicator.search(content, start + len(opening), barrier):
            matches.append(
                _template_frame(content, opening, closing, start, end, compiled.flags)
            )
            last_end = end
    return matches
