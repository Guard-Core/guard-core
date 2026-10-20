import re
from functools import lru_cache

from guard_core.sync._utils.detection_scan import _whole_value_rows_only

_ANCHOR_RE = re.compile(r"\\A|\\Z|(?<![\[\\])\^|(?<!\\)\$(?![{)\]])")


@lru_cache(maxsize=4096)
def _row_is_anchored(source: str) -> bool:
    return _ANCHOR_RE.search(source) is not None


def row_needs_the_whole_value(source: str, context_sensitive: frozenset[str]) -> bool:
    return source in context_sensitive or _row_is_anchored(source)


def rows_for_a_whole_value_pass(
    rows: list[tuple[re.Pattern, frozenset[str], str]],
    context_sensitive: frozenset[str],
) -> list[tuple[re.Pattern, frozenset[str], str]]:
    if not _whole_value_rows_only.get():
        return rows
    return [
        row
        for row in rows
        if row_needs_the_whole_value(row[0].pattern, context_sensitive)
    ]
