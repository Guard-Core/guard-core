import re as re
from functools import lru_cache

from guard_core._lazy_patterns import LazyPatterns, module_attribute_lookup
from guard_core.sync._utils.detection_scan import (
    _whole_value_path_rows_skipped,
    _whole_value_rows_only,
)
from guard_core.sync.handlers._suspatterns_lazy_rows import PatternRow

_PATTERNS = LazyPatterns(
    {
        "_ANCHOR_RE": (r"\\A|\\Z|(?<![\[\\])\^|(?<!\\)\$(?![{)\]])", 0),
    }
)
__getattr__ = module_attribute_lookup(_PATTERNS)


@lru_cache(maxsize=4096)
def _row_is_anchored(source: str) -> bool:
    return _PATTERNS["_ANCHOR_RE"].search(source) is not None


_WHOLE_VALUE_PATH_ROW_PREFIXES = ("\\A[/\\\\]", "\\A\\s*(?:/")


def row_is_a_whole_value_path(source: str) -> bool:
    return source.startswith(_WHOLE_VALUE_PATH_ROW_PREFIXES)


def row_needs_the_whole_value(source: str, context_sensitive: frozenset[str]) -> bool:
    return source in context_sensitive or _row_is_anchored(source)


def rows_for_a_whole_value_pass(
    rows: list[PatternRow],
    context_sensitive: frozenset[str],
) -> list[PatternRow]:
    if _whole_value_path_rows_skipped.get():
        return [row for row in rows if not row_is_a_whole_value_path(row[0].pattern)]
    if not _whole_value_rows_only.get():
        return rows
    return [
        row
        for row in rows
        if row_needs_the_whole_value(row[0].pattern, context_sensitive)
    ]
