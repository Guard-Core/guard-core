import re
from collections.abc import Iterable

from guard_core.sync.handlers._suspatterns_lazy_rows import COMPILED_BUILTIN_PATTERNS
from guard_core.sync.handlers._suspatterns_linear_path import linear_path_finder
from guard_core.sync.handlers._suspatterns_shell_sources import (
    _PATTERN_SCAN_WINDOW_MATCHERS,
)


def inline_scan_matches(pattern: re.Pattern, content: str) -> Iterable[re.Match] | None:
    scan_window_matcher = _PATTERN_SCAN_WINDOW_MATCHERS.get(pattern.pattern)
    if scan_window_matcher is not None:
        return scan_window_matcher(content, pattern)
    if COMPILED_BUILTIN_PATTERNS.get(pattern.pattern) is not pattern:
        return None
    linear_finder = linear_path_finder(pattern)
    return None if linear_finder is None else linear_finder(content)
