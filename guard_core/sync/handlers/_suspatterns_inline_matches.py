import re
from collections.abc import Callable, Iterable

from guard_core.sync._utils.detection_scan import _built_once_uncharged
from guard_core.sync.handlers._suspatterns_lazy_rows import (
    _BUILTIN_PATTERN_COMPILE_FLAGS,
    COMPILED_BUILTIN_PATTERNS,
    PatternSource,
    _SourceRow,
)
from guard_core.sync.handlers._suspatterns_linear_path import (
    _LinearPathRow,
    _row_for,
    linear_path_finder,
)
from guard_core.sync.handlers._suspatterns_scan_windows import (
    _SCAN_WINDOW_PATTERNS,
    _iter_scan_window_matches,
)
from guard_core.sync.handlers._suspatterns_shell_sources import (
    _PATTERN_SCAN_WINDOW_MATCHERS,
)
from guard_core.sync.handlers._suspatterns_windowed_finders import (
    _WINDOWED_PATTERN_FINDERS,
)

_Matcher = Callable[[str, re.Pattern], Iterable[re.Match]]
_Finder = Callable[[str], Iterable[re.Match]]


class _InlineFinder:
    __slots__ = ("finder", "flags", "matcher")

    def __init__(
        self,
        flags: int | None,
        matcher: _Matcher | None,
        finder: _Finder | None,
    ) -> None:
        self.flags = flags
        self.matcher = matcher
        self.finder = finder

    def __call__(self, content: str, pattern: re.Pattern) -> Iterable[re.Match] | None:
        if self.matcher is not None:
            return self.matcher(content, pattern)
        if self.finder is not None and self.flags == pattern.flags:
            return self.finder(content)
        return None


def _scan_window_finder(
    bounds: tuple[tuple[re.Pattern, re.Pattern], ...],
) -> _InlineFinder:
    return _InlineFinder(
        None,
        lambda content, pattern: _iter_scan_window_matches(content, pattern, bounds),
        None,
    )


class _InlineFinders(dict[str, _InlineFinder | None]):
    def __init__(self) -> None:
        super().__init__(
            {
                **{
                    source: _scan_window_finder(bounds)
                    for source, bounds in _SCAN_WINDOW_PATTERNS.items()
                },
                **{
                    source: _InlineFinder(None, matcher, None)
                    for source, matcher in _PATTERN_SCAN_WINDOW_MATCHERS.items()
                },
            }
        )

    def __missing__(self, source: str) -> _InlineFinder | None:
        builtin = COMPILED_BUILTIN_PATTERNS.get(source)
        if builtin is None:
            return None
        finder = _built_once_uncharged(lambda: linear_path_finder(builtin))
        entry = None if finder is None else _InlineFinder(builtin.flags, None, finder)
        self[source] = entry
        return entry


_INLINE_FINDERS = _InlineFinders()


_BUILTIN_ROW_FLAGS = re.compile("", _BUILTIN_PATTERN_COMPILE_FLAGS).flags


class _LinearRows(dict[str, _LinearPathRow | None]):
    def __missing__(self, source: str) -> _LinearPathRow | None:
        row = _built_once_uncharged(lambda: _row_for(source, _BUILTIN_ROW_FLAGS))
        self[source] = row
        return row


_LINEAR_ROWS = _LinearRows()


def linear_row_finds_nothing(source: str, content: str) -> bool:
    """True when a builtin linear path row has no match, found without compiling it."""
    if source in _WINDOWED_PATTERN_FINDERS:
        return False
    row = _LINEAR_ROWS[source]
    return row is not None and next(row.find(content), None) is None


def compiled_unless_known_clean(
    pattern: PatternSource, content: str
) -> re.Pattern | None:
    """The compiled row, or None for a builtin linear row with no match."""
    if not isinstance(pattern, _SourceRow):
        return pattern
    if linear_row_finds_nothing(pattern.pattern, content):
        return None
    return COMPILED_BUILTIN_PATTERNS[pattern.pattern]
