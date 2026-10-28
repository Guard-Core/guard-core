import re
from collections.abc import Callable, Iterable

from guard_core.sync._utils.detection_scan import _built_once_uncharged
from guard_core.sync.handlers._suspatterns_lazy_rows import COMPILED_BUILTIN_PATTERNS
from guard_core.sync.handlers._suspatterns_linear_path import linear_path_finder
from guard_core.sync.handlers._suspatterns_scan_windows import (
    _SCAN_WINDOW_PATTERNS,
    _iter_scan_window_matches,
)
from guard_core.sync.handlers._suspatterns_shell_sources import (
    _PATTERN_SCAN_WINDOW_MATCHERS,
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
