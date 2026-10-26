import bisect
import random
import re
import tracemalloc
from collections.abc import Iterator

import pytest

from guard_core.detection_engine.scan_window import bounded_finditer
from guard_core.handlers._suspatterns_scan_windows import _SCAN_WINDOW_PATTERNS

_MEMORY_SLACK_BYTES = 5 * 1024 * 1024
_SIZE = 262144
_TOKENS = [
    "..;",
    "..",
    ";",
    "/",
    "\\",
    "a",
    "<!DOCTYPE",
    "<!ENTITY",
    ">",
    "[",
    "]]>",
    "x",
    " ",
]


def _listing_finditer(
    text: str, compiled: re.Pattern, prefix: re.Pattern, terminator: re.Pattern
) -> Iterator[re.Match]:
    terminator_ends = [m.end() for m in terminator.finditer(text)]
    if not terminator_ends:
        return
    ceiling = terminator_ends[-1]
    prefix_starts = [m.start() for m in prefix.finditer(text)]
    if not prefix_starts:
        return
    search_from = 0
    while True:
        index = bisect.bisect_left(prefix_starts, search_from)
        match = None
        for start in prefix_starts[index:]:
            if start >= ceiling:
                break
            match = compiled.match(text, start, ceiling)
            if match is not None:
                break
        if match is None:
            return
        yield match
        search_from = match.end() if match.end() > match.start() else match.start() + 1


def _spans(matches: Iterator[re.Match]) -> list[tuple[int, int]]:
    return [match.span() for match in matches]


def test_the_bounded_finditer_yields_the_spans_of_the_listing_version() -> None:
    rng = random.Random(1392)
    hits = 0
    for source, bounds in _SCAN_WINDOW_PATTERNS.items():
        compiled = re.compile(source, re.IGNORECASE)
        for prefix, terminator in bounds:
            for _ in range(400):
                text = "".join(rng.choice(_TOKENS) for _ in range(rng.randint(0, 30)))
                expected = _spans(_listing_finditer(text, compiled, prefix, terminator))
                assert (
                    _spans(bounded_finditer(text, compiled, prefix, terminator))
                    == expected
                )
                hits += bool(expected)
    assert hits > 50


@pytest.mark.parametrize("unit", ["/", "\\", "a/", "..;/", ";/"])
def test_a_256_kb_value_costs_the_semicolon_window_at_most_5_mb(unit: str) -> None:
    source = r"\.\.;[^/\\]*[/\\]"
    ((prefix, terminator),) = _SCAN_WINDOW_PATTERNS[source]
    compiled = re.compile(source, re.IGNORECASE)
    content = (unit * (_SIZE // len(unit) + 1))[:_SIZE]
    tracemalloc.start()
    try:
        sum(1 for _ in bounded_finditer(content, compiled, prefix, terminator))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak <= _MEMORY_SLACK_BYTES
