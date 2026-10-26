"""Bound the regex scan window a caller's pattern runs on.

Several built-in detection patterns have the shape
``literal_prefix + unbounded_negated_class + terminator``. When the
terminator is absent, the underlying regex engine rescans to end-of-input
from every prefix occurrence, which is quadratic in input length. This
module locates every prefix and terminator occurrence with two linear
``finditer`` passes, then runs the caller's UNMODIFIED, uncapped pattern
against a bounded span per prefix candidate: from that candidate to the
rightmost terminator occurrence reachable from it. The pattern itself is
never rewritten, so neither an unbounded quantifier (CVE-2025-53539) nor a
``{0,N}`` length cap (GHSA-rrf6-pxg8-684g) is reintroduced.

A prefix candidate is tried once, against the farthest reachable
terminator. If that single attempt fails, no smaller window could have
succeeded either, so the candidate is abandoned and the next one is tried.

Outcome (a match found or not) is guaranteed to agree with running
``compiled`` unbounded. The exact span returned MAY differ from the
unbounded match in texts with multiple candidate prefixes, because a
different, still-valid starting prefix can be chosen. This is acceptable
only as long as no caller inspects the returned span instead of its mere
presence; a caller that starts consuming spans must first confirm this
module still guarantees span identity for its patterns.
"""

import bisect
import re
from array import array
from collections import deque
from collections.abc import Iterator, Sequence


def bounded_finditer(
    text: str,
    compiled: re.Pattern,
    prefix: re.Pattern,
    terminator: re.Pattern,
) -> Iterator[re.Match]:
    last_terminator = deque(terminator.finditer(text), maxlen=1)
    if not last_terminator:
        return
    ceiling = last_terminator[0].end()

    prefix_starts = array("i", (m.start() for m in prefix.finditer(text)))
    if not prefix_starts:
        return

    search_from = 0
    while True:
        start_idx = bisect.bisect_left(prefix_starts, search_from)
        match = _match_from_live_prefixes(
            text, compiled, prefix_starts, start_idx, ceiling
        )
        if match is None:
            return
        yield match
        search_from = match.end() if match.end() > match.start() else match.start() + 1


def _match_from_live_prefixes(
    text: str,
    compiled: re.Pattern,
    prefix_starts: Sequence[int],
    start_idx: int,
    ceiling: int,
) -> re.Match | None:
    for i in range(start_idx, len(prefix_starts)):
        start = prefix_starts[i]
        if start >= ceiling:
            break
        match = compiled.match(text, start, ceiling)
        if match is not None:
            return match
    return None


def bounded_search(
    text: str,
    compiled: re.Pattern,
    prefix: re.Pattern,
    terminator: re.Pattern,
) -> re.Match | None:
    return next(bounded_finditer(text, compiled, prefix, terminator), None)
