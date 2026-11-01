import re
from array import array
from collections.abc import Callable, Iterator
from functools import lru_cache

from guard_core.detection_engine.cache_stats import CacheStats, build_cache_stats
from guard_core.handlers._suspatterns_linear_path_source import (
    FLAT_CHAIN_CLASS,
    OPTIONAL_SEPARATOR,
    PATH_SEPARATORS,
    SEGMENT_STEP_RE,
    SEPARATOR,
    flattened,
    mandatory_characters,
    row_pieces,
    without_unbalanced_parentheses,
)

_MAX_BUILT_PATTERNS = 128
_UNSET = -2
_NO_END = -1
_STEP = SEGMENT_STEP_RE.match


class _LinearPathRow:
    def __init__(
        self, flags: int, pieces: list[str], guards: list[str | None], source: str
    ) -> None:
        self._flags = flags
        self._source = source
        self._raw_pieces = [flattened(piece) for piece in pieces]
        self._separator_optional = without_unbalanced_parentheses(pieces[0]).endswith(
            "?"
        )
        self._guards = [
            None if guard is None else re.compile(f"(?:{guard})", flags)
            for guard in guards
        ]
        self._tests = [
            re.compile(without_unbalanced_parentheses(piece), flags)
            for piece in self._raw_pieces[1:]
        ]
        self._mandatory = mandatory_characters(self._raw_pieces[-1], flags)
        self._built = lru_cache(maxsize=_MAX_BUILT_PATTERNS)(self._build)

    def _build(self, leading: int, counts: tuple[int, ...]) -> re.Pattern:
        needle = OPTIONAL_SEPARATOR if self._separator_optional else SEPARATOR
        parts = [self._raw_pieces[0].replace(needle, f"[/\\\\]{{{leading}}}", 1)]
        for count, piece in zip(counts, self._raw_pieces[1:], strict=True):
            parts.extend((f"{FLAT_CHAIN_CLASS}{{{count}}}", piece))
        return re.compile("".join(parts), self._flags)

    def _walk(
        self, text: str, chain: int, start: int, memo: array | None
    ) -> tuple[array, int]:
        guard = self._guards[chain]
        guard_match = None if guard is None else guard.match
        path = array("i")
        position = start
        while position != -1:
            if memo is not None and memo[position] != _UNSET:
                return path, memo[position]
            path.append(position)
            blocked = guard_match is not None and guard_match(text, position)
            step = None if blocked else _STEP(text, position)
            position = -1 if step is None else step.end()
        return path, _NO_END

    def _best_end(
        self, text: str, chain: int, start: int, memos: list[array | None]
    ) -> int:
        memo = memos[chain]
        if memo is None and chain:
            memo = memos[chain] = array("i", [_UNSET]) * (len(text) + 2)
        path, best = self._walk(text, chain, start, memo)
        tail_test = self._tests[chain].match
        final_chain = chain + 1 == len(self._guards)
        for position in reversed(path):
            if best == _NO_END and (tail := tail_test(text, position)) is not None:
                if final_chain or (
                    self._best_end(text, chain + 1, tail.end(), memos) != _NO_END
                ):
                    best = position
            if memo is not None:
                memo[position] = best
        return best

    def _solve(self, text: str, start: int) -> list[int] | None:
        if not all(any(map(text.__contains__, cases)) for cases in self._mandatory):
            return None
        memos: list[array | None] = [None] * len(self._guards)
        counts: list[int] = []
        position = start
        for chain in range(len(self._guards)):
            end = self._best_end(text, chain, position, memos)
            if end == _NO_END:
                return None
            counts.append(end - position)
            tail = self._tests[chain].match(text, end)
            position = end if tail is None else tail.end()
        return counts

    def _starts(self, text: str) -> tuple[int, ...]:
        if text.startswith(tuple(PATH_SEPARATORS)):
            return (1, 0) if self._separator_optional else (1,)
        return (0,) if self._separator_optional else ()

    def find(self, text: str) -> Iterator[re.Match]:
        for start in self._starts(text):
            counts = self._solve(text, start)
            if counts is not None:
                match = self._built(start, tuple(counts)).match(text)
                if match is not None:
                    yield match
                else:
                    yield from re.compile(self._source, self._flags).finditer(text)
                return


@lru_cache(maxsize=512)
def _row_for(source: str, flags: int) -> _LinearPathRow | None:
    split = row_pieces(source)
    return None if split is None else _LinearPathRow(flags, *split, source)


@lru_cache(maxsize=512)
def _flat_equivalent_for(source: str, flags: int) -> re.Pattern | None:
    flat = flattened(source)
    return None if flat == source else re.compile(flat, flags)


def linear_path_finder(
    pattern: re.Pattern,
) -> Callable[[str], Iterator[re.Match]] | None:
    row = _row_for(pattern.pattern, pattern.flags)
    if row is not None:
        return row.find
    flat = _flat_equivalent_for(pattern.pattern, pattern.flags)
    return None if flat is None else flat.finditer


def linear_path_cache_stats() -> CacheStats:
    rows, flat = _row_for.cache_info(), _flat_equivalent_for.cache_info()
    return build_cache_stats(
        rows.hits + flat.hits,
        rows.misses + flat.misses,
        0,
        rows.currsize + flat.currsize,
        (rows.maxsize or 0) + (flat.maxsize or 0),
    )
