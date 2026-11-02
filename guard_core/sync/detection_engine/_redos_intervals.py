from __future__ import annotations

import re
from collections.abc import Callable, Hashable, Iterable

MIN_CODE_POINT = 0
MAX_CODE_POINT = 0x10FFFF


def _normalize(intervals: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    ordered = sorted(intervals)
    if not ordered:
        return ()
    merged: list[list[int]] = [list(ordered[0])]
    for low, high in ordered[1:]:
        last = merged[-1]
        if low <= last[1] + 1:
            if high > last[1]:
                last[1] = high
        else:
            merged.append([low, high])
    return tuple((low, high) for low, high in merged)


class _IntervalSet:
    __slots__ = ("_intervals",)

    def __init__(self, intervals: Iterable[tuple[int, int]] = ()) -> None:
        self._intervals = _normalize(intervals)

    @classmethod
    def _from_normalized(cls, intervals: tuple[tuple[int, int], ...]) -> _IntervalSet:
        instance = cls.__new__(cls)
        instance._intervals = intervals
        return instance

    @classmethod
    def empty(cls) -> _IntervalSet:
        return cls._from_normalized(())

    @classmethod
    def full(cls) -> _IntervalSet:
        return cls._from_normalized(((MIN_CODE_POINT, MAX_CODE_POINT),))

    @classmethod
    def single(cls, code_point: int) -> _IntervalSet:
        return cls._from_normalized(((code_point, code_point),))

    @classmethod
    def from_range(cls, low: int, high: int) -> _IntervalSet:
        low = max(MIN_CODE_POINT, low)
        high = min(MAX_CODE_POINT, high)
        if low > high:
            return cls.empty()
        return cls._from_normalized(((low, high),))

    def is_empty(self) -> bool:
        return not self._intervals

    def contains(self, code_point: int) -> bool:
        intervals = self._intervals
        low_bound, high_bound = 0, len(intervals)
        while low_bound < high_bound:
            mid = (low_bound + high_bound) // 2
            low, high = intervals[mid]
            if code_point < low:
                high_bound = mid
            elif code_point > high:
                low_bound = mid + 1
            else:
                return True
        return False

    def first_member(self) -> int | None:
        if not self._intervals:
            return None
        return self._intervals[0][0]

    def component_first_members(self) -> tuple[int, ...]:
        return tuple(low for low, _high in self._intervals)

    def union(self, other: _IntervalSet) -> _IntervalSet:
        return _IntervalSet(list(self._intervals) + list(other._intervals))

    def intersection(self, other: _IntervalSet) -> _IntervalSet:
        result: list[tuple[int, int]] = []
        left, right = self._intervals, other._intervals
        i = j = 0
        while i < len(left) and j < len(right):
            a_low, a_high = left[i]
            b_low, b_high = right[j]
            low = max(a_low, b_low)
            high = min(a_high, b_high)
            if low <= high:
                result.append((low, high))
            if a_high < b_high:
                i += 1
            else:
                j += 1
        return _IntervalSet._from_normalized(tuple(result))

    def complement(self) -> _IntervalSet:
        result: list[tuple[int, int]] = []
        cursor = MIN_CODE_POINT
        for low, high in self._intervals:
            if low > cursor:
                result.append((cursor, low - 1))
            cursor = high + 1
        if cursor <= MAX_CODE_POINT:
            result.append((cursor, MAX_CODE_POINT))
        return _IntervalSet._from_normalized(tuple(result))

    def difference(self, other: _IntervalSet) -> _IntervalSet:
        return self.intersection(other.complement())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _IntervalSet):
            return NotImplemented
        return self._intervals == other._intervals

    def __hash__(self) -> int:
        return hash(self._intervals)

    def __repr__(self) -> str:
        return f"_IntervalSet({self._intervals!r})"


_CATEGORY_INTERVALS_CACHE: dict[Hashable, _IntervalSet] = {}


def cached_category_intervals(
    cache_key: Hashable, predicate: Callable[[int], bool]
) -> _IntervalSet:
    cached = _CATEGORY_INTERVALS_CACHE.get(cache_key)
    if cached is not None:
        return cached
    intervals: list[tuple[int, int]] = []
    start: int | None = None
    for code_point in range(MAX_CODE_POINT + 1):
        if predicate(code_point):
            if start is None:
                start = code_point
        elif start is not None:
            intervals.append((start, code_point - 1))
            start = None
    if start is not None:
        intervals.append((start, MAX_CODE_POINT))
    result = _IntervalSet(intervals)
    _CATEGORY_INTERVALS_CACHE[cache_key] = result
    return result


def _scan_escape_intervals(escape: str, flags: int) -> _IntervalSet:
    alphabet = "".join(map(chr, range(MAX_CODE_POINT + 1)))
    runs = re.compile("(?:" + escape + ")+", flags)
    return _IntervalSet._from_normalized(
        tuple((run.start(), run.end() - 1) for run in runs.finditer(alphabet))
    )


def cached_escape_intervals(escape: str, flags: int, negated: bool) -> _IntervalSet:
    ascii_flag = flags & re.ASCII
    cache_key = ("escape", escape, ascii_flag, negated)
    cached = _CATEGORY_INTERVALS_CACHE.get(cache_key)
    if cached is not None:
        return cached
    positive_key = ("escape", escape, ascii_flag, False)
    positive = _CATEGORY_INTERVALS_CACHE.get(positive_key)
    if positive is None:
        positive = _scan_escape_intervals(escape, ascii_flag)
        _CATEGORY_INTERVALS_CACHE[positive_key] = positive
    result = positive.complement() if negated else positive
    _CATEGORY_INTERVALS_CACHE[cache_key] = result
    return result
