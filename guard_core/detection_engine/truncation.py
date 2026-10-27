import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING

from guard_core._utils.detection_scan import (
    _EVENT_LOOP_SLICE_SECONDS,
    _charge_extraction_cpu,
    _charge_inline_cpu,
    _restart_inline_cpu,
    _scan_slice_start,
    _scan_time_budget_exhausted,
    _scan_time_remaining,
    _thread_cpu_seconds,
)
from guard_core.detection_engine.compiler import _yield_to_event_loop
from guard_core.detection_engine.on_handler_indicator import OnHandlerIndicator

if TYPE_CHECKING:
    from guard_core.detection_engine.preprocessor import ContentPreprocessor

_FULL_SCAN_TAIL_BYTES = 4096
EXTRACTION_WINDOW_CHARS = 262144
_WORD_RUN_RE = re.compile(r"\w+")

_attack_region_memo: ContextVar[
    dict[tuple[int, tuple[tuple[str, int], ...], str], list[tuple[int, int]]] | None
] = ContextVar("attack_region_memo", default=None)


@contextmanager
def reusing_attack_regions() -> Iterator[None]:
    token = _attack_region_memo.set({})
    try:
        yield
    finally:
        _attack_region_memo.reset(token)


def _append_regions(
    found: list[tuple[int, int]],
    pattern: re.Pattern[str] | OnHandlerIndicator,
    text: str,
    max_regions: int,
    start: int = 0,
    stop: int | None = None,
) -> None:
    matches = (
        pattern.finditer(text) if stop is None else pattern.finditer(text, start, stop)
    )
    for match in matches:
        if len(found) >= max_regions:
            break
        found.append((max(0, match.start() - 100), min(len(text), match.end() + 100)))


def _find_regions(
    pattern: re.Pattern[str] | OnHandlerIndicator, text: str, max_regions: int
) -> list[tuple[int, int]]:
    found: list[tuple[int, int]] = []
    _append_regions(found, pattern, text, max_regions)
    return found


def _collect_regions(
    preprocessor: "ContentPreprocessor", content: str, max_regions: int
) -> tuple[list[tuple[int, int]], bool]:
    regions: list[tuple[int, int]] = []
    started = _thread_cpu_seconds()
    try:
        for indicator in preprocessor.compiled_indicators:
            remaining = _scan_time_remaining()
            if remaining is not None and _thread_cpu_seconds() - started >= remaining:
                return regions, False
            regions.extend(_find_regions(indicator, content, max_regions))
            if len(regions) >= max_regions:
                break
        return regions, True
    finally:
        _charge_extraction_cpu(_thread_cpu_seconds() - started)


async def yield_once_slice_elapsed() -> None:
    slice_start = _scan_slice_start.get()
    if (
        slice_start is None
        or time.monotonic() - slice_start < _EVENT_LOOP_SLICE_SECONDS
    ):
        return
    _charge_inline_cpu()
    await _yield_to_event_loop()
    _restart_inline_cpu()
    _scan_slice_start.set(time.monotonic())


def _word_run_end(text: str, position: int) -> int:
    run = _WORD_RUN_RE.match(text, position)
    return position if run is None else run.end()


def _word_run_windows(text: str) -> Iterator[tuple[int, int]]:
    start = 0
    while start < len(text):
        stop = min(len(text), start + EXTRACTION_WINDOW_CHARS)
        stop = max(stop, _word_run_end(text, stop))
        yield start, stop
        start = stop


def _indicator_windows(
    indicator: re.Pattern[str] | OnHandlerIndicator, text: str
) -> Iterator[tuple[int, int]]:
    if isinstance(indicator, OnHandlerIndicator):
        return _word_run_windows(text)
    return iter(((0, len(text)),))


async def _collect_regions_yielding(
    preprocessor: "ContentPreprocessor", content: str, max_regions: int
) -> tuple[list[tuple[int, int]], bool]:
    regions: list[tuple[int, int]] = []
    for indicator in preprocessor.compiled_indicators:
        for start, stop in _indicator_windows(indicator, content):
            started = _thread_cpu_seconds()
            try:
                if _scan_time_budget_exhausted():
                    return regions, False
                _append_regions(regions, indicator, content, max_regions, start, stop)
            finally:
                _charge_extraction_cpu(_thread_cpu_seconds() - started)
            await yield_once_slice_elapsed()
        if len(regions) >= max_regions:
            break
    return regions, True


def _merge_regions(
    regions: list[tuple[int, int]], max_regions: int
) -> list[tuple[int, int]]:
    if not regions:
        return []
    regions.sort()
    merged = [regions[0]]
    for start, end in regions[1:]:
        if start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged[:max_regions]


def _regions_memo_key(
    preprocessor: "ContentPreprocessor", content: str
) -> tuple[int, tuple[tuple[str, int], ...], str]:
    max_regions = min(100, preprocessor.max_content_length // 100)
    indicators = tuple((p.pattern, p.flags) for p in preprocessor.compiled_indicators)
    return (max_regions, indicators, content)


def extract_attack_regions(
    preprocessor: "ContentPreprocessor", content: str
) -> list[tuple[int, int]]:
    memo = _attack_region_memo.get()
    key = _regions_memo_key(preprocessor, content)
    if memo is not None and key in memo:
        return list(memo[key])
    regions, complete = _collect_regions(preprocessor, content, key[0])
    merged = _merge_regions(regions, key[0])
    if memo is not None and complete:
        memo[key] = merged
    return list(merged)


async def truncate_safely_yielding(
    preprocessor: "ContentPreprocessor", content: str
) -> str:
    if (
        len(content) <= preprocessor._MAX_FULL_SCAN_BYTES
        or not preprocessor.preserve_attack_patterns
    ):
        return truncate_safely(preprocessor, content)
    key = _regions_memo_key(preprocessor, content)
    memo = _attack_region_memo.get()
    token = None
    if memo is None:
        memo = {}
        token = _attack_region_memo.set(memo)
    try:
        if key not in memo:
            regions, complete = await _collect_regions_yielding(
                preprocessor, content, key[0]
            )
            if complete:
                memo[key] = _merge_regions(regions, key[0])
        return truncate_safely(preprocessor, content)
    finally:
        if token is not None:
            _attack_region_memo.reset(token)


def extract_and_concatenate_attack_regions(
    content: str, attack_regions: list[tuple[int, int]], budget: int
) -> str:
    result = ""
    remaining = budget

    for start, end in attack_regions:
        chunk_len = min(end - start, remaining)
        result += content[start : start + chunk_len]
        remaining -= chunk_len
        if remaining <= 0:
            break

    return result


def _consume_gap(
    content: str, last_end: int, start: int, gap_budget: int
) -> tuple[str, int]:
    gap_len = start - last_end
    if gap_len <= gap_budget:
        return content[last_end:start], gap_budget - gap_len
    chunk_len = gap_budget - 1
    piece = content[last_end : last_end + chunk_len] if chunk_len > 0 else ""
    return f"{piece} ", 0


def build_result_with_attack_regions_and_context(
    content: str, attack_regions: list[tuple[int, int]], budget: int
) -> str:
    attack_length = sum(end - start for start, end in attack_regions)
    gap_budget = budget - attack_length
    result_parts: list[str] = []
    last_end = 0

    for start, end in attack_regions:
        if last_end < start and gap_budget > 0:
            piece, gap_budget = _consume_gap(content, last_end, start, gap_budget)
            result_parts.append(piece)
        result_parts.append(content[start:end])
        last_end = end

    if last_end < len(content) and gap_budget > 0:
        tail_len = min(len(content) - last_end, gap_budget)
        result_parts.append(content[last_end : last_end + tail_len])

    return "".join(result_parts)


def cap_with_tail(content: str, max_full_scan_bytes: int) -> str:
    cap = max_full_scan_bytes
    tail = min(_FULL_SCAN_TAIL_BYTES, cap)
    head_len = cap - tail
    return content[:head_len] + content[-tail:]


def truncate_safely(preprocessor: "ContentPreprocessor", content: str) -> str:
    max_full_scan_bytes = preprocessor._MAX_FULL_SCAN_BYTES

    if len(content) <= max_full_scan_bytes:
        return content

    if not preprocessor.preserve_attack_patterns:
        return content[:max_full_scan_bytes]

    attack_regions = preprocessor.extract_attack_regions(content)

    if not attack_regions:
        content = preprocessor._cap_with_tail(content)
        return content

    attack_length = sum(end - start for start, end in attack_regions)

    if attack_length >= max_full_scan_bytes:
        content = preprocessor._extract_and_concatenate_attack_regions(
            content, attack_regions, budget=max_full_scan_bytes
        )
        return content

    content = preprocessor._build_result_with_attack_regions_and_context(
        content, attack_regions, budget=max_full_scan_bytes
    )
    return content
