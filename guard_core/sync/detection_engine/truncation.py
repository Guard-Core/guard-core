from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from guard_core.sync._utils.detection_scan import (
    _scan_time_remaining,
    _thread_cpu_seconds,
)

_FULL_SCAN_TAIL_BYTES = 4096

_attack_region_memo: ContextVar[dict[Any, list[tuple[int, int]]] | None] = ContextVar(
    "attack_region_memo", default=None
)


@contextmanager
def reusing_attack_regions() -> Iterator[None]:
    token = _attack_region_memo.set({})
    try:
        yield
    finally:
        _attack_region_memo.reset(token)


def _find_regions(pattern: Any, text: str, max_regions: int) -> list[tuple[int, int]]:
    found: list[tuple[int, int]] = []
    for match in pattern.finditer(text):
        if len(found) >= max_regions:
            break
        start = max(0, match.start() - 100)
        end = min(len(text), match.end() + 100)
        found.append((start, end))
    return found


def _collect_regions(
    preprocessor: Any, content: str, max_regions: int
) -> tuple[list[tuple[int, int]], bool]:
    regions: list[tuple[int, int]] = []
    started = _thread_cpu_seconds()
    for indicator in preprocessor.compiled_indicators:
        remaining = _scan_time_remaining()
        if remaining is not None and _thread_cpu_seconds() - started >= remaining:
            return regions, False
        regions.extend(_find_regions(indicator, content, max_regions))
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


def extract_attack_regions(preprocessor: Any, content: str) -> list[tuple[int, int]]:
    max_regions = min(100, preprocessor.max_content_length // 100)
    memo = _attack_region_memo.get()
    indicators = tuple((p.pattern, p.flags) for p in preprocessor.compiled_indicators)
    key = (max_regions, indicators, content)
    if memo is not None and key in memo:
        return list(memo[key])
    regions, complete = _collect_regions(preprocessor, content, max_regions)
    merged = _merge_regions(regions, max_regions)
    if memo is not None and complete:
        memo[key] = merged
    return list(merged)


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


def truncate_safely(preprocessor: Any, content: str) -> str:
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
