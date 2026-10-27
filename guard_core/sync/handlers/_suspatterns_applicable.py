from collections.abc import Sequence

from guard_core.sync.handlers._suspatterns_lazy_rows import PatternRow, PatternSource
from guard_core.sync.handlers._suspatterns_pattern_table import (
    DETECTION_NUL_TAIL_RAW_VIEW_PATTERN_SOURCES,
    DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES,
)
from guard_core.sync.handlers._suspatterns_shell_sources import (
    DETECTION_RAW_VIEW_PATTERN_SOURCES,
    DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES,
)


def _excluded_from_raw_only(
    raw: bool, url_decoded: bool, recon_raw: bool, nul_tail: bool
) -> bool:
    return url_decoded or not (raw or recon_raw or nul_tail)


def _pattern_excluded_from_view(
    pattern: PatternSource,
    raw_view_only: bool | None,
    url_decoded_view_only: bool | None = None,
    nul_tail_rows: bool = False,
) -> bool:
    is_raw_view_pattern = pattern.pattern in DETECTION_RAW_VIEW_PATTERN_SOURCES
    is_url_decoded_view_pattern = (
        pattern.pattern in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    )
    is_recon_raw_view_pattern = (
        pattern.pattern in DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES
    )
    if raw_view_only is True:
        return _excluded_from_raw_only(
            is_raw_view_pattern,
            is_url_decoded_view_pattern,
            is_recon_raw_view_pattern,
            nul_tail_rows
            and pattern.pattern in DETECTION_NUL_TAIL_RAW_VIEW_PATTERN_SOURCES,
        )
    if url_decoded_view_only is True:
        return is_raw_view_pattern or not is_url_decoded_view_pattern
    return raw_view_only is False and (
        is_raw_view_pattern or is_url_decoded_view_pattern
    )


def _category_disabled(category: str, enabled_categories: set[str] | None) -> bool:
    return (
        enabled_categories is not None
        and category != "custom"
        and category not in enabled_categories
    )


def _pattern_should_be_skipped(
    pattern: PatternSource,
    contexts: frozenset[str],
    category: str,
    *,
    raw_view_only: bool | None,
    skip_filter: bool,
    normalized_context: str,
    enabled_categories: set[str] | None,
    url_decoded_view_only: bool | None = None,
    nul_tail_rows: bool = False,
) -> bool:
    if _pattern_excluded_from_view(
        pattern, raw_view_only, url_decoded_view_only, nul_tail_rows
    ):
        return True
    if not skip_filter and normalized_context not in contexts:
        return True
    return _category_disabled(category, enabled_categories)


_APPLICABLE_PATTERN_CACHE_MAX_ENTRIES = 256
_applicable_pattern_cache: dict[
    tuple[object, ...],
    tuple[
        list[PatternRow],
        list[PatternRow],
        bool,
    ],
] = {}


def _applicable_cache_key(
    raw_view_only: bool | None,
    url_decoded_view_only: bool | None,
    skip_filter: bool,
    normalized_context: str,
    enabled_categories: set[str] | None,
    nul_tail_rows: bool,
) -> tuple[object, ...]:
    return (
        nul_tail_rows,
        raw_view_only,
        url_decoded_view_only,
        skip_filter,
        normalized_context,
        None if enabled_categories is None else frozenset(enabled_categories),
    )


def _tail_was_skipped(
    all_patterns: Sequence[PatternRow],
    applicable: Sequence[PatternRow],
) -> bool:
    return bool(all_patterns) and (
        not applicable or applicable[-1] is not all_patterns[-1]
    )


def _applicable_patterns(
    all_patterns: Sequence[PatternRow],
    *,
    raw_view_only: bool | None,
    url_decoded_view_only: bool | None,
    skip_filter: bool,
    normalized_context: str,
    enabled_categories: set[str] | None,
    nul_tail_rows: bool = False,
) -> tuple[list[PatternRow], bool]:
    key = _applicable_cache_key(
        raw_view_only,
        url_decoded_view_only,
        skip_filter,
        normalized_context,
        enabled_categories,
        nul_tail_rows,
    )
    cached = _applicable_pattern_cache.get(key)
    if cached is not None and cached[0] == all_patterns:
        return cached[1], cached[2]
    applicable = [
        row
        for row in all_patterns
        if not _pattern_should_be_skipped(
            row[0],
            row[1],
            row[2],
            raw_view_only=raw_view_only,
            skip_filter=skip_filter,
            normalized_context=normalized_context,
            enabled_categories=enabled_categories,
            url_decoded_view_only=url_decoded_view_only,
            nul_tail_rows=nul_tail_rows,
        )
    ]
    skipped_tail = _tail_was_skipped(all_patterns, applicable)
    if len(_applicable_pattern_cache) >= _APPLICABLE_PATTERN_CACHE_MAX_ENTRIES:
        _applicable_pattern_cache.clear()
    _applicable_pattern_cache[key] = (list(all_patterns), applicable, skipped_tail)
    return applicable, skipped_tail
