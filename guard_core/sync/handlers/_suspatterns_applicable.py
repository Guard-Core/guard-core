import re
from typing import Any

from guard_core.sync.handlers._suspatterns_pattern_table import (
    DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES,
)
from guard_core.sync.handlers._suspatterns_shell_sources import (
    DETECTION_RAW_VIEW_PATTERN_SOURCES,
    DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES,
)


def _pattern_excluded_from_view(
    pattern: re.Pattern,
    raw_view_only: bool | None,
    url_decoded_view_only: bool | None = None,
) -> bool:
    is_raw_view_pattern = pattern.pattern in DETECTION_RAW_VIEW_PATTERN_SOURCES
    is_url_decoded_view_pattern = (
        pattern.pattern in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    )
    is_recon_raw_view_pattern = (
        pattern.pattern in DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES
    )
    if raw_view_only is True:
        return is_url_decoded_view_pattern or not (
            is_raw_view_pattern or is_recon_raw_view_pattern
        )
    if url_decoded_view_only is True:
        return is_raw_view_pattern or not is_url_decoded_view_pattern
    if raw_view_only is False:
        return is_raw_view_pattern or is_url_decoded_view_pattern
    return False


def _pattern_should_be_skipped(
    pattern: re.Pattern,
    contexts: frozenset[str],
    category: str,
    *,
    raw_view_only: bool | None,
    skip_filter: bool,
    normalized_context: str,
    enabled_categories: set[str] | None,
    url_decoded_view_only: bool | None = None,
) -> bool:
    if _pattern_excluded_from_view(pattern, raw_view_only, url_decoded_view_only):
        return True
    if not skip_filter and normalized_context not in contexts:
        return True
    return (
        enabled_categories is not None
        and category != "custom"
        and category not in enabled_categories
    )


_APPLICABLE_PATTERN_CACHE_MAX_ENTRIES = 256
_applicable_pattern_cache: dict[
    tuple[Any, ...],
    tuple[
        list[tuple[re.Pattern, frozenset[str], str]],
        list[tuple[re.Pattern, frozenset[str], str]],
        bool,
    ],
] = {}


def _applicable_patterns(
    all_patterns: list[tuple[re.Pattern, frozenset[str], str]],
    *,
    raw_view_only: bool | None,
    url_decoded_view_only: bool | None,
    skip_filter: bool,
    normalized_context: str,
    enabled_categories: set[str] | None,
) -> tuple[list[tuple[re.Pattern, frozenset[str], str]], bool]:
    key = (
        raw_view_only,
        url_decoded_view_only,
        skip_filter,
        normalized_context,
        None if enabled_categories is None else frozenset(enabled_categories),
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
        )
    ]
    skipped_tail = bool(all_patterns) and (
        not applicable or applicable[-1] is not all_patterns[-1]
    )
    if len(_applicable_pattern_cache) >= _APPLICABLE_PATTERN_CACHE_MAX_ENTRIES:
        _applicable_pattern_cache.clear()
    _applicable_pattern_cache[key] = (list(all_patterns), applicable, skipped_tail)
    return applicable, skipped_tail
