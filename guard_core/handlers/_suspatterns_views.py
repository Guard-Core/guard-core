import time

from guard_core.detection_engine import ContentPreprocessor, truncation
from guard_core.detection_engine.encoding_decoders import (
    decode_overlong_utf8_percent_runs,
    decode_percent_u_escapes,
    percent_decode,
)
from guard_core.handlers._suspatterns_regex import (
    _resolve_pattern_weight,
    _sanitize_for_reporting,
    _SusPatternsRegexMixin,
)
from guard_core.handlers._suspatterns_sources import (
    _DEFAULT_MAX_SCAN_LENGTH,
    _PATH_TRAVERSAL_DECODED_SHAPE_RE,
)
from guard_core.handlers._suspatterns_state import _DetectionState

_LEGACY_PATH_TRAVERSAL_DECODE_MAX_ITERATIONS = 8
_LEGACY_PATH_TRAVERSAL_PREPROCESSOR = ContentPreprocessor()
_NUL_TEXT_MARKERS = ("%00", "\\u0000", "\\x00")
_DELETED_CONTROL_CHARS = frozenset(
    chr(code) for code in range(32) if code not in (9, 10, 13)
)


def _legacy_decode_path_traversal_view(normalized_content: str) -> str:
    decoded = normalized_content
    for _ in range(_LEGACY_PATH_TRAVERSAL_DECODE_MAX_ITERATIONS):
        previous = decoded
        decoded = decode_overlong_utf8_percent_runs(decoded)
        decoded = percent_decode(decoded, errors="ignore")
        decoded = decode_percent_u_escapes(decoded)
        decoded = _LEGACY_PATH_TRAVERSAL_PREPROCESSOR.normalize_unicode(decoded)
        if decoded == previous:
            break
    return _LEGACY_PATH_TRAVERSAL_PREPROCESSOR.remove_null_bytes(decoded)


class _SusPatternsViewsMixin(_SusPatternsRegexMixin):
    async def _check_raw_view_patterns(
        self,
        content: str,
        ip_address: str,
        context: str,
        correlation_id: str | None,
        enabled_categories: set[str] | None,
        state: _DetectionState,
    ) -> tuple[list[dict], list[str], list[str]]:
        preprocessor = state.preprocessor
        if not preprocessor:
            return [], [], []

        raw_view_content = await preprocessor.preprocess_signal_preserving_yielding(
            content
        )
        return await self._check_regex_patterns(
            raw_view_content,
            ip_address,
            correlation_id,
            context,
            enabled_categories,
            state=state,
            raw_view_only=True,
            nul_tail_rows=(
                not _DELETED_CONTROL_CHARS.isdisjoint(raw_view_content)
                or any(map(raw_view_content.__contains__, _NUL_TEXT_MARKERS))
            ),
        )

    async def _check_decoded_view_path_traversal(
        self,
        processed_content: str,
        content: str,
        context: str,
        enabled_categories: set[str] | None,
        state: _DetectionState,
    ) -> dict[str, str | float] | None:
        if (
            enabled_categories is not None
            and "path_traversal" not in enabled_categories
        ):
            return None

        pattern_start = time.monotonic()
        preprocessor = state.preprocessor
        if preprocessor:
            raw_view_content = await preprocessor.preprocess_signal_preserving_yielding(
                content
            )
            decoded_view_content = processed_content
        else:
            max_length = getattr(
                self._scan_config(),
                "detection_max_content_length",
                _DEFAULT_MAX_SCAN_LENGTH,
            )
            raw_view_content = _LEGACY_PATH_TRAVERSAL_PREPROCESSOR.normalize_unicode(
                content[:max_length]
            )
            decoded_view_content = _legacy_decode_path_traversal_view(raw_view_content)

        decoded_matches = list(
            _PATH_TRAVERSAL_DECODED_SHAPE_RE.finditer(decoded_view_content)
        )
        raw_count = len(_PATH_TRAVERSAL_DECODED_SHAPE_RE.findall(raw_view_content))
        if len(decoded_matches) <= raw_count:
            return None

        match = decoded_matches[0]
        return {
            "type": "regex",
            "pattern": _PATH_TRAVERSAL_DECODED_SHAPE_RE.pattern,
            "match": _sanitize_for_reporting(match.group()),
            "position": match.start(),
            "execution_time": time.monotonic() - pattern_start,
            "category": "path_traversal",
            "weight": _resolve_pattern_weight(
                _PATH_TRAVERSAL_DECODED_SHAPE_RE.pattern, "path_traversal"
            ),
        }

    async def _check_url_decoded_view_patterns(
        self,
        content: str,
        ip_address: str,
        context: str,
        correlation_id: str | None,
        enabled_categories: set[str] | None,
        state: _DetectionState,
        *,
        precomputed_decoded: str | None = None,
        precomputed_decode_budget_exhausted: bool = False,
    ) -> tuple[list[dict], list[str], list[str], bool]:
        preprocessor = state.preprocessor
        if not preprocessor:
            return [], [], [], False

        if precomputed_decoded is not None:
            url_decoded_view_content = await truncation.truncate_safely_yielding(
                preprocessor, precomputed_decoded
            )
            decode_budget_exhausted_flag = precomputed_decode_budget_exhausted
        else:
            decode_budget_exhausted: list[bool] = [False]
            url_decoded_view_content = (
                await preprocessor.preprocess_url_decoded_newline_preserving(
                    content, decode_budget_exhausted
                )
            )
            decode_budget_exhausted_flag = decode_budget_exhausted[0]

        threats, matched, timeouts = await self._check_regex_patterns(
            url_decoded_view_content,
            ip_address,
            correlation_id,
            context,
            enabled_categories,
            state=state,
            url_decoded_view_only=True,
        )
        return threats, matched, timeouts, decode_budget_exhausted_flag

    async def _comment_dropped_view(
        self,
        precomputed_decoded: str | None,
        processed_content: str,
        state: _DetectionState,
    ) -> str | None:
        preprocessor = state.preprocessor
        if not preprocessor or precomputed_decoded is None:
            return None
        return await preprocessor.preprocess_comment_dropped_view_yielding(
            precomputed_decoded, processed_content
        )

    async def _check_comment_dropped_view_patterns(
        self,
        dropped_view: str | None,
        ip_address: str,
        context: str,
        correlation_id: str | None,
        enabled_categories: set[str] | None,
        state: _DetectionState,
    ) -> tuple[list[dict], list[str], list[str]]:
        if dropped_view is None:
            return [], [], []
        if enabled_categories is not None and "sqli" not in enabled_categories:
            return [], [], []

        return await self._check_regex_patterns(
            dropped_view,
            ip_address,
            correlation_id,
            context,
            {"sqli"},
            state=state,
            raw_view_only=False,
        )

    async def _check_short_base64_additive_view_patterns(
        self,
        content: str,
        ip_address: str,
        context: str,
        correlation_id: str | None,
        enabled_categories: set[str] | None,
        state: _DetectionState,
    ) -> tuple[list[dict], list[str], list[str]]:
        preprocessor = state.preprocessor
        if not preprocessor:
            return [], [], []

        additive_view_content = (
            await preprocessor.preprocess_short_base64_additive_view_yielding(content)
        )
        if not additive_view_content:
            return [], [], []

        return await self._check_regex_patterns(
            additive_view_content,
            ip_address,
            correlation_id,
            context,
            enabled_categories,
            state=state,
        )
