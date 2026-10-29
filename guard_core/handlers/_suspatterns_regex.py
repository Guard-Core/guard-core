import concurrent.futures
import logging
import re
import time
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

from guard_core._utils._scan_outcomes import (
    SCAN_OUTCOME_QUEUE_WAIT,
    SCAN_OUTCOME_RUN_TIMEOUT,
    ScanBudgetSpent,
)
from guard_core._utils.compiler_finditer import _compiler_finditer
from guard_core._utils.detection_scan import (
    _EVENT_LOOP_SLICE_SECONDS,
    _SCAN_TIME_BUDGET_EXHAUSTED_PATTERN,
    _charge_inline_cpu,
    _close_cpu_pass,
    _open_cpu_pass,
    _record_scan_time,
    _redact_pattern_source,
    _restart_inline_cpu,
    _scan_slice_start,
    _scan_time_budget_exhausted,
    _scan_time_budget_exhausted_threat,
    _scan_time_cap,
    _suspended,
    _timed_in_worker,
    _warn_scan_time_cap_reached_once,
)
from guard_core._utils.logging_utils import _sanitize_for_reporting
from guard_core.detection_engine.binary_prefix import (
    BinaryPrefix,
    build_binary_prefix,
    match_has_text_neighbourhood,
    match_is_binary_dense,
)
from guard_core.detection_engine.compiler import (
    RegexQueueWaitExpired,
    _await_regex_future,
    _yield_to_event_loop,
    no_regex_worker_time,
    report_scan_success,
    report_scan_timeout,
    shared_regex_executor,
    submit_to_regex_executor,
)
from guard_core.handlers._suspatterns_applicable import (
    _applicable_patterns,
)
from guard_core.handlers._suspatterns_applicable import (
    _pattern_excluded_from_view as _pattern_excluded_from_view,
)
from guard_core.handlers._suspatterns_applicable import (
    _pattern_should_be_skipped as _pattern_should_be_skipped,
)
from guard_core.handlers._suspatterns_candidate_gates import (
    _CANDIDATE_REJECTION_VALIDATORS as _CANDIDATE_REJECTION_VALIDATORS,
)
from guard_core.handlers._suspatterns_candidate_gates import (
    _CONTEXT_SENSITIVE_ROW_SOURCES,
    _candidate_passes_the_route_gates,
)
from guard_core.handlers._suspatterns_enhanced import _SusPatternsEnhancedMixin
from guard_core.handlers._suspatterns_inline_matches import (
    _INLINE_FINDERS,
    compiled_unless_known_clean,
)
from guard_core.handlers._suspatterns_lazy_rows import (
    PatternSource,
)
from guard_core.handlers._suspatterns_literals import (
    fold_for_literals,
    rows_with_required_literal,
)
from guard_core.handlers._suspatterns_named_floor import (
    probe_lies_inside_a_declared_path_param,
)
from guard_core.handlers._suspatterns_pattern_table import NOISE_PRONE_PATTERN_SOURCES
from guard_core.handlers._suspatterns_registry import _SusPatternsRegistryMixin
from guard_core.handlers._suspatterns_sources import (
    _DEFAULT_COMPILER_TIMEOUT,
    _EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX,
)
from guard_core.handlers._suspatterns_state import _DetectionState
from guard_core.handlers._suspatterns_weights import (
    _DECODE_BUDGET_EXHAUSTED_PATTERN as _DECODE_BUDGET_EXHAUSTED_PATTERN,
)
from guard_core.handlers._suspatterns_weights import (
    DETECTION_CATEGORY_WEIGHTS as DETECTION_CATEGORY_WEIGHTS,
)
from guard_core.handlers._suspatterns_weights import (
    DETECTION_PATTERN_WEIGHT_OVERRIDES as DETECTION_PATTERN_WEIGHT_OVERRIDES,
)
from guard_core.handlers._suspatterns_weights import (
    _decode_budget_exhausted_threat as _decode_budget_exhausted_threat,
)
from guard_core.handlers._suspatterns_weights import _resolve_pattern_weight
from guard_core.handlers._suspatterns_whole_value_rows import (
    rows_for_a_whole_value_pass,
)
from guard_core.handlers._suspatterns_windowed_finders import (
    _LITERAL_EXCLUDED_SOURCES,
    _WINDOWED_PATTERN_FINDERS,
)

if TYPE_CHECKING:
    from guard_core.protocols.agent_protocol import JsonValue

logger = logging.getLogger("guard_core.handlers.suspatterns")


def _build_regex_threat(
    pattern: re.Pattern,
    match: re.Match,
    category: str,
    pattern_start: float,
    context: str = "unknown",
    binary_prefix: BinaryPrefix | None = None,
) -> dict[str, "JsonValue"] | None:
    if not _candidate_passes_the_route_gates(pattern, match, context):
        return None
    if probe_lies_inside_a_declared_path_param(
        pattern, match, context, category, _candidate_passes_the_route_gates
    ):
        return None
    # A match inside dense binary is noise unless its own neighbourhood is text:
    # binary padding around a command must not hide the command.
    if (
        pattern.pattern in NOISE_PRONE_PATTERN_SOURCES
        and match_is_binary_dense(binary_prefix, match)
        and not match_has_text_neighbourhood(binary_prefix, match)
    ):
        return None
    return {
        "type": "regex",
        "pattern": pattern.pattern,
        "match": _sanitize_for_reporting(match.group()),
        "position": match.start(),
        "execution_time": time.monotonic() - pattern_start,
        "category": category,
        "weight": _resolve_pattern_weight(pattern.pattern, category),
    }


def _scan_budget_spent(time_cap: float | None, rows_pending: bool = True) -> bool:
    return rows_pending and time_cap is not None and _scan_time_budget_exhausted()


def _validator_context(context: str, normalized: str) -> str:
    if context.endswith(_EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX):
        return f"{normalized}{_EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX}"
    return normalized


def _threat_after_timeout(
    threat: dict[str, "JsonValue"] | None,
    timeout_occurred: bool,
    pattern: PatternSource,
    category: str,
    pattern_start: float,
    timeouts: list[str],
) -> dict[str, "JsonValue"] | None:
    if not timeout_occurred:
        return threat
    timeouts.append(pattern.pattern)
    return threat or _build_timeout_threat(pattern, category, pattern_start)


def _build_timeout_threat(
    pattern: PatternSource, category: str, pattern_start: float
) -> dict[str, "JsonValue"]:
    return {
        "type": "pattern_timeout",
        "pattern": pattern.pattern,
        "match": "",
        "position": 0,
        "execution_time": time.monotonic() - pattern_start,
        "category": category,
        "weight": _resolve_pattern_weight(pattern.pattern, category),
    }


async def _first_accepted_regex_threat(
    matches: Iterator[re.Match],
    pattern: re.Pattern,
    category: str,
    pattern_start: float,
    context: str = "unknown",
    binary_prefix: BinaryPrefix | None = None,
) -> dict[str, "JsonValue"] | None:
    slice_start, request_scoped = _pass_slice_start()
    time_cap = _scan_time_cap.get()
    for match in matches:
        if threat := _build_regex_threat(
            pattern, match, category, pattern_start, context, binary_prefix
        ):
            return threat
        slice_start = await _yield_once_slice_elapsed(slice_start, request_scoped)
        if time_cap is not None and _scan_time_budget_exhausted():
            raise ScanBudgetSpent
    return None


def _pass_slice_start() -> tuple[float, bool]:
    request_slice_start = _scan_slice_start.get()
    if request_slice_start is None:
        return time.monotonic(), False
    return request_slice_start, True


async def _yield_once_slice_elapsed(slice_start: float, request_scoped: bool) -> float:
    if time.monotonic() - slice_start < _EVENT_LOOP_SLICE_SECONDS:
        return slice_start
    _charge_inline_cpu()
    await _yield_to_event_loop()
    _restart_inline_cpu()
    slice_start = time.monotonic()
    if request_scoped:
        _scan_slice_start.set(slice_start)
    return slice_start


def _record_budget_exhaustion(
    ip_address: str,
    threats: list[dict],
    matched_patterns: list[str],
    timeouts: list[str],
) -> None:
    budget_threat = _scan_time_budget_exhausted_threat(
        _resolve_pattern_weight(_SCAN_TIME_BUDGET_EXHAUSTED_PATTERN, "custom")
    )
    _warn_scan_time_cap_reached_once(ip_address)
    threats.append(budget_threat)
    matched_patterns.append(_SCAN_TIME_BUDGET_EXHAUSTED_PATTERN)
    timeouts.append(_SCAN_TIME_BUDGET_EXHAUSTED_PATTERN)


class _SusPatternsRegexMixin(_SusPatternsRegistryMixin, _SusPatternsEnhancedMixin):
    async def _check_regex_pattern(
        self,
        pattern: PatternSource,
        content: str,
        ip_address: str,
        pattern_start: float,
        category: str,
        *,
        state: _DetectionState | None = None,
        context: str = "unknown",
        binary_prefix: BinaryPrefix | None = None,
    ) -> tuple[dict | None, bool]:
        state = self._resolve_state(state)
        compiled = compiled_unless_known_clean(pattern, content)
        if compiled is None:
            return None, False
        pattern = compiled
        windowed_finder = _WINDOWED_PATTERN_FINDERS.get(pattern.pattern)
        if windowed_finder is not None:
            return await self._check_windowed_pattern(
                pattern,
                windowed_finder,
                content,
                pattern_start,
                category,
                context,
                binary_prefix,
            )

        timeout_occurred = False

        inline = _INLINE_FINDERS[pattern.pattern]
        if inline is not None and (found := inline(content, pattern)) is not None:
            threat = await _first_accepted_regex_threat(
                iter(found),
                pattern,
                category,
                pattern_start,
                context,
                binary_prefix,
            )
            return threat, timeout_occurred

        compiler = state.compiler

        if compiler:
            matches, outcome = await _compiler_finditer(
                compiler, pattern, category, content, pattern_start
            )
            if outcome == SCAN_OUTCOME_QUEUE_WAIT:
                raise no_regex_worker_time(compiler.default_timeout)
            if outcome == SCAN_OUTCOME_RUN_TIMEOUT:
                timeout_occurred = True
                logger.warning(
                    "Pattern timeout: "
                    f"{_redact_pattern_source(pattern.pattern, self)[:50]}..."
                )

            threat = await _first_accepted_regex_threat(
                iter(matches),
                pattern,
                category,
                pattern_start,
                context,
                binary_prefix,
            )
            if threat:
                return threat, timeout_occurred
        else:
            threat, timeout_occurred = await self._check_regex_pattern_with_retry(
                pattern,
                content,
                ip_address,
                pattern_start,
                category,
                context,
                binary_prefix,
            )
            if threat:
                return threat, timeout_occurred

        return None, timeout_occurred

    async def _check_windowed_pattern(
        self,
        pattern: re.Pattern,
        finder: Callable[[str], Iterator[re.Match]],
        content: str,
        pattern_start: float,
        category: str,
        context: str,
        binary_prefix: BinaryPrefix | None = None,
    ) -> tuple[dict | None, bool]:
        timeout = getattr(
            self._scan_config(), "detection_compiler_timeout", _DEFAULT_COMPILER_TIMEOUT
        )
        worker_cpu: list[float] = []
        future, started = submit_to_regex_executor(
            _timed_in_worker(lambda: list(finder(content)), worker_cpu),
            shared_regex_executor(),
        )
        try:
            matches = await _suspended(_await_regex_future(future, started, timeout))
            report_scan_success()
            _record_scan_time(sum(worker_cpu))
        except RegexQueueWaitExpired as exc:
            report_scan_timeout()
            raise no_regex_worker_time(timeout) from exc
        except concurrent.futures.TimeoutError:
            _record_scan_time(timeout)
            logger.warning(
                "Pattern timeout: "
                f"{_redact_pattern_source(pattern.pattern, self)[:50]}..."
            )
            future.cancel()
            report_scan_timeout()
            return None, True
        except Exception as e:
            logger.error(
                f"Error in windowed regex search for pattern "
                f"{_redact_pattern_source(pattern.pattern, self)[:50]}...: {e}"
            )
            return None, False

        threat = await _first_accepted_regex_threat(
            iter(matches), pattern, category, pattern_start, context, binary_prefix
        )
        return threat, False

    async def _check_regex_pattern_with_retry(
        self,
        pattern: re.Pattern,
        content: str,
        ip_address: str,
        pattern_start: float,
        category: str,
        context: str = "unknown",
        binary_prefix: BinaryPrefix | None = None,
    ) -> tuple[dict | None, bool]:
        search_from = 0
        timeout_occurred = False

        while True:
            match, occurred = await self._check_pattern_with_timeout(
                pattern, content, ip_address, pattern_start, search_from
            )
            timeout_occurred = timeout_occurred or occurred
            if match is None or occurred:
                break

            threat = _build_regex_threat(
                pattern, match, category, pattern_start, context, binary_prefix
            )
            if threat:
                return threat, timeout_occurred

            search_from = (
                match.end() + 1 if match.end() == match.start() else match.end()
            )

        return None, timeout_occurred

    async def _check_pattern_with_timeout(
        self,
        pattern: re.Pattern,
        content: str,
        ip_address: str,
        pattern_start: float,
        search_from: int = 0,
    ) -> tuple[re.Match | None, bool]:
        timeout = getattr(
            self._scan_config(), "detection_compiler_timeout", _DEFAULT_COMPILER_TIMEOUT
        )
        worker_cpu: list[float] = []
        future, started = submit_to_regex_executor(
            _timed_in_worker(lambda: pattern.search(content, search_from), worker_cpu),
            shared_regex_executor(),
        )
        try:
            match = await _suspended(_await_regex_future(future, started, timeout))
            report_scan_success()
            _record_scan_time(sum(worker_cpu))
            return match, False
        except RegexQueueWaitExpired as exc:
            report_scan_timeout()
            raise no_regex_worker_time(timeout) from exc
        except concurrent.futures.TimeoutError:
            _record_scan_time(timeout)
            logger.warning(
                f"Regex timeout exceeded for pattern: "
                f"{_redact_pattern_source(pattern.pattern, self)[:50]}... "
                f"Potential ReDoS attack blocked. IP: {ip_address}"
            )
            future.cancel()
            report_scan_timeout()
            return None, True
        except Exception as e:
            logger.error(
                f"Error in regex search for pattern "
                f"{_redact_pattern_source(pattern.pattern, self)[:50]}...: {e}"
            )
            return None, False

    _KNOWN_CONTEXTS = frozenset(
        {"query_param", "header", "url_path", "request_body", "unknown"}
    )

    @staticmethod
    def _normalize_context(context: str | None) -> str:
        if context is None:
            return "unknown"
        normalized = context.split(":", 1)[0]
        if normalized not in _SusPatternsRegexMixin._KNOWN_CONTEXTS:
            return "unknown"
        return normalized

    async def _check_regex_patterns(
        self,
        content: str,
        ip_address: str,
        correlation_id: str | None,
        context: str = "unknown",
        enabled_categories: set[str] | None = None,
        *,
        state: _DetectionState | None = None,
        raw_view_only: bool | None = None,
        url_decoded_view_only: bool | None = None,
        nul_tail_rows: bool = False,
    ) -> tuple[list[dict], list[str], list[str]]:
        state = self._resolve_state(state)
        threats: list[dict] = []
        matched_patterns: list[str] = []
        timeouts: list[str] = []

        all_patterns = await self._rows_to_scan()
        normalized = self._normalize_context(context)
        validator_context = _validator_context(context, normalized)
        skip_filter = normalized in ("unknown", "request_body")
        performance_monitor = state.performance_monitor
        binary_prefix = build_binary_prefix(content)

        applicable_patterns, skipped_tail = _applicable_patterns(
            all_patterns,
            raw_view_only=raw_view_only,
            url_decoded_view_only=url_decoded_view_only,
            skip_filter=skip_filter,
            normalized_context=normalized,
            enabled_categories=enabled_categories,
            nul_tail_rows=nul_tail_rows,
        )

        applicable_patterns = rows_for_a_whole_value_pass(
            applicable_patterns, _CONTEXT_SENSITIVE_ROW_SOURCES
        )
        time_cap = _scan_time_cap.get()
        slice_start, request_scoped = _pass_slice_start()
        mark_token = _open_cpu_pass()

        metric_rows: list[tuple[str, float, int, bool, bool]] = []
        content_length = len(content)

        try:
            for pattern, _contexts, category in rows_with_required_literal(
                applicable_patterns,
                fold_for_literals(content),
                _LITERAL_EXCLUDED_SOURCES,
            ):
                if _scan_budget_spent(time_cap):
                    _record_budget_exhaustion(
                        ip_address, threats, matched_patterns, timeouts
                    )
                    break

                pattern_start = time.monotonic()

                scan_content = content
                try:
                    threat, timeout_occurred = await self._check_regex_pattern(
                        pattern,
                        scan_content,
                        ip_address,
                        pattern_start,
                        category,
                        state=state,
                        context=validator_context,
                        binary_prefix=binary_prefix,
                    )
                except ScanBudgetSpent:
                    _record_budget_exhaustion(
                        ip_address, threats, matched_patterns, timeouts
                    )
                    break

                slice_start = await _yield_once_slice_elapsed(
                    slice_start, request_scoped
                )

                threat = _threat_after_timeout(
                    threat, timeout_occurred, pattern, category, pattern_start, timeouts
                )

                if threat:
                    threats.append(threat)
                    matched_patterns.append(pattern.pattern)

                if performance_monitor:
                    metric_rows.append(
                        (
                            pattern.pattern,
                            time.monotonic() - pattern_start,
                            content_length,
                            bool(threat),
                            timeout_occurred,
                        )
                    )
            else:
                if _scan_budget_spent(time_cap, skipped_tail):
                    _record_budget_exhaustion(
                        ip_address, threats, matched_patterns, timeouts
                    )

        finally:
            _close_cpu_pass(mark_token)

        if performance_monitor and metric_rows:
            await performance_monitor.record_metrics(
                metric_rows,
                agent_handler=self._events_agent_handler,
                correlation_id=correlation_id,
            )

        return threats, matched_patterns, timeouts
