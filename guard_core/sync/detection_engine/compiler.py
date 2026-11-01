import concurrent.futures
import contextlib
import logging
import os
import re
import threading
import time
from collections.abc import Callable
from typing import TypeVar

from guard_core.exceptions import BodyReadFailedError
from guard_core.sync._utils._scan_outcomes import (
    SCAN_OUTCOME_QUEUE_WAIT,
    SCAN_OUTCOME_RUN_TIMEOUT,
)
from guard_core.sync._utils.pattern_source_redaction import _SensitiveNameSets
from guard_core.sync.detection_engine import _validation_cache
from guard_core.sync.detection_engine._redos_cost_arbiter import (
    _PATTERN_SAFETY_DEFAULT_CAP,
    TransientReason,
    _reach_probe_cost_verdict,
    _run_pattern_safety_probe_subprocess,
)
from guard_core.sync.detection_engine._redos_structural_prefilters import (
    _dangerous_construct_violation,
    _first_structural_safety_violation,
)
from guard_core.sync.detection_engine.cache_stats import CacheStats, build_cache_stats

logger = logging.getLogger("guard_core.sync.detection_engine.compiler")

_SHARED_EXECUTOR_MAX_WORKERS = 4

_shared_executor: concurrent.futures.ThreadPoolExecutor | None = None
_executor_lock = threading.Lock()

_consecutive_timeouts = 0
_timeout_lock = threading.Lock()


def shared_regex_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _shared_executor
    if _shared_executor is None:
        with _executor_lock:
            if _shared_executor is None:
                _shared_executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=_SHARED_EXECUTOR_MAX_WORKERS,
                    thread_name_prefix="guard-regex",
                )
    return _shared_executor


def _forget_the_parents_workers() -> None:
    # A forked child has none of the parent's worker threads. Keeping the parent's
    # pool would queue its first scan behind workers that do not exist (the scan
    # waits out its bound and the request fails), and a lock another parent thread
    # held at fork time would stay held for good.
    global _shared_executor, _executor_lock, _consecutive_timeouts, _timeout_lock
    _shared_executor = None
    _executor_lock = threading.Lock()
    _consecutive_timeouts = 0
    _timeout_lock = threading.Lock()


with contextlib.suppress(AttributeError):
    os.register_at_fork(after_in_child=_forget_the_parents_workers)


class RegexQueueWaitExpired(Exception):
    """No worker took the scan within its bound: the pattern never ran."""


def no_regex_worker_time(waited: float) -> BodyReadFailedError:
    return BodyReadFailedError(
        f"no regex worker took the scan within {waited} s, so the request was not "
        "fully scanned"
    )


_Result = TypeVar("_Result")
_MatchWorkWrapper = Callable[
    [Callable[[], list[re.Match]]], Callable[[], list[re.Match]]
]


def submit_to_regex_executor(
    work: Callable[[], _Result],
    executor: concurrent.futures.ThreadPoolExecutor | None = None,
    ran_for: list[float] | None = None,
    worker_cpu: list[float] | None = None,
) -> tuple[concurrent.futures.Future[_Result], list[float]]:
    started: list[float] = []

    def run() -> _Result:
        start = time.monotonic()
        started.append(start)
        cpu_start = time.thread_time()
        try:
            return work()
        finally:
            if ran_for is not None:
                ran_for.append(time.monotonic() - start)
            if worker_cpu is not None:
                worker_cpu.append(time.thread_time() - cpu_start)

    return (executor or shared_regex_executor()).submit(run), started


def _run_budget_left(
    future: concurrent.futures.Future[_Result],
    started: list[float],
    timeout: float,
    expired: BaseException,
) -> float:
    """The run budget a scan has left once its first wait of ``timeout`` ended.

    A future that finished with an error of its own, or a worker that started, is
    judged by its own run; a worker that never started gets
    RegexQueueWaitExpired.
    """
    if not started and (future.cancelled() or future.cancel()):
        raise RegexQueueWaitExpired() from expired
    if future.done():
        raise expired
    return max(timeout - (time.monotonic() - (started or [time.monotonic()])[0]), 0.0)


def wait_for_regex_run(
    future: concurrent.futures.Future[_Result], started: list[float], timeout: float
) -> _Result:
    try:
        return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError as exc:
        left = _run_budget_left(future, started, timeout, exc)
    return future.result(timeout=left)


def _await_regex_future(
    future: concurrent.futures.Future[_Result], started: list[float], timeout: float
) -> _Result:
    return wait_for_regex_run(future, started, timeout)


def _yield_to_event_loop() -> None:
    return None


def report_scan_success() -> None:
    global _consecutive_timeouts
    if _consecutive_timeouts:
        with _timeout_lock:
            _consecutive_timeouts = 0


def report_scan_timeout() -> None:
    global _shared_executor, _consecutive_timeouts
    with _timeout_lock:
        _consecutive_timeouts += 1
        if _consecutive_timeouts < _SHARED_EXECUTOR_MAX_WORKERS:
            return
        stale_count = _consecutive_timeouts
        _consecutive_timeouts = 0
        with _executor_lock:
            stale_executor = _shared_executor
            _shared_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=_SHARED_EXECUTOR_MAX_WORKERS,
                thread_name_prefix="guard-regex",
            )
    if stale_executor is not None:
        stale_executor.shutdown(wait=False)
    logger.warning(
        "guard_core shared regex scan pool replaced after %d consecutive "
        "timeouts; a slow pattern may have permanently occupied all workers",
        stale_count,
    )


class PatternCompiler:
    MAX_CACHE_SIZE = 1000

    def __init__(
        self,
        default_timeout: float = 5.0,
        max_cache_size: int = 1000,
        validation_cache: "_validation_cache.PatternValidationCache | None" = None,
        redaction_names: _SensitiveNameSets | None = None,
    ):
        self.redaction_names = redaction_names
        self.default_timeout = default_timeout
        self.max_cache_size = min(max_cache_size, 5000)
        self._compiled_cache: dict[str, re.Pattern] = {}
        self._cache_order: list[str] = []
        self._compiled_sets: dict[
            tuple[str, ...], tuple[tuple[str, re.Pattern], ...]
        ] = {}
        self._cache_hits = 0
        self._cache_misses = 0
        self._cache_evictions = 0
        self._lock = threading.Lock()
        self._cache_guard = threading.Lock()
        self._validation_cache = validation_cache

    def _recall_compiled(self, cache_key: str, *, promote: bool) -> re.Pattern | None:
        with self._cache_guard:
            compiled = self._compiled_cache.get(cache_key)
            if compiled is not None:
                self._cache_hits += 1
                if promote:
                    self._cache_order.remove(cache_key)
                    self._cache_order.append(cache_key)
            return compiled

    def _remember_compiled(self, cache_key: str, compiled: re.Pattern) -> re.Pattern:
        with self._cache_guard:
            known = self._compiled_cache.get(cache_key)
            if known is not None:
                self._cache_hits += 1
                return known
            self._cache_misses += 1
            if len(self._compiled_cache) >= self.max_cache_size:
                oldest_key = self._cache_order.pop(0)
                del self._compiled_cache[oldest_key]
                self._cache_evictions += 1
            self._compiled_cache[cache_key] = compiled
            self._cache_order.append(cache_key)
            return compiled

    def compile_pattern(
        self, pattern: str, flags: int = re.IGNORECASE | re.MULTILINE
    ) -> re.Pattern:
        cache_key = f"{pattern}:{flags}"
        cached = self._recall_compiled(cache_key, promote=True)
        if cached is not None:
            return cached
        with self._lock:
            return self._remember_compiled(cache_key, re.compile(pattern, flags))

    def compile_pattern_sync(
        self, pattern: str, flags: int = re.IGNORECASE | re.MULTILINE
    ) -> re.Pattern:
        cache_key = f"{pattern}:{flags}"
        cached = self._recall_compiled(cache_key, promote=False)
        if cached is not None:
            return cached
        return self._remember_compiled(cache_key, re.compile(pattern, flags))

    def compile_pattern_set_sync(
        self, patterns: list[str]
    ) -> tuple[tuple[str, re.Pattern], ...]:
        """Compile a list of patterns that is looked up on every request (the
        blocked user agents) with one lookup. A repeat counts one hit per pattern."""
        key = tuple(patterns)
        with self._cache_guard:
            known = self._compiled_sets.get(key)
            if known is not None:
                self._cache_hits += len(known)
                return known
        compiled = tuple(
            (pattern, self.compile_pattern_sync(pattern)) for pattern in key
        )
        with self._cache_guard:
            if len(self._compiled_sets) >= self.max_cache_size:
                del self._compiled_sets[next(iter(self._compiled_sets))]
            self._compiled_sets[key] = compiled
        return compiled

    def validate_pattern_safety(
        self,
        pattern: str,
        test_strings: list[str] | None = None,
        max_content_length: int | None = None,
        flags: int = re.IGNORECASE | re.MULTILINE,
    ) -> tuple[bool, str]:
        dangerous_violation = _dangerous_construct_violation(pattern)
        if dangerous_violation is not None:
            return False, dangerous_violation

        try:
            self.compile_pattern_sync(pattern, flags)
        except Exception as e:
            return False, f"Pattern validation failed: {str(e)}"

        if test_strings is not None:
            structural_violation = _first_structural_safety_violation(pattern)
            if structural_violation is not None:
                return False, structural_violation
            return _run_pattern_safety_probe_subprocess(pattern, test_strings, flags)

        if self._validation_cache is None:
            return _reach_probe_cost_verdict(
                pattern, max_content_length, flags, self.redaction_names
            )
        cap = max_content_length or _PATTERN_SAFETY_DEFAULT_CAP
        cached = self._validation_cache.get(pattern, flags, cap)
        if cached is not None:
            return cached
        safe, reason = _reach_probe_cost_verdict(
            pattern, max_content_length, flags, self.redaction_names
        )
        if not isinstance(reason, TransientReason):
            self._validation_cache.put(pattern, flags, cap, safe, reason)
        return safe, reason

    def create_safe_matcher(
        self,
        pattern: str | re.Pattern,
        timeout: float | None = None,
        inline_safe: bool = False,
    ) -> Callable[[str], re.Match | None]:
        compiled = (
            pattern
            if isinstance(pattern, re.Pattern)
            else self.compile_pattern_sync(pattern)
        )
        match_timeout = timeout or self.default_timeout

        if inline_safe:

            def inline_safe_match(text: str) -> re.Match | None:
                return compiled.search(text)

            return inline_safe_match

        def safe_match(text: str) -> re.Match | None:
            future = shared_regex_executor().submit(compiled.search, text)
            try:
                result = future.result(timeout=match_timeout)
                report_scan_success()
                return result
            except concurrent.futures.TimeoutError:
                future.cancel()
                report_scan_timeout()
                return None
            except Exception:
                return None

        return safe_match

    def create_safe_finditer_matcher(
        self,
        pattern: str | re.Pattern,
        timeout: float | None = None,
        inline_safe: bool = False,
        worker_wrapper: _MatchWorkWrapper | None = None,
        outcome: list[str] | None = None,
    ) -> Callable[[str], list[re.Match]]:
        compiled = (
            pattern
            if isinstance(pattern, re.Pattern)
            else self.compile_pattern_sync(pattern)
        )
        match_timeout = timeout or self.default_timeout
        scan_outcome = [] if outcome is None else outcome

        if inline_safe:

            def inline_safe_finditer(text: str) -> list[re.Match]:
                return list(compiled.finditer(text))

            return inline_safe_finditer

        def safe_finditer(text: str) -> list[re.Match]:
            def work() -> list[re.Match]:
                return list(compiled.finditer(text))

            worker_cpu: list[float] = []
            future, started = submit_to_regex_executor(
                work if worker_wrapper is None else worker_wrapper(work),
                worker_cpu=worker_cpu,
            )
            try:
                result: list[re.Match] = wait_for_regex_run(
                    future, started, match_timeout
                )
                report_scan_success()
                ran_past_budget = sum(worker_cpu) >= 0.9 * match_timeout
                if not result and ran_past_budget:
                    scan_outcome.append(SCAN_OUTCOME_RUN_TIMEOUT)
                return result
            except RegexQueueWaitExpired:
                report_scan_timeout()
                scan_outcome.append(SCAN_OUTCOME_QUEUE_WAIT)
                return []
            except concurrent.futures.TimeoutError:
                future.cancel()
                report_scan_timeout()
                scan_outcome.append(SCAN_OUTCOME_RUN_TIMEOUT)
                return []
            except Exception:
                return []

        return safe_finditer

    def create_async_safe_finditer_matcher(
        self,
        pattern: str | re.Pattern,
        timeout: float | None = None,
        inline_safe: bool = False,
        worker_wrapper: _MatchWorkWrapper | None = None,
        outcome: list[str] | None = None,
    ) -> Callable[[str], list[re.Match]]:
        compiled = (
            pattern
            if isinstance(pattern, re.Pattern)
            else self.compile_pattern_sync(pattern)
        )
        match_timeout = timeout or self.default_timeout

        if inline_safe:

            def async_inline_finditer(text: str) -> list[re.Match]:
                return list(compiled.finditer(text))

            return async_inline_finditer

        sync_finder = self.create_safe_finditer_matcher(
            pattern,
            timeout=match_timeout,
            worker_wrapper=worker_wrapper,
            outcome=outcome,
        )

        def async_safe_finditer(text: str) -> list[re.Match]:
            return sync_finder(text)

        return async_safe_finditer

    def batch_compile(
        self,
        patterns: list[str],
        validate: bool = True,
        max_content_length: int | None = None,
    ) -> dict[str, re.Pattern]:
        compiled_patterns = {}
        for pattern in patterns:
            if validate:
                is_safe, reason = self.validate_pattern_safety(
                    pattern, max_content_length=max_content_length
                )
                if not is_safe:
                    continue
            try:
                compiled_patterns[pattern] = self.compile_pattern(pattern)
            except re.error:
                continue
        return compiled_patterns

    def get_cache_stats(self) -> CacheStats:
        return build_cache_stats(
            self._cache_hits,
            self._cache_misses,
            self._cache_evictions,
            len(self._compiled_cache),
            self.max_cache_size,
        )

    def get_validation_cache_stats(self) -> CacheStats | None:
        if self._validation_cache is None:
            return None
        return self._validation_cache.get_cache_stats()

    def clear_cache(self) -> None:
        with self._lock:
            with self._cache_guard:
                self._compiled_cache.clear()
                self._cache_order.clear()
                self._compiled_sets.clear()
