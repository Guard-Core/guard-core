import asyncio
import concurrent.futures
import logging
import re
import threading
from collections.abc import Awaitable, Callable

from guard_core.detection_engine import _validation_cache
from guard_core.detection_engine._redos_cost_arbiter import (
    _reach_probe_cost_verdict,
    _run_pattern_safety_probe_subprocess,
)
from guard_core.detection_engine._redos_structural_prefilters import (
    _dangerous_construct_violation,
    _first_structural_safety_violation,
)

logger = logging.getLogger("guard_core.detection_engine.compiler")

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
    ):
        self.default_timeout = default_timeout
        self.max_cache_size = min(max_cache_size, 5000)
        self._compiled_cache: dict[str, re.Pattern] = {}
        self._cache_order: list[str] = []
        self._lock = asyncio.Lock()
        self._validation_cache = validation_cache

    async def compile_pattern(
        self, pattern: str, flags: int = re.IGNORECASE | re.MULTILINE
    ) -> re.Pattern:
        cache_key = f"{pattern}:{flags}"

        if cache_key in self._compiled_cache:
            async with self._lock:
                if cache_key in self._compiled_cache:
                    self._cache_order.remove(cache_key)
                    self._cache_order.append(cache_key)
                    return self._compiled_cache[cache_key]

        async with self._lock:
            if cache_key not in self._compiled_cache:
                if len(self._compiled_cache) >= self.max_cache_size:
                    oldest_key = self._cache_order.pop(0)
                    del self._compiled_cache[oldest_key]

                self._compiled_cache[cache_key] = re.compile(pattern, flags)
                self._cache_order.append(cache_key)

            return self._compiled_cache[cache_key]

    def compile_pattern_sync(
        self, pattern: str, flags: int = re.IGNORECASE | re.MULTILINE
    ) -> re.Pattern:
        return re.compile(pattern, flags)

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

        if self._validation_cache is not None:
            cached = self._validation_cache.get(pattern, flags)
            if cached is not None:
                return cached
        verdict = _reach_probe_cost_verdict(pattern, max_content_length, flags)
        if self._validation_cache is not None:
            self._validation_cache.put(pattern, flags, *verdict)
        return verdict

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
    ) -> Callable[[str], list[re.Match]]:
        compiled = (
            pattern
            if isinstance(pattern, re.Pattern)
            else self.compile_pattern_sync(pattern)
        )
        match_timeout = timeout or self.default_timeout

        if inline_safe:

            def inline_safe_finditer(text: str) -> list[re.Match]:
                return list(compiled.finditer(text))

            return inline_safe_finditer

        def safe_finditer(text: str) -> list[re.Match]:
            future = shared_regex_executor().submit(
                lambda: list(compiled.finditer(text))
            )
            try:
                result = future.result(timeout=match_timeout)
                report_scan_success()
                return result
            except concurrent.futures.TimeoutError:
                future.cancel()
                report_scan_timeout()
                return []
            except Exception:
                return []

        return safe_finditer

    def create_async_safe_finditer_matcher(
        self,
        pattern: str | re.Pattern,
        timeout: float | None = None,
        inline_safe: bool = False,
    ) -> Callable[[str], Awaitable[list[re.Match]]]:
        compiled = (
            pattern
            if isinstance(pattern, re.Pattern)
            else self.compile_pattern_sync(pattern)
        )
        match_timeout = timeout or self.default_timeout

        if inline_safe:

            async def async_inline_finditer(text: str) -> list[re.Match]:
                return list(compiled.finditer(text))

            return async_inline_finditer

        sync_finder = self.create_safe_finditer_matcher(pattern, timeout=match_timeout)

        async def async_safe_finditer(text: str) -> list[re.Match]:
            return await asyncio.to_thread(sync_finder, text)

        return async_safe_finditer

    async def batch_compile(
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
                compiled_patterns[pattern] = await self.compile_pattern(pattern)
            except re.error:
                continue
        return compiled_patterns

    async def clear_cache(self) -> None:
        async with self._lock:
            self._compiled_cache.clear()
            self._cache_order.clear()
