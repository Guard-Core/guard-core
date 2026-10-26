import re
import time
from typing import Any

from guard_core._utils._scan_outcomes import (
    SCAN_OUTCOME_QUEUE_WAIT,
    SCAN_OUTCOME_RUN_TIMEOUT,
)
from guard_core._utils.detection_scan import (
    _record_scan_time,
    _scan_cpu_reached,
    _suspended,
    _timed_in_worker,
)


async def _worker_finditer(
    compiler: Any, pattern: re.Pattern, content: str
) -> tuple[list[re.Match], str | None]:
    worker_cpu: list[float] = []
    outcome: list[str] = []
    finder = compiler.create_async_safe_finditer_matcher(
        pattern,
        inline_safe=False,
        worker_wrapper=lambda work: _timed_in_worker(work, worker_cpu),
        outcome=outcome,
    )
    matches: list[re.Match] = await _suspended(finder(content))
    if outcome[:1] != [SCAN_OUTCOME_QUEUE_WAIT]:
        _record_scan_time(sum(worker_cpu) if worker_cpu else compiler.default_timeout)
    return matches, outcome[0] if outcome else None


async def _compiler_finditer(
    compiler: Any,
    pattern: re.Pattern,
    category: str,
    content: str,
    pattern_start: float,
) -> tuple[list[re.Match], str | None]:
    if category == "custom":
        return await _worker_finditer(compiler, pattern, content)
    finder = compiler.create_async_safe_finditer_matcher(pattern, inline_safe=True)
    found: list[re.Match] = await finder(content)
    budget = 0.9 * compiler.default_timeout
    late = time.monotonic() - pattern_start >= budget and _scan_cpu_reached(budget)
    return found, SCAN_OUTCOME_RUN_TIMEOUT if late and not found else None
