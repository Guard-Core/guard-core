import re
import time
from collections.abc import Callable
from typing import TypeVar

from guard_core.detection_engine._redos_cost_arbiter import (
    _LOAD_FACTOR_CEILING,
    _REFERENCE_SCAN_PATTERN,
    _REFERENCE_SCAN_PROBE_LENGTH,
    _REFERENCE_SCAN_SECONDS,
)

_REFERENCE = re.compile(_REFERENCE_SCAN_PATTERN)
_REFERENCE_TEXT = "/" + "0" * _REFERENCE_SCAN_PROBE_LENGTH
_REFERENCE_SAMPLES = 3
_T = TypeVar("_T")
_fastest_factor = float("inf")


def _reference_scan_seconds() -> float:
    best = float("inf")
    for _ in range(_REFERENCE_SAMPLES):
        start = time.process_time()
        _REFERENCE.search(_REFERENCE_TEXT)
        best = min(best, time.process_time() - start)
    return best


def local_load_factor() -> float:
    return min(
        max(_reference_scan_seconds() / _REFERENCE_SCAN_SECONDS, 1.0),
        _LOAD_FACTOR_CEILING,
    )


def timed_normalized(run: Callable[[], _T]) -> tuple[_T, float]:
    # The factor is the lowest reference reading of this process so far: a reading
    # inflated by noise or by a core change never over-divides a later sample, and a
    # sample that ran on a slower core is left slow, which the callers' minimum
    # statistics absorb. A per-sample factor made the growth checks fail in the loaded
    # cell (LEDGER 6.505).
    global _fastest_factor
    _fastest_factor = min(_fastest_factor, local_load_factor())
    start = time.process_time()
    result = run()
    return result, (time.process_time() - start) / _fastest_factor
