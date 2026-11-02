import re
import time
from collections.abc import Callable
from typing import TypeVar

from guard_core.sync.detection_engine._redos_cost_arbiter import (
    _LOAD_FACTOR_CEILING,
    _REFERENCE_SCAN_PATTERN,
    _REFERENCE_SCAN_PROBE_LENGTH,
    _REFERENCE_SCAN_SECONDS,
)

_REFERENCE = re.compile(_REFERENCE_SCAN_PATTERN)
_REFERENCE_TEXT = "/" + "0" * _REFERENCE_SCAN_PROBE_LENGTH
_REFERENCE_SAMPLES = 3
_T = TypeVar("_T")


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
    factor = local_load_factor()
    start = time.process_time()
    result = run()
    return result, (time.process_time() - start) / factor
