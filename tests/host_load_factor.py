from collections.abc import Callable
from typing import TypeVar

from guard_core.detection_engine._redos_cost_arbiter import _measure_host_load_factor

_T = TypeVar("_T")


def host_load_factor() -> float:
    return max(_measure_host_load_factor(), 1.0)


def run_with_host_load_factor(run: Callable[[], _T]) -> tuple[_T, float]:
    before = host_load_factor()
    result = run()
    return result, max(before, host_load_factor())
