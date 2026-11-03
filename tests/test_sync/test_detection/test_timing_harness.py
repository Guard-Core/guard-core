import multiprocessing as mp
import time

import pytest

from tests.test_detection import test_builtin_pattern_safety as safety

# A worker that crashes or finishes ends the join at once, so this is only a guard
# against a true hang. A short one lets a loaded host's slow forkserver start
# pass for "still running", which the harness reports as None, not as a crash.
_HANG_GUARD_SECONDS = 600.0


@pytest.mark.parametrize("worker", ["raw", "windowed", "scan_window"])
def test_timing_worker_crash_cannot_report_success(worker: str) -> None:
    with pytest.raises(RuntimeError, match="timing worker exited with code"):
        if worker == "raw":
            safety._timed_batch("[", ["payload"], timeout=_HANG_GUARD_SECONDS)
        elif worker == "windowed":
            safety._timed_windowed_batch(
                "not-a-registered-pattern", ["payload"], _HANG_GUARD_SECONDS
            )
        else:
            safety._timed_scan_window_batch(
                "not-a-matcher", "a", ["payload"], _HANG_GUARD_SECONDS
            )


def _exit_without_result() -> None:
    return


def test_clean_worker_exit_without_result_cannot_report_success() -> None:
    context = mp.get_context("forkserver")
    queue: mp.Queue[list[float]] = context.Queue()
    process = context.Process(target=_exit_without_result)
    with pytest.raises(RuntimeError, match="without reporting a result"):
        safety._collect_child_result(process, queue, timeout=_HANG_GUARD_SECONDS)


def test_timed_out_worker_is_reaped() -> None:
    context = mp.get_context("forkserver")
    queue: mp.Queue[list[float]] = context.Queue()
    process = context.Process(target=time.sleep, args=(60.0,))
    started = time.monotonic()
    assert safety._collect_child_result(process, queue, timeout=0.1) is None
    assert time.monotonic() - started < 10.0
    assert process not in mp.active_children()


def test_successful_worker_returns_every_measurement() -> None:
    measurements = safety._timed_batch("a+", ["aaaa", "b"], timeout=_HANG_GUARD_SECONDS)
    assert measurements is not None
    assert len(measurements) == 2
    assert all(measurement >= 0.0 for measurement in measurements)
