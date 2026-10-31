import concurrent.futures
import threading

import pytest

from guard_core.sync.detection_engine import compiler


def test_a_forked_child_forgets_the_parents_pool_counts_and_locks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parents_pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    held_by_another_thread = threading.Lock()
    held_by_another_thread.acquire()
    monkeypatch.setattr(compiler, "_shared_executor", parents_pool)
    monkeypatch.setattr(compiler, "_consecutive_timeouts", 3)
    monkeypatch.setattr(compiler, "_executor_lock", held_by_another_thread)
    monkeypatch.setattr(compiler, "_timeout_lock", held_by_another_thread)

    compiler._forget_the_parents_workers()

    assert compiler._shared_executor is None
    assert compiler._consecutive_timeouts == 0
    assert compiler._executor_lock is not held_by_another_thread
    assert compiler._timeout_lock is not held_by_another_thread
    assert not compiler._executor_lock.locked()
    assert not compiler._timeout_lock.locked()
    assert compiler.shared_regex_executor().submit(lambda: 7).result(timeout=5) == 7
    parents_pool.shutdown()
    held_by_another_thread.release()
