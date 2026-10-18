import sys
import threading

from guard_core.sync.handlers import ratelimit_handler as ratelimit_handler_module
from guard_core.sync.handlers.ratelimit_handler import (
    RateLimitTier,
    _in_memory_tier_verdict,
)


def test_by_ip_dedicated_store_evict_and_append_is_atomic_under_the_lock() -> None:
    """Proves the dedicated store's evict-then-append sequence is atomic.

    CPython's GIL makes a hard, deterministic lock-vs-no-lock split
    unreachable: individual deque ops (popleft/append/len) are already
    atomic, so a naive "count total appends across N calls with no eviction"
    test passes identically whether the lock is held or not, it never
    exercises the actual race window. The real race is in the *compound*
    eviction loop: `while dq and dq[0] <= window_start: dq.popleft()`
    decides to pop based on a snapshot of `dq[0]`, then calls `popleft()`
    a moment later. Without the lock, another thread can drain the deque
    in between, so the pending `popleft()` fires against whatever is now
    at the front, including a different thread's freshly appended (and
    definitely not expired) entry, or an already-empty deque
    (`IndexError`).

    This test forces that window: pre-seed the store with only long-expired
    entries, then have every thread run one evict-and-append call with a
    window that makes only the pre-seeded entries stale and every thread's
    own append fresh (`current_time` far above `window_start`, so no
    thread's own append can ever legitimately be evicted, by itself or by
    any other thread). Under the lock the surviving count is exactly
    `threads_count`, deterministically. `sys.setswitchinterval` is dropped
    to force frequent context switches, this does not make CPython's
    scheduling a test-controllable contract, so the outcome isn't
    provable-deterministic without the lock either, but it reproduces the
    race reliably at this thread/entry count.

    Verified locally (20/20 trials each): with the lock, every trial
    surfaces exactly `threads_count` surviving entries; with the lock
    swapped for a no-op, trials undercount (fresh entries wrongly evicted)
    and one trial raised `IndexError: pop from an empty deque` outright.
    """
    threads_count = 32
    stale_entries = 200
    key = "203.0.113.14"
    tiers = [RateLimitTier("global", 1_000_000, 999)]

    store = ratelimit_handler_module._by_ip_request_timestamps
    lock = ratelimit_handler_module._by_ip_lock
    store.pop(key, None)
    store[key].extend(0.0 for _ in range(stale_entries))

    errors: list[BaseException] = []
    barrier = threading.Barrier(threads_count)

    def worker(i: int) -> None:
        try:
            barrier.wait()
            _in_memory_tier_verdict(store, key, tiers, 1000.0 + i, lock)
        except (IndexError, RuntimeError) as e:
            errors.append(e)

    previous_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        threads = [
            threading.Thread(target=worker, args=(i,)) for i in range(threads_count)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(previous_interval)

    assert errors == [], f"unexpected concurrency errors: {errors}"
    assert len(store[key]) == threads_count
