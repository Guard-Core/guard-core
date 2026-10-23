import threading
import time

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker


def test_concurrent_writers_and_readers_do_not_raise() -> None:
    config = SyncSecurityConfig()
    tracker = BehaviorTracker(config)
    rule = BehaviorRule(rule_type="usage", threshold=1_000_000, window=60)
    errors: list[BaseException] = []
    stop = threading.Event()

    def writer(worker_id: int) -> None:
        try:
            i = 0
            while not stop.is_set():
                tracker.track_endpoint_usage(
                    f"endpoint-{worker_id}-{i % 50}",
                    f"10.0.{worker_id}.{i % 20}",
                    rule,
                )
                i += 1
        except BaseException as e:
            errors.append(e)

    def reader() -> None:
        try:
            while not stop.is_set():
                tracker.get_recent_event_count("10.0.0.1", 60)
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(w,)) for w in range(6)]
    threads += [threading.Thread(target=reader) for _ in range(2)]
    for t in threads:
        t.start()
    time.sleep(2)
    stop.set()
    for t in threads:
        t.join()

    assert errors == [], f"unexpected concurrency errors: {errors}"
