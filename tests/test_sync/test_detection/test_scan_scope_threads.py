import sys
import threading

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.penetration_detection import _configured_manager_and_scope
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_manager_for

REQUESTS_PER_THREAD = 5000


def _app(max_length: int) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=True,
        redis_prefix="scope-threads:",
        detection_max_content_length=max_length,
    )


def test_threads_of_two_apps_on_one_prefix_always_get_their_own_detection_state() -> (
    None
):
    first, second = _app(1000), _app(100000)
    assert sus_patterns_manager_for(first, bind=True) is sus_patterns_manager_for(
        second, bind=True
    )
    mismatches = [0, 0]

    def request_loop(index: int, config: SyncSecurityConfig) -> None:
        for _ in range(REQUESTS_PER_THREAD):
            _, scope = _configured_manager_and_scope(config)
            assert scope is not None
            preprocessor = scope.state.preprocessor
            assert preprocessor is not None
            if preprocessor.max_content_length != config.detection_max_content_length:
                mismatches[index] += 1

    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        threads = [
            threading.Thread(target=request_loop, args=(0, first)),
            threading.Thread(target=request_loop, args=(1, second)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        sys.setswitchinterval(previous)
    assert mismatches == [0, 0]
