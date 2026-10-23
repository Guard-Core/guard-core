import threading

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers import ratelimit_handler
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager, RateLimitTier

THREADS = 16
LIMIT = 10
ATTEMPTS_PER_THREAD = 5


def _config() -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        rate_limit=LIMIT,
        rate_limit_window=60,
    )


def test_threads_asking_for_one_config_at_once_get_one_state() -> None:
    config = _config()
    barrier = threading.Barrier(THREADS)
    managers: list[RateLimitManager] = []

    def build() -> None:
        barrier.wait()
        managers.append(RateLimitManager(config))

    threads = [threading.Thread(target=build) for _ in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(managers) == THREADS
    assert len({id(manager) for manager in managers}) == 1
    assert ratelimit_handler._managers[(RateLimitManager, id(config))] is managers[0]


def test_threads_share_one_window_through_their_own_managers() -> None:
    config = _config()
    barrier = threading.Barrier(THREADS)
    allowed: list[bool] = []
    tier = RateLimitTier("global", LIMIT, 60)

    def hit() -> None:
        manager = RateLimitManager(config)
        barrier.wait()
        for _ in range(ATTEMPTS_PER_THREAD):
            verdict = manager._tier_verdict("203.0.113.9", [tier], config)
            allowed.append(verdict.tier_index is None)

    threads = [threading.Thread(target=hit) for _ in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(allowed) == THREADS * ATTEMPTS_PER_THREAD
    assert allowed.count(True) == LIMIT
