import threading
import time
from typing import Any
from unittest.mock import MagicMock

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ratelimit_handler import (
    RateLimitManager,
    RateLimitTier,
    RateLimitVerdict,
    _in_memory_tier_verdict,
)


def _fresh_manager(rate_limit: int = 5, rate_limit_window: int = 1) -> RateLimitManager:
    RateLimitManager._instance = None
    config = SecurityConfig(rate_limit=rate_limit, rate_limit_window=rate_limit_window)
    return RateLimitManager(config)


def test_lock_is_set_on_singleton() -> None:
    manager = _fresh_manager(rate_limit=10, rate_limit_window=60)
    assert hasattr(manager, "_lock")
    assert manager._lock is not None


def test_concurrent_eviction_and_append_does_not_raise() -> None:
    manager = _fresh_manager(rate_limit=5, rate_limit_window=1)
    manager.request_timestamps.clear()
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            for _ in range(500):
                _in_memory_tier_verdict(
                    manager.request_timestamps,
                    "10.0.0.2",
                    [RateLimitTier("global", 5, 1)],
                    time.time(),
                    manager._lock,
                )
        except RuntimeError as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"unexpected concurrency errors: {errors}"


def test_initialize_redis_no_enable_redis() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=False)
    manager = RateLimitManager(config)
    mock_redis = MagicMock()
    manager.initialize_redis(mock_redis)
    assert manager.redis_handler is mock_redis
    assert manager.rate_limit_script_sha is None


def test_tier_verdict_without_a_redis_handler_counts_in_memory() -> None:
    manager = _fresh_manager()
    manager.redis_handler = None
    verdict = manager._tier_verdict(
        "1.2.3.4", [RateLimitTier("global", 5, 60)], manager.config
    )
    assert verdict == RateLimitVerdict(None)
    assert len(manager.request_timestamps) == 1


def test_reset_redis_empty_keys() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=True)
    manager = RateLimitManager(config)
    mock_redis = MagicMock()
    mock_redis.keys.return_value = []
    manager.redis_handler = mock_redis
    manager.request_timestamps["1.2.3.4"].append(1.0)
    manager.reset()
    assert len(manager.request_timestamps) == 0
    mock_redis.delete_pattern.assert_not_called()


def test_reset_redis_none_keys() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=True)
    manager = RateLimitManager(config)
    mock_redis: Any = MagicMock()
    mock_redis.keys.return_value = None
    manager.redis_handler = mock_redis
    manager.reset()
    mock_redis.delete_pattern.assert_not_called()
