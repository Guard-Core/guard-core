import logging
import time
from collections.abc import Generator

import pytest

from guard_core.handlers.ipban_handler import (
    IPBanManager,
    _ObservableTTLCache,
)


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


def _swap_in_small_cache(manager: IPBanManager, maxsize: int) -> None:
    manager.banned_ips = _ObservableTTLCache(
        maxsize=maxsize,
        ttl=manager.LOCAL_CACHE_TTL_CAP_SECONDS,
        on_evict=manager._on_eviction,
    )


@pytest.mark.asyncio
async def test_banned_ips_overflow_increments_eviction_counter_and_logs_at_threshold(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    _swap_in_small_cache(manager, maxsize=2)

    caplog.set_level(logging.WARNING, logger="guard_core.handlers.ipban")

    await manager.ban_ip("8.8.0.1", duration=300, reason="t")
    await manager.ban_ip("8.8.0.2", duration=300, reason="t")
    await manager.ban_ip("8.8.0.3", duration=300, reason="t")

    assert manager.evictions_count == 1
    [first] = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert "1 entries evicted" in first.getMessage()

    for i in range(4, 103):
        await manager.ban_ip(f"8.8.{i // 256}.{i % 256}", duration=300, reason="t")

    assert manager.evictions_count == 100
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 2
    assert "100" in warnings[1].getMessage()
    assert "silent overflow" in warnings[1].getMessage()


@pytest.mark.asyncio
async def test_ttl_expiry_does_not_increment_eviction_counter() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips = _ObservableTTLCache(
        maxsize=10, ttl=1, on_evict=manager._on_eviction
    )

    await manager.ban_ip("10.0.0.1", duration=1, reason="t")
    await manager.ban_ip("10.0.0.2", duration=1, reason="t")

    time.sleep(1.1)

    await manager.ban_ip("10.0.0.3", duration=1, reason="t")

    assert manager.evictions_count == 0


@pytest.mark.asyncio
async def test_eviction_counter_persists_across_singleton_calls() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    _swap_in_small_cache(manager, maxsize=1)

    await manager.ban_ip("10.0.0.1", duration=300, reason="t")
    await manager.ban_ip("10.0.0.2", duration=300, reason="t")
    assert manager.evictions_count == 1

    second = IPBanManager()
    assert second is manager
    assert second.evictions_count == 1
