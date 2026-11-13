"""The sync tree shares one client across threads; the loop-parking of the async tree
still runs here when a client is recorded under a loop that is alive."""

import asyncio
from collections.abc import Iterator
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.conftest import REDIS_URL


@pytest.fixture
def manager() -> Iterator[RedisManager]:
    yield RedisManager(
        SyncSecurityConfig(
            enable_redis=True, redis_url=REDIS_URL, redis_prefix="wp781syncparked:"
        )
    )


@pytest.fixture
def live_loop() -> Iterator[asyncio.AbstractEventLoop]:
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


def test_a_client_of_a_live_loop_is_parked_not_closed_and_close_releases_it(
    manager: RedisManager, live_loop: asyncio.AbstractEventLoop
) -> None:
    manager.initialize()
    first = manager._redis
    assert first is not None
    manager._client_loop = live_loop
    second = MagicMock()

    assert manager._swap_client(second, None, None) == (None, None, None)

    assert manager._redis is second
    assert manager._parked_clients()[live_loop][0] is first
    assert manager.is_connected_on_this_loop() is True
    assert manager.is_connected() is True
    manager._client_loop = live_loop
    assert manager.is_connected_on_this_loop() is False
    manager.close()
    assert manager._parked_clients() == {}
    assert manager.is_connected() is False


def test_a_parked_client_recorded_for_this_thread_is_adopted_by_a_connect(
    manager: RedisManager,
) -> None:
    manager.initialize()
    parked = manager._redis
    assert parked is not None
    key = manager._pool_key
    manager._redis = None
    manager._parked_clients()[None] = (parked, key)

    manager.initialize()

    assert manager._redis is parked
    assert manager._parked_clients() == {}
    manager.close()
