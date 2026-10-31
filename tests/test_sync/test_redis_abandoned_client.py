import asyncio
from collections.abc import Iterator

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.conftest import REDIS_URL


@pytest.fixture
def manager() -> Iterator[RedisManager]:
    config = SyncSecurityConfig(
        enable_redis=True, redis_url=REDIS_URL, redis_prefix="wp336syncabandon:"
    )
    yield RedisManager(config)


def test_a_sync_client_recorded_under_another_loop_is_closed_in_place(
    manager: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager.initialize()
    old_client = manager._redis
    assert old_client is not None
    other_loop = asyncio.new_event_loop()
    other_loop.close()
    manager._client_loop = other_loop
    real_close = old_client.close
    closed: list[bool] = []

    def close_and_record() -> None:
        closed.append(True)
        real_close()

    monkeypatch.setattr(old_client, "close", close_and_record)

    manager.initialize()

    assert closed == [True]
    assert manager._redis is not old_client
    manager.close()
