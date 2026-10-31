import threading
from collections.abc import Iterator

import pytest

from guard_core._redis_client_loop import running_loop_or_none
from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.conftest import REDIS_URL


@pytest.fixture
def manager() -> Iterator[RedisManager]:
    config = SyncSecurityConfig(
        enable_redis=True, redis_url=REDIS_URL, redis_prefix="wp313syncloop:"
    )
    yield RedisManager(config)


def test_the_sync_tree_has_no_loop_so_a_client_serves_every_thread(
    manager: RedisManager,
) -> None:
    manager.initialize()
    manager.set_key("loop", "k", "v", ttl=30)
    client = manager._redis
    answers: list[str | None] = []

    worker = threading.Thread(
        target=lambda: answers.append(manager.get_key("loop", "k"))
    )
    worker.start()
    worker.join(timeout=30)

    assert running_loop_or_none() is None
    assert manager._client_loop is None
    assert answers == ["v"]
    assert manager._redis is client
