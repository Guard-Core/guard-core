from collections.abc import Generator, Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from redis import Redis

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.cloud_ip_stores import RedisCloudIpStore
from guard_core.sync.handlers.redis_handler import RedisManager, close_redis_client
from tests.test_sync.conftest import REDIS_URL, suite_redis_prefix

PREFIX = suite_redis_prefix("wp16cloud")


class NoKeysConnection:
    def __init__(self, conn: Redis) -> None:
        self._conn = conn

    def keys(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the cloud store issued KEYS on the shared Redis")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


def _clear(client: Redis) -> None:
    for key in [k for k in client.scan_iter(match=f"{PREFIX}*")]:
        client.delete(key)


@pytest.fixture
def conn() -> Generator[Redis, None]:
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    _clear(client)
    yield client
    _clear(client)
    close_redis_client(client)


def test_the_redis_cloud_store_clear_lists_its_keys_with_scan(
    conn: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = RedisManager(
        SyncSecurityConfig(enable_redis=True, redis_url=REDIS_URL, redis_prefix=PREFIX)
    )

    @contextmanager
    def no_keys_connection() -> Iterator[NoKeysConnection]:
        yield NoKeysConnection(conn)

    monkeypatch.setattr(manager, "get_connection", no_keys_connection)
    store = RedisCloudIpStore(manager)
    store.set("AWS", {"10.0.0.0/8"})
    store.set("GCP", {"192.0.2.0/24"})
    conn.set(f"{PREFIX}other:keep", "1")

    store.clear()

    left = sorted([k for k in conn.scan_iter(match=f"{PREFIX}*")])
    assert left == [f"{PREFIX}other:keep"]
