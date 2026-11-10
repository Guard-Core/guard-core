from collections.abc import Generator, Iterator
from contextlib import contextmanager

import pytest
from redis import Redis

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler
from guard_core.sync.handlers.redis_handler import RedisManager, close_redis_client
from tests.test_sync.conftest import REDIS_URL, suite_redis_prefix

PREFIX = suite_redis_prefix("wp537keys")


class NoKeysConnection:
    def __init__(self, conn: Redis) -> None:
        self._conn = conn

    def keys(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("the engine issued KEYS on the shared Redis")

    def __getattr__(self, name: str) -> object:
        return getattr(self._conn, name)


def _clear(client: Redis) -> None:
    for key in [k for k in client.scan_iter(match=f"{PREFIX}*")]:
        client.delete(key)


def _remaining(client: Redis) -> list[str]:
    return sorted([k for k in client.scan_iter(match=f"{PREFIX}*")])


@pytest.fixture
def conn() -> Generator[Redis, None]:
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    _clear(client)
    yield client
    _clear(client)
    close_redis_client(client)


@pytest.fixture
def manager(conn: Redis, monkeypatch: pytest.MonkeyPatch) -> RedisManager:
    redis_manager = RedisManager(
        SyncSecurityConfig(enable_redis=True, redis_url=REDIS_URL, redis_prefix=PREFIX)
    )

    @contextmanager
    def no_keys_connection() -> Iterator[NoKeysConnection]:
        yield NoKeysConnection(conn)

    monkeypatch.setattr(redis_manager, "get_connection", no_keys_connection)
    return redis_manager


def test_delete_pattern_removes_the_matches_with_scan_and_never_keys(
    conn: Redis, manager: RedisManager
) -> None:
    conn.set(f"{PREFIX}rate_limit:rate:a", "1")
    conn.set(f"{PREFIX}other:keep", "1")

    assert manager.delete_pattern("rate_limit:rate:*") == 1

    assert _remaining(conn) == [f"{PREFIX}other:keep"]


def test_the_rate_limit_reset_clears_its_windows_with_scan_and_never_keys(
    conn: Redis, manager: RedisManager
) -> None:
    config = SyncSecurityConfig(
        enable_redis=True, redis_url=REDIS_URL, redis_prefix=PREFIX, rate_limit=2
    )
    limiter = rate_limit_handler(config)
    limiter.initialize_redis(manager)
    conn.set(f"{PREFIX}rate_limit:rate:1.2.3.4", "1")
    conn.set(f"{PREFIX}other:keep", "1")

    limiter.reset()

    assert _remaining(conn) == [f"{PREFIX}other:keep"]


def test_the_ip_ban_reset_clears_its_bans_with_scan_and_never_keys(
    conn: Redis, manager: RedisManager
) -> None:
    bans = IPBanManager()
    bans.redis_handler = manager
    conn.set(f"{PREFIX}banned_ips:1.2.3.4", "1")
    conn.set(f"{PREFIX}other:keep", "1")

    bans.reset()

    left = _remaining(conn)
    assert f"{PREFIX}other:keep" in left
    assert f"{PREFIX}banned_ips:1.2.3.4" not in left
