import logging
import warnings

import pytest
from redis import Connection, ConnectionPool, Redis

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers import redis_handler
from guard_core.sync.handlers.redis_handler import (
    _build_redis_client,
    _redis_over_owned_pool,
    close_redis_client,
    scan_unlink_through_new_client,
)
from tests.test_sync.conftest import REDIS_URL

POOL_SIZE = 2
TIMEOUT = 0.4


class _OnlyClose(Redis):
    """A client of a redis-py before 5.0.1: ``close`` closes it, there is no
    ``aclose``, and ``close`` drops the pool the client owns."""

    def __getattribute__(self, name: str) -> object:
        if name == "aclose":
            raise AttributeError(name)
        return super().__getattribute__(name)

    def close(self) -> None:
        # __getattribute__ is typed object, which hides the attribute types from mypy
        pool: ConnectionPool = object.__getattribute__(self, "connection_pool")
        pool.disconnect()


def _is_open(connection: object) -> bool:
    return any(getattr(connection, a, None) is not None for a in ("_sock", "_reader"))


def _connected(client: Redis) -> Connection:
    pool = client.connection_pool
    connection = pool.get_connection()
    pool.release(connection)
    assert _is_open(connection)
    return connection


def _close_only_client() -> Redis:
    pool = _build_redis_client(REDIS_URL, POOL_SIZE, TIMEOUT).connection_pool
    return _OnlyClose(connection_pool=pool)


def test_a_client_with_only_close_gets_its_connection_pool_disconnected() -> None:
    client = _close_only_client()
    connection = _connected(client)

    close_redis_client(client)

    assert not _is_open(connection)


def test_a_client_with_aclose_closes_without_a_deprecation_warning() -> None:
    client = _build_redis_client(REDIS_URL, POOL_SIZE, TIMEOUT)
    connection = _connected(client)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        close_redis_client(client)

    assert not _is_open(connection)


def test_the_safe_close_of_a_client_with_aclose_logs_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = _build_redis_client(REDIS_URL, POOL_SIZE, TIMEOUT)
    connection = _connected(client)
    manager = redis_handler.RedisManager(SyncSecurityConfig(enable_agent=False))

    with caplog.at_level(logging.WARNING), warnings.catch_warnings():
        warnings.simplefilter("error")
        manager._safe_aclose(client)

    assert not _is_open(connection)
    assert "Failed to close a Redis client" not in caplog.text


def test_the_scan_clear_through_a_new_client_closes_it_when_the_scan_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _close_only_client()
    connection = _connected(client)

    def failing_scan(*_args: object, **_kwargs: object) -> int:
        raise RuntimeError("the scan failed")

    monkeypatch.setattr(Redis, "from_url", classmethod(lambda cls, *a, **k: client))
    monkeypatch.setattr(redis_handler, "scan_unlink", failing_scan)

    with pytest.raises(RuntimeError, match="the scan failed"):
        scan_unlink_through_new_client(REDIS_URL, "wp381:*")

    assert not _is_open(connection)


def test_a_client_built_without_from_pool_still_owns_and_closes_its_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(Redis, "from_pool", raising=False)

    client = _build_redis_client(REDIS_URL, POOL_SIZE, TIMEOUT)
    connection = _connected(client)

    assert client.auto_close_connection_pool is True
    close_redis_client(client)
    assert not _is_open(connection)


def test_the_pool_owning_client_of_the_fallback_closes_its_pool() -> None:
    pool = _build_redis_client(REDIS_URL, POOL_SIZE, TIMEOUT).connection_pool
    client = _redis_over_owned_pool(pool)
    connection = _connected(client)

    assert client.auto_close_connection_pool is True
    close_redis_client(client)
    assert not _is_open(connection)
