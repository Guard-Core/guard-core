import asyncio
from collections.abc import AsyncIterator, Hashable, Iterator
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from redis.asyncio import Redis

from guard_core._redis_exceptions import RedisConnectionError
from guard_core.exceptions import GuardRedisError
from guard_core.handlers import _redis_shared_clients
from guard_core.handlers.redis_handler import (
    RedisHandlerBase,
    RedisManager,
    is_connected_redis_manager,
)
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL

KEY = "wp465c-open-connection-cleanup"


class _Owner:
    """A weak-referenceable stand-in for another manager holding the client."""


def _manager() -> RedisManager:
    return RedisManager(SecurityConfig(enable_redis=True, redis_url=REDIS_URL))


def _client(*, ping_fails: bool) -> MagicMock:
    client = MagicMock()
    client.ping = AsyncMock(
        side_effect=RedisConnectionError("down") if ping_fails else None
    )
    return client


@contextmanager
def _opening(
    client: MagicMock, *, key: Hashable | None, shared: bool
) -> Iterator[asyncio.AbstractEventLoop]:
    scope = asyncio.get_running_loop()
    opened = MagicMock(return_value=(client, key, scope, shared))
    try:
        with patch.object(_redis_shared_clients, "open_client", opened):
            yield scope
    finally:
        _redis_shared_clients._entries.pop(KEY, None)


async def test_a_failure_after_registering_keeps_a_client_another_holds() -> None:
    manager = _manager()
    client = _client(ping_fails=False)
    other_owner = _Owner()
    with _opening(client, key=KEY, shared=False):
        with (
            patch.object(
                manager,
                "_send_redis_event",
                AsyncMock(side_effect=[RuntimeError("boom"), None]),
            ),
            patch.object(manager, "_safe_aclose", AsyncMock()) as closed,
        ):
            real_register = _redis_shared_clients.register_client

            async def register_then_add_owner(
                owner: RedisManager, client: Redis, key: Hashable, scope: object
            ) -> Redis:
                published = await real_register(owner, client, key, scope)
                _redis_shared_clients.acquire(KEY, scope, other_owner)
                return published

            with patch.object(
                _redis_shared_clients, "register_client", register_then_add_owner
            ):
                with pytest.raises(GuardRedisError):
                    await manager._open_connection("redis://x")
    closed.assert_not_awaited()
    assert manager._redis is None


async def test_a_failed_ping_on_a_shared_client_keeps_it_for_its_other_owner() -> None:
    manager = _manager()
    client = _client(ping_fails=True)
    other_owner = _Owner()
    with _opening(client, key=KEY, shared=True) as scope:
        _redis_shared_clients.publish(KEY, scope, client, other_owner)
        _redis_shared_clients.acquire(KEY, scope, manager)
        with patch.object(manager, "_safe_aclose", AsyncMock()) as closed:
            with pytest.raises(GuardRedisError):
                await manager._open_connection("redis://x")
        closed.assert_not_awaited()
        assert set(_redis_shared_clients._entries[KEY].owners) == {other_owner}


async def test_a_failed_ping_on_the_last_owner_closes_the_shared_client() -> None:
    manager = _manager()
    client = _client(ping_fails=True)
    with _opening(client, key=KEY, shared=True) as scope:
        _redis_shared_clients.publish(KEY, scope, client, manager)
        with patch.object(manager, "_safe_aclose", AsyncMock()) as closed:
            with pytest.raises(GuardRedisError):
                await manager._open_connection("redis://x")
        closed.assert_awaited_once_with(client)
        assert KEY not in _redis_shared_clients._entries


async def test_an_unregistered_client_is_closed_whatever_the_registry_says() -> None:
    manager = _manager()
    client = _client(ping_fails=True)
    with _opening(client, key=KEY, shared=False):
        with (
            patch.object(_redis_shared_clients, "release", return_value=False),
            patch.object(manager, "_safe_aclose", AsyncMock()) as closed,
        ):
            with pytest.raises(GuardRedisError):
                await manager._open_connection("redis://x")
    closed.assert_awaited_once_with(client)


async def test_a_shared_client_without_a_key_is_closed_whatever_the_registry_says() -> (
    None
):
    manager = _manager()
    client = _client(ping_fails=True)
    with _opening(client, key=None, shared=True):
        with (
            patch.object(_redis_shared_clients, "release", return_value=False),
            patch.object(manager, "_safe_aclose", AsyncMock()) as closed,
        ):
            with pytest.raises(GuardRedisError):
                await manager._open_connection("redis://x")
    closed.assert_awaited_once_with(client)


async def test_record_detection_strikes_rejects_a_reply_that_misses_a_category() -> (
    None
):
    manager = _manager()
    with patch.object(manager, "safe_operation", AsyncMock(return_value=[1, 0, 5, 6])):
        with pytest.raises(ValueError, match="zip"):
            await manager.record_detection_strikes(
                "192.0.2.1", ("xss", "sqli", "rce"), 10.0, 1.0, 60, 100
            )


class _MatchRecordingConnection:
    def __init__(self) -> None:
        self.matches: list[object] = []

    async def scan_iter(
        self, match: object = None, count: int = 0
    ) -> AsyncIterator[str]:
        self.matches.append(match)
        for key in ("p:ns:a", "p:other:b"):
            yield key


async def test_keys_scans_only_the_prefixed_pattern() -> None:
    handler = RedisHandlerBase(
        SecurityConfig(enable_redis=True, redis_url="redis://x", redis_prefix="p:")
    )
    connection = _MatchRecordingConnection()
    handler._redis = MagicMock(scan_iter=connection.scan_iter)
    await handler.keys("ns:*")
    assert connection.matches == ["p:ns:*"]


def test_only_a_manager_holding_a_client_is_a_connected_redis_manager() -> None:
    manager = _manager()
    assert is_connected_redis_manager(manager) is False
    manager._redis = MagicMock()
    assert is_connected_redis_manager(manager) is True
    assert is_connected_redis_manager(MagicMock()) is False
