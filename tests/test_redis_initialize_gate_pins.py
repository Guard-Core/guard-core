from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL


def manager_with_gate(*, connected: bool, enters: bool, recovers: bool) -> RedisManager:
    manager = RedisManager(SecurityConfig(enable_redis=True, redis_url=REDIS_URL))
    manager._redis = MagicMock() if connected else None
    gate = SimpleNamespace(enter=lambda: enters, leave=lambda _connected: recovers)
    vars(manager)["_reconnect_gate_of_this_manager"] = gate
    return manager


@pytest.mark.asyncio
async def test_a_refused_reconnect_is_a_503_connection_failed() -> None:
    manager = manager_with_gate(connected=False, enters=False, recovers=False)
    with pytest.raises(GuardRedisError) as refused:
        await manager.initialize()
    assert refused.value.status_code == 503
    assert refused.value.detail == "Redis connection failed"


@pytest.mark.asyncio
async def test_an_initialize_on_a_connected_manager_reports_no_recovery() -> None:
    manager = manager_with_gate(connected=True, enters=True, recovers=True)
    sent = AsyncMock()
    with (
        patch.object(manager, "_open_connection", AsyncMock()),
        patch.object(manager, "_send_redis_event", sent),
    ):
        await manager.initialize()
    sent.assert_not_called()


@pytest.mark.asyncio
async def test_the_first_success_after_failures_reports_the_recovery() -> None:
    manager = manager_with_gate(connected=False, enters=True, recovers=True)

    async def connect(_url: str) -> None:
        manager._redis = MagicMock()

    sent = AsyncMock()
    with (
        patch.object(manager, "_open_connection", connect),
        patch.object(manager, "_send_redis_event", sent),
    ):
        await manager.initialize()
    sent.assert_awaited_once()
    assert sent.await_args is not None
    assert sent.await_args.kwargs["action_taken"] == "connection_recovered"
    assert (
        sent.await_args.kwargs["reason"]
        == "Redis connection recovered after failed attempts"
    )


@pytest.mark.asyncio
async def test_an_operation_that_returns_nothing_reads_as_false_zero_or_empty() -> None:
    manager = RedisManager(SecurityConfig(enable_redis=True, redis_url=REDIS_URL))
    with patch.object(manager, "safe_operation", AsyncMock(return_value=None)):
        assert await manager.set_key("ns", "k", "v") is False
        assert await manager.exists("ns", "k") is False
        assert await manager.incr("ns", "k") == 0
        assert await manager.delete("ns", "k") == 0
        assert await manager.delete_pattern("ns:*") == 0
        assert await manager.keys("ns:*") == []
        assert await manager.record_sliding_window_hit("ns", "k", 2.0, 1.0, 5) == 0


@pytest.mark.asyncio
async def test_set_key_if_absent_is_true_only_when_the_write_took_place() -> None:
    configured = RedisManager(SecurityConfig(enable_redis=True, redis_url=REDIS_URL))
    with patch.object(configured, "safe_operation", AsyncMock(return_value=True)):
        assert await configured.set_key_if_absent("ns", "k", "v") is True
    unconfigured = RedisManager(SecurityConfig(enable_redis=False))
    assert await unconfigured.set_key_if_absent("ns", "k", "v") is False


@pytest.mark.asyncio
async def test_get_many_without_redis_answers_one_none_per_pair() -> None:
    unconfigured = RedisManager(SecurityConfig(enable_redis=False))
    assert await unconfigured.get_many([("a", "1"), ("b", "2")]) == [None, None]
