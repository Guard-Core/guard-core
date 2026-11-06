from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL


def manager_with_gate(*, connected: bool, enters: bool, recovers: bool) -> RedisManager:
    manager = RedisManager(SyncSecurityConfig(enable_redis=True, redis_url=REDIS_URL))
    manager._redis = MagicMock() if connected else None
    gate = SimpleNamespace(enter=lambda: enters, leave=lambda _connected: recovers)
    vars(manager)["_reconnect_gate_of_this_manager"] = gate
    return manager


def test_a_refused_reconnect_is_a_503_connection_failed() -> None:
    manager = manager_with_gate(connected=False, enters=False, recovers=False)
    with pytest.raises(GuardRedisError) as refused:
        manager.initialize()
    assert refused.value.status_code == 503
    assert refused.value.detail == "Redis connection failed"


def test_an_initialize_on_a_connected_manager_reports_no_recovery() -> None:
    manager = manager_with_gate(connected=True, enters=True, recovers=True)
    sent = MagicMock()
    with (
        patch.object(manager, "_open_connection", MagicMock()),
        patch.object(manager, "_send_redis_event", sent),
    ):
        manager.initialize()
    sent.assert_not_called()


def test_the_first_success_after_failures_reports_the_recovery() -> None:
    manager = manager_with_gate(connected=False, enters=True, recovers=True)

    def connect(_url: str) -> None:
        manager._redis = MagicMock()

    sent = MagicMock()
    with (
        patch.object(manager, "_open_connection", connect),
        patch.object(manager, "_send_redis_event", sent),
    ):
        manager.initialize()
    sent.assert_called_once()
    assert sent.call_args is not None
    assert sent.call_args.kwargs["action_taken"] == "connection_recovered"
    assert (
        sent.call_args.kwargs["reason"]
        == "Redis connection recovered after failed attempts"
    )


def test_an_operation_that_returns_nothing_reads_as_false_zero_or_empty() -> None:
    manager = RedisManager(SyncSecurityConfig(enable_redis=True, redis_url=REDIS_URL))
    with patch.object(manager, "safe_operation", MagicMock(return_value=None)):
        assert manager.set_key("ns", "k", "v") is False
        assert manager.exists("ns", "k") is False
        assert manager.incr("ns", "k") == 0
        assert manager.delete("ns", "k") == 0
        assert manager.delete_pattern("ns:*") == 0
        assert manager.keys("ns:*") == []
        assert manager.record_sliding_window_hit("ns", "k", 2.0, 1.0, 5) == 0


def test_set_key_if_absent_is_true_only_when_the_write_took_place() -> None:
    configured = RedisManager(
        SyncSecurityConfig(enable_redis=True, redis_url=REDIS_URL)
    )
    with patch.object(configured, "safe_operation", MagicMock(return_value=True)):
        assert configured.set_key_if_absent("ns", "k", "v") is True
    unconfigured = RedisManager(SyncSecurityConfig(enable_redis=False))
    assert unconfigured.set_key_if_absent("ns", "k", "v") is False


def test_get_many_without_redis_answers_one_none_per_pair() -> None:
    unconfigured = RedisManager(SyncSecurityConfig(enable_redis=False))
    assert unconfigured.get_many([("a", "1"), ("b", "2")]) == [None, None]
