"""LEDGER 1.49: pins for the redis_handler.py mutants no other test reaches (class
defaults, the connect bookkeeping, the refusal status and text, the operation name
a failed get_key reports, and the zero a count or an unconfigured Redis answers)."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.handlers._background_stop import BackgroundUsers
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix

_CONFIG_DEFAULT_PROBE = (
    "from guard_core.handlers.redis_handler import RedisManager\n"
    "print(type(RedisManager.config).__name__)"
)


def _live_manager(tag: str) -> RedisManager:
    return RedisManager(
        SecurityConfig(
            enable_redis=True, redis_url=REDIS_URL, redis_prefix=suite_redis_prefix(tag)
        )
    )


def _unconfigured_manager() -> RedisManager:
    return RedisManager(SecurityConfig(enable_redis=False))


def test_a_manager_class_is_not_degraded_and_has_connected_never() -> None:
    assert RedisManager._degraded is False
    assert RedisManager._connect_generation == 0


def test_a_fresh_manager_class_holds_its_config_through_the_weakable_descriptor() -> (
    None
):
    # A fresh interpreter, run from the repo root: other tests leave the class slot
    # replaced by a descriptor of their own, which would mask a changed default.
    result = subprocess.run(
        [sys.executable, "-c", _CONFIG_DEFAULT_PROBE],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
        cwd=Path(__file__).resolve().parents[1],
    )

    assert result.stdout.split() == ["WeakableConfig"]


async def test_a_degraded_manager_refuses_initialize_with_503_and_the_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _live_manager("degraded-refusal")
    manager._degraded = True
    monkeypatch.setattr(manager, "_start_the_attempt_if_the_window_is_open", Mock())

    with pytest.raises(GuardRedisError) as raised:
        await manager.initialize()

    assert raised.value.status_code == 503
    assert raised.value.detail == "Redis connection failed"


async def test_a_checkout_that_leaves_no_client_is_refused_with_503_and_the_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _live_manager("no-client")
    monkeypatch.setattr(manager, "initialize", AsyncMock())

    with pytest.raises(GuardRedisError) as raised:
        async with manager.get_connection():
            raise AssertionError("the body must not run")

    assert raised.value.status_code == 503
    assert raised.value.detail == "Redis connection failed"


async def test_each_connect_counts_once_and_clears_the_degraded_flag() -> None:
    manager = _live_manager("generation")
    manager._degraded = True
    try:
        await manager._open_connection(REDIS_URL)
        assert manager._degraded is False
        assert manager._connect_generation == 1
        await manager._open_connection(REDIS_URL)
        assert manager._connect_generation == 2
    finally:
        await manager.close()


async def test_close_clears_the_degraded_flag_to_false() -> None:
    manager = _live_manager("close-degraded")
    manager._degraded = True

    await manager.close()

    assert manager._degraded is False


def test_the_background_users_are_kept_in_the_manager_under_their_own_name() -> None:
    manager = _live_manager("background-users")

    users = manager._background_user_set()

    assert isinstance(users, BackgroundUsers)
    assert vars(manager)["_background_users"] is users
    assert manager._background_user_set() is users


async def test_a_failed_get_key_reports_the_get_operation_by_name() -> None:
    manager = _live_manager("get-key-name")
    agent = AsyncMock()
    manager.agent_handler = agent
    client = Mock()
    client.get = AsyncMock(side_effect=RuntimeError("boom"))
    manager._redis = client

    with pytest.raises(GuardRedisError):
        await manager.get_key("ns", "k")

    event = agent.send_event.call_args[0][0]
    assert event.metadata["function_name"] == "_get"


async def test_an_unconfigured_redis_records_no_hit_and_counts_zero() -> None:
    manager = _unconfigured_manager()

    recorded = await manager.record_sliding_window_hit("ns", "k", 10.0, 1.0, 60)
    counted = await manager.count_sliding_window_hits("ns", "k", 1.0)
    summed = await manager.sum_indexed_window_hits("ns", "index", 1.0)

    assert (recorded, counted, summed) == (0, 0, 0)


async def test_a_count_and_a_sum_without_a_reply_are_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _live_manager("no-reply")
    monkeypatch.setattr(manager, "safe_operation", AsyncMock(return_value=None))

    counted = await manager.count_sliding_window_hits("ns", "k", 1.0)
    summed = await manager.sum_indexed_window_hits("ns", "index", 1.0)

    assert (counted, summed) == (0, 0)
