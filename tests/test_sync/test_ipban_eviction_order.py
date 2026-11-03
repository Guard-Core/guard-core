import logging
import time
from collections.abc import Generator
from typing import Any, cast
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.sync.handlers._ipban_cache import _BanStore
from guard_core.sync.handlers.ipban_handler import IPBanManager
from tests.test_sync.fake_agent import mock_agent


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


def _manager(maxsize: int) -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.agent_handler = Mock(send_event=MagicMock())
    manager.banned_ips = _BanStore(maxsize=maxsize, on_evict=manager._on_eviction)
    return manager


def _events(manager: IPBanManager) -> list[Any]:
    sent = [
        call.args[0]
        for call in mock_agent(manager.agent_handler).send_event.call_args_list
    ]
    return [event for event in sent if event.event_type == "ip_ban_evicted"]


def test_the_default_store_holds_one_hundred_thousand_bans() -> None:
    store = cast(_BanStore, IPBanManager().banned_ips)

    assert store.maxsize == 100_000


def test_the_ban_closest_to_expiry_is_evicted_first() -> None:
    manager = _manager(maxsize=3)
    manager.ban_ip("8.8.0.1", duration=3600, reason="t")
    manager.ban_ip("8.8.0.2", duration=60, reason="t")
    manager.ban_ip("8.8.0.3", duration=7200, reason="t")

    manager.ban_ip("8.8.0.4", duration=3600, reason="t")

    assert manager.is_ip_banned("8.8.0.2") is False
    for survivor in ("8.8.0.1", "8.8.0.3", "8.8.0.4"):
        assert manager.is_ip_banned(survivor) is True


def test_an_expired_ban_makes_room_without_counting_as_an_eviction() -> None:
    manager = _manager(maxsize=2)
    manager.banned_ips["8.8.0.1"] = time.time() - 10
    manager.ban_ip("8.8.0.2", duration=600, reason="t")

    manager.ban_ip("8.8.0.3", duration=600, reason="t")

    assert manager.evictions_count == 0
    assert _events(manager) == []


def test_evicting_unexpired_bans_sends_every_event_and_samples_the_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager(maxsize=1)
    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")

    for index in range(102):
        manager.ban_ip(f"8.8.{index // 256}.{index % 256}", 600 + index, "t")

    assert manager.evictions_count == 101
    assert len([r for r in caplog.records if "evicted" in r.getMessage()]) == 2
    events = _events(manager)
    assert len(events) == 101
    first, hundredth = events[0], events[99]
    assert first.event_type == "ip_ban_evicted"
    assert first.action_taken == "ban_evicted"
    assert first.metadata["evictions"] == 1
    assert first.ip_address == "8.8.0.0"
    assert hundredth.metadata["evictions"] == 100
    assert hundredth.metadata["remaining_seconds"] > 0
    assert hundredth.ip_address == "8.8.0.99"
