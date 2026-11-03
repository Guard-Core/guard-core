import logging
import time
from collections.abc import Generator
from unittest.mock import AsyncMock, patch

import pytest

from guard_core.handlers.ipban_handler import IPBanManager
from tests.fake_agent import redis_slot

LONG_BAN = 86_400


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


async def test_a_ban_longer_than_an_hour_keeps_its_whole_duration_in_memory(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    caplog.set_level(logging.WARNING, logger="guard_core.handlers.ipban")

    await manager.ban_ip("8.8.8.7", duration=LONG_BAN, reason="test")

    assert manager.banned_ips["8.8.8.7"] == pytest.approx(time.time() + LONG_BAN, abs=2)
    assert not [r for r in caplog.records if r.levelno == logging.WARNING]


async def test_a_long_ban_is_still_enforced_after_the_old_one_hour_cap() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    start = time.time()
    await manager.ban_ip("8.8.8.8", duration=LONG_BAN, reason="test")

    with patch("time.time", return_value=start + 7200):
        assert await manager.is_ip_banned("8.8.8.8") is True
    with patch("time.time", return_value=start + LONG_BAN + 5):
        assert await manager.is_ip_banned("8.8.8.8") is False


async def test_a_cidr_ban_longer_than_an_hour_keeps_its_whole_duration() -> None:
    manager = IPBanManager()
    manager.redis_handler = None

    await manager.ban_ip("8.8.9.0/24", duration=LONG_BAN, reason="test")

    [(network, expiry)] = manager.banned_networks
    assert str(network) == "8.8.9.0/24"
    assert expiry == pytest.approx(time.time() + LONG_BAN, abs=2)


async def test_a_redis_write_failure_keeps_the_whole_duration_in_this_process(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = redis_slot(
        AsyncMock(
            spec=["set_key"], set_key=AsyncMock(side_effect=ConnectionError("down"))
        )
    )
    caplog.set_level(logging.WARNING, logger="guard_core.handlers.ipban")

    await manager.ban_ip("8.8.8.9", duration=LONG_BAN, reason="test")
    await manager.ban_ip("8.8.10.0/24", duration=LONG_BAN, reason="test")

    assert manager.banned_ips["8.8.8.9"] == pytest.approx(time.time() + LONG_BAN, abs=2)
    [(_, expiry)] = manager.banned_networks
    assert expiry == pytest.approx(time.time() + LONG_BAN, abs=2)
    messages = [r.getMessage() for r in caplog.records]
    assert all("shortened" not in message for message in messages)
    assert sum("this process only" in message for message in messages) == 2


async def test_an_expired_ban_is_not_enforced_and_is_forgotten() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    await manager.ban_ip("8.8.8.10", duration=60, reason="test")

    with patch("time.time", return_value=time.time() + 120):
        assert await manager.is_ip_banned("8.8.8.10") is False

    assert "8.8.8.10" not in manager.banned_ips
