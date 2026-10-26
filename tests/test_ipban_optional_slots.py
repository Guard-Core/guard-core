import ipaddress
import logging
from collections.abc import Generator
from unittest.mock import AsyncMock

import pytest

from guard_core.handlers._ipban_lookup import PendingKeysRead
from guard_core.handlers.ipban_handler import IPBanManager

LOGGER = "guard_core.handlers.ipban"


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


def _read() -> PendingKeysRead:
    return PendingKeysRead("203.0.113.9", None, ipaddress.ip_address("203.0.113.9"))


async def test_the_redis_ban_key_read_without_a_redis_handler_bans_nothing() -> None:
    manager = IPBanManager()
    manager.redis_handler = None

    assert await manager.finish_ban_check(_read()) is False


async def test_the_redis_handler_the_values_came_from_is_required_to_settle_them() -> (
    None
):
    manager = IPBanManager()
    manager.redis_handler = None

    with pytest.raises(RuntimeError, match="needs the Redis handler"):
        await manager.decide_from_ban_values(
            [("banned_ips", "203.0.113.9")], ["1", None], 2.0
        )


async def test_recidive_escalation_without_a_config_raises_a_clear_error() -> None:
    manager = IPBanManager()
    manager.config = None

    with pytest.raises(RuntimeError, match="needs the app config"):
        await manager._escalated_ban_terms("banned_ips", "203.0.113.9", 60)
    with pytest.raises(RuntimeError, match="needs the app config"):
        await manager._record_recidive_ban("203.0.113.9", 60)


async def test_a_loopback_ban_is_not_enforced_without_a_config_and_says_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.config = None

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert manager._ban_stands_for("127.0.0.1", None) is False

    assert caplog.records == []


async def test_the_prefix_contract_is_not_checked_without_a_config() -> None:
    manager = IPBanManager()
    manager.config = None

    await manager.initialize_redis(AsyncMock())
