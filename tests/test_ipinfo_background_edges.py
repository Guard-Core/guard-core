import logging
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from guard_core.handlers.ipinfo_handler import IPInfoManager


@pytest.fixture
def manager(tmp_path: Path) -> Generator[IPInfoManager, None, None]:
    IPInfoManager._instance = None
    instance = IPInfoManager("token", tmp_path / "country_asn.mmdb")
    yield instance
    instance._cancel_staleness_timer()
    IPInfoManager._instance = None


def _redis(**operations: Any) -> AsyncMock:
    redis = AsyncMock()
    for name, outcome in operations.items():
        setattr(redis, name, outcome)
    return redis


async def test_a_load_that_cannot_be_scheduled_is_logged_and_not_left_in_flight(
    manager: IPInfoManager, caplog: pytest.LogCaptureFixture
) -> None:
    def refuse(coroutine: Any) -> None:
        coroutine.close()
        raise RuntimeError("no running loop")

    with (
        patch("asyncio.create_task", side_effect=refuse),
        patch("threading.Thread.start", side_effect=RuntimeError("no thread")),
        caplog.at_level(logging.ERROR, logger="guard_core.handlers.ipinfo"),
    ):
        manager.schedule_database_load()

    assert manager._background_in_flight is False
    assert any("Could not schedule" in message for message in caplog.messages)


async def test_a_background_load_that_raises_is_logged_and_released(
    manager: IPInfoManager, caplog: pytest.LogCaptureFixture
) -> None:
    manager._background_in_flight = True

    with (
        caplog.at_level(logging.ERROR, logger="guard_core.handlers.ipinfo"),
    ):
        await manager._load_in_background(AsyncMock(side_effect=RuntimeError("x")))

    assert manager._background_in_flight is False
    assert any("Background GeoIP database load failed" in m for m in caplog.messages)


def test_the_staleness_timer_is_not_armed_without_a_database_file(
    manager: IPInfoManager,
) -> None:
    manager._arm_staleness_timer()

    assert manager._staleness_timer is None


async def test_a_redis_copy_that_does_not_open_is_dropped(
    manager: IPInfoManager,
) -> None:
    redis = _redis(get_key=AsyncMock(return_value=b"copy"), delete=AsyncMock())
    manager.redis_handler = redis

    with (
        patch.object(manager, "_write_database_atomically"),
        patch.object(manager, "_open_database_or_none", return_value=None),
    ):
        assert await manager._adopt_redis_copy() is False

    redis.delete.assert_awaited_once_with("ipinfo", "database")


async def test_a_failed_drop_of_a_cached_database_is_logged(
    manager: IPInfoManager, caplog: pytest.LogCaptureFixture
) -> None:
    redis = _redis(delete=AsyncMock(side_effect=RuntimeError("down")))

    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.ipinfo"):
        await manager._drop_cached_database(redis)

    assert any("could not be dropped" in message for message in caplog.messages)


async def test_an_unavailable_download_lock_lets_the_download_run(
    manager: IPInfoManager, caplog: pytest.LogCaptureFixture
) -> None:
    manager.redis_handler = _redis(
        set_key_if_absent=AsyncMock(side_effect=RuntimeError("down"))
    )

    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.ipinfo"):
        assert await manager._claim_download_lock() is True

    assert any("lock unavailable" in message for message in caplog.messages)


async def test_a_lock_that_cannot_be_released_is_logged(
    manager: IPInfoManager, caplog: pytest.LogCaptureFixture
) -> None:
    manager.redis_handler = _redis(
        set_key_if_absent=AsyncMock(return_value=True),
        get_key=AsyncMock(side_effect=lambda *_: manager._download_lock_token),
        delete=AsyncMock(side_effect=RuntimeError("down")),
    )

    with (
        patch.object(manager, "_fetch_and_store_database", AsyncMock()),
        caplog.at_level(logging.WARNING, logger="guard_core.handlers.ipinfo"),
    ):
        await manager._download_database()

    assert any("lock not released" in message for message in caplog.messages)
