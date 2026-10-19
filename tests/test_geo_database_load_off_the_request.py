import asyncio
from collections.abc import Generator
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from guard_core._utils.access_control import check_ip_country
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.models import SecurityConfig


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False, ipinfo_token="tok", whitelist_countries=["US"]
    )


async def _finish_background_load(manager: IPInfoManager) -> None:
    task = getattr(manager, "_background_task", None)
    if task is not None:
        await asyncio.wait_for(task, timeout=5)


async def test_a_missing_database_is_downloaded_once_per_backoff_window(
    tmp_path: Path,
) -> None:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "missing.mmdb")
    download = AsyncMock(side_effect=RuntimeError("network down"))

    with patch.object(manager, "_download_database", download):
        for _ in range(5):
            await check_ip_country("203.0.113.5", _config(), manager)
            await _finish_background_load(manager)

    assert download.await_count == 1


async def test_a_first_request_waits_for_the_download(tmp_path: Path) -> None:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "missing.mmdb")
    finished: list[bool] = []

    async def slow_download() -> None:
        await asyncio.sleep(0.3)
        finished.append(True)
        raise RuntimeError("network down")

    with patch.object(manager, "_download_database", slow_download):
        blocked = await check_ip_country("203.0.113.5", _config(), manager)
        finished_before_the_answer = bool(finished)
        await _finish_background_load(manager)

    assert blocked is True
    assert finished_before_the_answer is True
    assert finished == [True]


async def test_the_download_is_retried_after_the_backoff_window(
    tmp_path: Path,
) -> None:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "missing.mmdb")
    manager._RETRY_BACKOFF_SECONDS = 0.0
    download = AsyncMock(side_effect=RuntimeError("network down"))

    with patch.object(manager, "_download_database", download):
        for _ in range(3):
            await check_ip_country("203.0.113.5", _config(), manager)
            await _finish_background_load(manager)

    assert download.await_count == 3
