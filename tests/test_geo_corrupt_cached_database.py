from collections.abc import Generator
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from guard_core.handlers.ipinfo_handler import IPInfoManager
from tests.geo_fixture import CLIENT_IP, country_database_bytes


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


def _manager_with_cached_copy(
    tmp_path: Path, cached: bytes | str
) -> tuple[IPInfoManager, Mock]:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "db.mmdb")
    redis = Mock()
    redis.get_key = AsyncMock(return_value=cached)
    redis.delete = AsyncMock(return_value=1)
    manager.redis_handler = redis
    return manager, redis


async def test_a_corrupt_cached_database_is_dropped_and_downloaded_again(
    tmp_path: Path,
) -> None:
    manager, redis = _manager_with_cached_copy(tmp_path, b"not a database")
    good_copy = country_database_bytes("CN")

    async def download() -> None:
        manager._write_database_atomically(good_copy)

    with patch.object(manager, "_download_database", download):
        await manager.initialize()

    assert manager.is_initialized
    assert manager.get_country(CLIENT_IP) == "CN"
    redis.delete.assert_awaited_once_with("ipinfo", "database")


async def test_a_valid_cached_database_is_used_without_a_download(
    tmp_path: Path,
) -> None:
    manager, redis = _manager_with_cached_copy(
        tmp_path, country_database_bytes("CN").decode("latin-1")
    )
    download = AsyncMock()

    with patch.object(manager, "_download_database", download):
        await manager.initialize()

    assert manager.get_country(CLIENT_IP) == "CN"
    download.assert_not_awaited()
    redis.delete.assert_not_awaited()
