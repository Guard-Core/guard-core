from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from tests.geo_fixture import CLIENT_IP, country_database_bytes


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


def _manager_with_cached_copy(tmp_path: Path, cached: bytes) -> IPInfoManager:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "db.mmdb")
    manager.redis_handler = Mock()
    manager.redis_handler.get_key = MagicMock(return_value=cached)
    manager.redis_handler.delete = MagicMock(return_value=1)
    return manager


def test_a_corrupt_cached_database_is_dropped_and_downloaded_again(
    tmp_path: Path,
) -> None:
    manager = _manager_with_cached_copy(tmp_path, b"not a database")
    good_copy = country_database_bytes("CN")

    def download() -> None:
        manager._write_database_atomically(good_copy)

    with patch.object(manager, "_download_database", download):
        manager.initialize()

    assert manager.is_initialized
    assert manager.get_country(CLIENT_IP) == "CN"
    manager.redis_handler.delete.assert_called_once_with("ipinfo", "database")


def test_a_valid_cached_database_is_used_without_a_download(
    tmp_path: Path,
) -> None:
    manager = _manager_with_cached_copy(
        tmp_path, country_database_bytes("CN").decode("latin-1")
    )
    download = MagicMock()

    with patch.object(manager, "_download_database", download):
        manager.initialize()

    assert manager.get_country(CLIENT_IP) == "CN"
    download.assert_not_called()
    manager.redis_handler.delete.assert_not_called()
