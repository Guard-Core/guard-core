import os
import time
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from tests.geo_fixture import country_database_bytes


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


VALID_DB = country_database_bytes("CN")


def test_ipinfo_max_age_default_86400(tmp_path: Path) -> None:
    mgr = IPInfoManager(token="tok", db_path=tmp_path / "db.mmdb")
    assert mgr._max_age == 86400


def test_ipinfo_max_age_configurable(tmp_path: Path) -> None:
    mgr = IPInfoManager(token="tok", db_path=tmp_path / "db.mmdb", max_age=7200)
    assert mgr._max_age == 7200


def test_ipinfo_is_db_outdated_uses_max_age(tmp_path: Path) -> None:
    db_path = tmp_path / "db.mmdb"
    db_path.write_bytes(VALID_DB)
    mgr = IPInfoManager(token="tok", db_path=db_path, max_age=60)
    assert mgr._is_db_outdated() is False
    old = time.time() - 120
    os.utime(db_path, (old, old))
    assert mgr._is_db_outdated() is True


def test_ipinfo_refresh_redownloads_and_swaps_the_reader(tmp_path: Path) -> None:
    db_path = tmp_path / "db.mmdb"
    mgr = IPInfoManager(token="tok", db_path=db_path)
    old_reader = Mock()
    mgr.reader = old_reader
    new_reader = Mock()

    def fake_download() -> None:
        db_path.write_bytes(b"placeholder")

    with (
        patch.object(
            mgr, "_download_database", side_effect=fake_download
        ) as mock_download,
        patch(
            "maxminddb.open_database",
            return_value=new_reader,
        ),
    ):
        mgr.refresh()

    mock_download.assert_called_once()
    assert mgr.reader is new_reader
    old_reader.close.assert_not_called()


def test_ipinfo_refresh_opens_database_when_download_succeeds(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "db.mmdb"
    mgr = IPInfoManager(token="tok", db_path=db_path)
    mgr.reader = None

    def fake_download() -> None:
        db_path.write_bytes(b"placeholder")

    fake_reader = object()

    with (
        patch.object(mgr, "close"),
        patch.object(mgr, "_download_database", side_effect=fake_download),
        patch(
            "maxminddb.open_database",
            return_value=fake_reader,
        ),
    ):
        mgr.refresh()

    assert mgr.reader is fake_reader


def test_ipinfo_refresh_logs_and_returns_when_download_fails(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "db.mmdb"
    mgr = IPInfoManager(token="tok", db_path=db_path)
    mgr.reader = None
    error_messages: list[str] = []

    def capture_error(msg: str) -> None:
        error_messages.append(msg)

    with (
        patch.object(mgr, "close"),
        patch.object(mgr, "_download_database") as mock_download,
        patch.object(mgr.logger, "error", side_effect=capture_error),
    ):
        mock_download.side_effect = RuntimeError("network down")
        mgr.refresh()

    assert mgr.reader is None
    assert any("RuntimeError" in m for m in error_messages)
    assert not any("network down" in m for m in error_messages)


def test_ipinfo_download_database_uses_configured_ttl(tmp_path: Path) -> None:
    mgr = IPInfoManager(token="tok", db_path=tmp_path / "db.mmdb", max_age=7200)
    mgr.redis_handler = MagicMock()
    mgr.redis_handler.set_key = MagicMock()

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.content = VALID_DB
    mock_response.__enter__ = MagicMock(return_value=mock_response)
    mock_response.__exit__ = MagicMock(return_value=None)
    mock_response.raw.read1 = MagicMock(side_effect=[VALID_DB, b""])

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_response)
    mock_session.__enter__ = MagicMock(return_value=mock_session)
    mock_session.__exit__ = MagicMock(return_value=None)

    with patch(
        "requests.Session",
        return_value=mock_session,
    ):
        mgr._download_database()

    mgr.redis_handler.set_key.assert_called_once()
    call = mgr.redis_handler.set_key.call_args_list[0]
    assert call.kwargs["ttl"] == 7200
