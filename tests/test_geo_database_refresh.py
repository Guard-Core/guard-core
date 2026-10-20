import asyncio
import os
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.protocols.redis_protocol import RedisHandlerProtocol
from tests.geo_fixture import CLIENT_IP, country_database_bytes
from tests.mock_download import streamed


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


class _SharedRedis:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], Any] = {}

    async def get_key(self, namespace: str, key: str) -> Any:
        return self.values.get((namespace, key))

    async def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool:
        self.values[(namespace, key)] = value
        return True

    async def set_key_if_absent(
        self, namespace: str, key: str, value: Any, ttl: int
    ) -> bool:
        if (namespace, key) in self.values:
            return False
        self.values[(namespace, key)] = value
        return True

    async def delete(self, namespace: str, key: str) -> int:
        return int(self.values.pop((namespace, key), None) is not None)


def _manager_with_database(tmp_path: Path, country: str = "CN") -> IPInfoManager:
    db_path = tmp_path / "db.mmdb"
    db_path.write_bytes(country_database_bytes(country))
    manager = IPInfoManager(token="tok", db_path=db_path, max_age=3600)
    manager._apply_opened_reader(manager._open_database_or_none())
    return manager


def _response_with(content: bytes) -> MagicMock:
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.content_length = None
    mock_response.content.iter_chunked = streamed(content)
    mock_session = MagicMock()
    mock_session.get = AsyncMock(return_value=mock_response)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


async def test_a_garbage_download_never_replaces_the_working_database(
    tmp_path: Path,
) -> None:
    manager = _manager_with_database(tmp_path)
    working_copy = manager.db_path.read_bytes()

    with (
        patch(
            "aiohttp.ClientSession",
            return_value=_response_with(b"<html>rate limited</html>"),
        ),
        patch.object(manager, "_sleep", AsyncMock()),
    ):
        await manager.refresh()

    assert manager.db_path.read_bytes() == working_copy
    assert manager.get_country(CLIENT_IP) == "CN"


async def test_a_good_download_is_swapped_in_without_closing_the_old_reader(
    tmp_path: Path,
) -> None:
    manager = _manager_with_database(tmp_path, "CN")
    old_reader = Mock(wraps=manager.reader)
    manager.reader = old_reader

    with patch(
        "aiohttp.ClientSession",
        return_value=_response_with(country_database_bytes("US")),
    ):
        await manager.refresh()

    assert manager.get_country(CLIENT_IP) == "US"
    old_reader.close.assert_not_called()


async def test_a_worker_leaves_the_download_to_the_one_holding_the_lock(
    tmp_path: Path,
) -> None:
    redis = _SharedRedis()
    redis.values[("ipinfo", "download_lock")] = "1"
    manager = IPInfoManager(token="tok", db_path=tmp_path / "db.mmdb")
    manager.redis_handler = cast(RedisHandlerProtocol, redis)
    session_factory = MagicMock(
        return_value=_response_with(country_database_bytes("US"))
    )

    with patch("aiohttp.ClientSession", session_factory):
        await manager.initialize()

        assert not manager.is_initialized
        session_factory.assert_not_called()

        redis.values[("ipinfo", "database")] = country_database_bytes("US").decode(
            "latin-1"
        )
        del redis.values[("ipinfo", "download_lock")]
        await manager.initialize()

    session_factory.assert_not_called()
    assert manager.get_country(CLIENT_IP) == "US"


async def test_the_download_lock_is_released_after_a_download(tmp_path: Path) -> None:
    redis = _SharedRedis()
    manager = IPInfoManager(token="tok", db_path=tmp_path / "db.mmdb")
    manager.redis_handler = cast(RedisHandlerProtocol, redis)

    with patch(
        "aiohttp.ClientSession",
        return_value=_response_with(country_database_bytes("US")),
    ):
        await manager.initialize()

    assert ("ipinfo", "download_lock") not in redis.values
    assert manager.get_country(CLIENT_IP) == "US"


async def test_a_refresh_uses_the_redis_copy_before_downloading(
    tmp_path: Path,
) -> None:
    manager = _manager_with_database(tmp_path, "CN")
    redis = _SharedRedis()
    redis.values[("ipinfo", "database")] = country_database_bytes("US").decode(
        "latin-1"
    )
    manager.redis_handler = cast(RedisHandlerProtocol, redis)
    download = AsyncMock()

    with patch.object(manager, "_download_database", download):
        await manager.refresh()

    download.assert_not_awaited()
    assert manager.get_country(CLIENT_IP) == "US"


async def test_a_database_past_geo_ip_db_max_age_is_refreshed_in_the_background(
    tmp_path: Path,
) -> None:
    manager = _manager_with_database(tmp_path, "CN")
    download = AsyncMock()

    with patch.object(manager, "_download_database", download):
        manager._mark_refresh_due()
        manager.get_country(CLIENT_IP)
        manager.get_country(CLIENT_IP)
        task = manager._background_task
        assert task is not None
        await asyncio.wait_for(task, timeout=5)
        manager.get_country(CLIENT_IP)

    assert download.await_count == 1


async def test_a_loaded_database_arms_the_staleness_timer_from_the_file_age(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "db.mmdb"
    db_path.write_bytes(country_database_bytes("CN"))
    two_hours_ago = time.time() - 7200
    os.utime(db_path, (two_hours_ago, two_hours_ago))
    manager = IPInfoManager(token="tok", db_path=db_path, max_age=86400)
    timer = Mock()

    with patch(
        "guard_core.handlers.ipinfo_handler.threading.Timer", return_value=timer
    ) as make_timer:
        manager._apply_opened_reader(manager._open_database_or_none())

    delay = make_timer.call_args.args[0]
    assert 86400 - 7200 - 5 <= delay <= 86400 - 7200 + 5
    timer.start.assert_called_once()


async def test_the_first_start_without_a_database_says_what_country_rules_do(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "missing.mmdb")

    with (
        patch.object(
            manager,
            "_download_database",
            AsyncMock(side_effect=RuntimeError("network down")),
        ),
        caplog.at_level("WARNING"),
    ):
        await manager.initialize()

    message = " ".join(record.message for record in caplog.records)
    assert "whitelist_countries denies" in message
    assert "blocked_countries allows" in message
