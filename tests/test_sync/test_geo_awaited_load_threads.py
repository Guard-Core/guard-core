import threading
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync._utils.access_control import check_ip_country
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from tests.geo_fixture import CLIENT_IP, country_database_bytes


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


def test_concurrent_first_requests_join_one_load_without_a_timeout(
    tmp_path: Path,
) -> None:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")
    config = SecurityConfig(
        enable_redis=False,
        ipinfo_token="tok",
        ipinfo_db_path=manager.db_path,
        blocked_countries=["CN"],
    )
    started, release = threading.Event(), threading.Event()
    downloads: list[int] = []

    def download() -> None:
        downloads.append(1)
        started.set()
        release.wait()
        manager.db_path.write_bytes(country_database_bytes("CN"))

    verdicts: list[bool] = []

    def request() -> None:
        verdicts.append(check_ip_country(CLIENT_IP, config, manager))

    with patch.object(manager, "_download_database", MagicMock(side_effect=download)):
        requests = [threading.Thread(target=request) for _ in range(5)]
        for thread in requests:
            thread.start()
        assert started.wait(timeout=5)
        release.set()
        for thread in requests:
            thread.join(timeout=5)

    assert verdicts == [True] * 5
    assert len(downloads) == 1
