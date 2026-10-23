import threading
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from guard_core.exceptions import GeoDatabaseLoadError
from guard_core.models import SyncSecurityConfig
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
    config = SyncSecurityConfig(
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


def test_concurrent_first_requests_all_fail_on_one_raising_load(
    tmp_path: Path,
) -> None:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")
    config = SyncSecurityConfig(
        enable_redis=False,
        ipinfo_token="tok",
        ipinfo_db_path=manager.db_path,
        blocked_countries=["CN"],
    )
    started, release = threading.Event(), threading.Event()
    loads: list[int] = []

    def raising_load() -> bool:
        loads.append(1)
        started.set()
        release.wait()
        raise OSError("disk gone")

    outcomes: list[BaseException | bool] = []

    def request() -> None:
        try:
            outcomes.append(check_ip_country(CLIENT_IP, config, manager))
        except GeoDatabaseLoadError as error:
            outcomes.append(error)

    with patch.object(
        manager, "_adopt_redis_copy", MagicMock(side_effect=raising_load)
    ):
        requests = [threading.Thread(target=request) for _ in range(5)]
        for thread in requests:
            thread.start()
        assert started.wait(timeout=5)
        release.set()
        for thread in requests:
            thread.join(timeout=5)

    assert [type(outcome) for outcome in outcomes] == [GeoDatabaseLoadError] * 5
    assert len({id(outcome) for outcome in outcomes}) == 5
    assert len(loads) == 1


def test_an_in_flight_retry_keeps_the_previous_failure_visible(
    tmp_path: Path,
) -> None:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")
    config = SyncSecurityConfig(
        enable_redis=False,
        ipinfo_token="tok",
        ipinfo_db_path=manager.db_path,
        blocked_countries=["CN"],
    )
    with patch.object(
        manager, "_adopt_redis_copy", MagicMock(side_effect=OSError("disk gone"))
    ):
        with pytest.raises(GeoDatabaseLoadError):
            check_ip_country(CLIENT_IP, config, manager)
    started, release = threading.Event(), threading.Event()

    def held_retry() -> None:
        started.set()
        release.wait()

    manager._last_attempt_at = None
    retry = manager._start_or_join_load(held_retry)
    assert started.wait(timeout=5)

    with pytest.raises(GeoDatabaseLoadError):
        manager._raise_last_load_error()
    release.set()
    retry.join(timeout=5)
    assert manager._last_load_error is None
