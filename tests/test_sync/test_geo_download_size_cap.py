import time
from collections.abc import Generator
from pathlib import Path

import pytest

from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from tests.geo_fixture import (
    GeoDownloadServer,
    country_database_bytes,
    database_server,
    declared_length_server,
    fast_endless_server,
    gzip_inflating_server,
)

CAP = 262144
TOTAL_BOUND = 2.0
KEPT_DATABASE = b"the previous database"
SIZE_CAP_LOG = "guard_core.sync.handlers.ipinfo"


@pytest.fixture(autouse=True)
def _bounded_downloads(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[None, None, None]:
    IPInfoManager._instance = None

    def no_sleep(self: IPInfoManager, seconds: float) -> None:
        return None

    monkeypatch.setattr(IPInfoManager, "_sleep", no_sleep)
    monkeypatch.setattr(IPInfoManager, "_download_total_timeout", TOTAL_BOUND)
    yield
    IPInfoManager._instance = None


def _manager(server: GeoDownloadServer, tmp_path: Path, cap: int) -> IPInfoManager:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")
    manager._download_url = server.url
    manager._download_max_bytes = cap
    manager.db_path.write_bytes(KEPT_DATABASE)
    return manager


def _fails_over_the_cap(manager: IPInfoManager) -> tuple[str, float]:
    started = time.monotonic()
    with pytest.raises(TimeoutError) as failure:
        manager._fetch_and_store_database()
    elapsed = time.monotonic() - started
    assert manager.db_path.read_bytes() == KEPT_DATABASE
    return str(failure.value), elapsed


def test_the_shipped_size_cap_is_128_mib() -> None:
    assert IPInfoManager._download_max_bytes == 134217728


@pytest.mark.parametrize("chunked", [False, True])
def test_a_fast_endless_body_ends_at_the_cap_well_before_the_total_bound(
    chunked: bool, tmp_path: Path
) -> None:
    with fast_endless_server(chunked) as server:
        message, elapsed = _fails_over_the_cap(_manager(server, tmp_path, CAP))

    assert str(CAP) in message
    assert elapsed < TOTAL_BOUND / 2
    assert server.attempts == 3


def test_a_small_gzip_body_that_inflates_past_the_cap_ends_at_the_cap(
    tmp_path: Path,
) -> None:
    with gzip_inflating_server(64 * CAP) as server:
        message, elapsed = _fails_over_the_cap(_manager(server, tmp_path, CAP))

    assert str(CAP) in message
    assert elapsed < TOTAL_BOUND / 2
    assert server.attempts == 3


def test_a_two_layer_gzip_body_that_inflates_past_the_cap_never_gets_past_it(
    tmp_path: Path,
) -> None:
    # urllib3 decodes both layers and the count ends the body at the cap
    # (TimeoutError); aiohttp decodes none of "gzip, gzip", so the small raw body
    # arrives and fails validation (ValueError). Neither inflates past the cap.
    with gzip_inflating_server(64 * CAP, layers=2) as server:
        manager = _manager(server, tmp_path, CAP)
        started = time.monotonic()
        with pytest.raises((TimeoutError, ValueError)) as failure:
            manager._fetch_and_store_database()
        elapsed = time.monotonic() - started

    assert manager.db_path.read_bytes() == KEPT_DATABASE
    assert elapsed < TOTAL_BOUND / 2
    assert isinstance(failure.value, ValueError) or str(CAP) in str(failure.value)


def test_a_body_exactly_at_the_cap_succeeds(tmp_path: Path) -> None:
    body = country_database_bytes("CN")
    with database_server(body) as server:
        manager = _manager(server, tmp_path, len(body))
        manager._fetch_and_store_database()

    assert manager.db_path.read_bytes() == body
    assert server.attempts == 1


def test_a_body_one_byte_over_the_cap_is_never_written(
    tmp_path: Path,
) -> None:
    body = country_database_bytes("CN")
    with database_server(body) as server:
        message, _ = _fails_over_the_cap(_manager(server, tmp_path, len(body) - 1))

    assert str(len(body) - 1) in message
    assert server.attempts == 3


def test_a_content_length_over_the_cap_fails_before_the_body_is_read(
    tmp_path: Path,
) -> None:
    with declared_length_server(declared=CAP + 1, sent=16) as server:
        message, elapsed = _fails_over_the_cap(_manager(server, tmp_path, CAP))

    assert f"declares {CAP + 1} bytes" in message
    assert elapsed < TOTAL_BOUND / 2


def test_hitting_the_cap_logs_an_error_naming_the_cap_the_size_and_the_setting(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with declared_length_server(declared=CAP + 1, sent=16) as server:
        manager = _manager(server, tmp_path, CAP)
        with caplog.at_level("ERROR", logger=SIZE_CAP_LOG):
            _fails_over_the_cap(manager)

    errors = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert len(errors) == 3
    assert all(
        str(CAP) in line and str(CAP + 1) in line and "_download_max_bytes" in line
        for line in errors
    )


def test_the_streaming_count_logs_the_received_bytes_when_the_cap_is_hit(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with fast_endless_server(chunked=True) as server:
        manager = _manager(server, tmp_path, CAP)
        with caplog.at_level("ERROR", logger=SIZE_CAP_LOG):
            _fails_over_the_cap(manager)

    line = caplog.records[0].getMessage()
    assert str(CAP) in line
    assert "_download_max_bytes" in line
    assert "has sent at least" in line
