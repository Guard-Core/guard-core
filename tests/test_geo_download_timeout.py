import time
from collections.abc import Generator
from pathlib import Path

import pytest

from guard_core._utils.access_control import check_ip_country
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.models import SecurityConfig
from tests.geo_fixture import (
    CLIENT_IP,
    GeoDownloadServer,
    endless_server,
    silent_server,
    stalls_once_server,
    trickles_then_delays_server,
    trickling_server,
)

SHIPPED_BOUNDS = (
    IPInfoManager._download_connect_timeout,
    IPInfoManager._download_read_timeout,
    IPInfoManager._download_total_timeout,
)
READ_BOUND = 0.4
TOTAL_BOUND = 1.0


@pytest.fixture(autouse=True)
def _bounded_downloads(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[None, None, None]:
    IPInfoManager._instance = None

    async def no_sleep(self: IPInfoManager, seconds: float) -> None:
        return None

    monkeypatch.setattr(IPInfoManager, "_sleep", no_sleep)
    monkeypatch.setattr(IPInfoManager, "_download_connect_timeout", READ_BOUND)
    monkeypatch.setattr(IPInfoManager, "_download_read_timeout", READ_BOUND)
    monkeypatch.setattr(IPInfoManager, "_download_total_timeout", TOTAL_BOUND)
    yield
    IPInfoManager._instance = None


def _manager_downloading_from(
    server: GeoDownloadServer, tmp_path: Path
) -> IPInfoManager:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")
    manager._download_url = server.url
    return manager


def _blocking(manager: IPInfoManager) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        ipinfo_token="tok",
        ipinfo_db_path=manager.db_path,
        blocked_countries=["CN"],
    )


def _allow_list(manager: IPInfoManager) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        ipinfo_token="tok",
        ipinfo_db_path=manager.db_path,
        whitelist_countries=["CN"],
    )


async def test_a_silent_server_ends_each_attempt_at_the_idle_bound_on_a_cold_request(
    tmp_path: Path,
) -> None:
    with silent_server() as server:
        manager = _manager_downloading_from(server, tmp_path)
        started = time.monotonic()
        denied = await check_ip_country(CLIENT_IP, _allow_list(manager), manager)
        elapsed = time.monotonic() - started
        allowed = await check_ip_country(CLIENT_IP, _blocking(manager), manager)

    assert server.attempts == 3
    assert 3 * READ_BOUND <= elapsed < 3 * READ_BOUND + 1.0
    assert denied is True
    assert allowed is False
    assert manager.reader is None


async def test_a_silent_server_ends_each_attempt_at_the_idle_bound_at_startup(
    tmp_path: Path,
) -> None:
    with silent_server() as server:
        manager = _manager_downloading_from(server, tmp_path)
        started = time.monotonic()
        await manager.initialize()
        elapsed = time.monotonic() - started
        denied = await check_ip_country(CLIENT_IP, _allow_list(manager), manager)
        allowed = await check_ip_country(CLIENT_IP, _blocking(manager), manager)

    assert server.attempts == 3
    assert 3 * READ_BOUND <= elapsed < 3 * READ_BOUND + 1.0
    assert denied is True
    assert allowed is False


async def test_a_download_with_gaps_under_the_idle_bound_completes_and_is_enforced(
    tmp_path: Path,
) -> None:
    with trickling_server(gap=0.15, pieces=4) as server:
        manager = _manager_downloading_from(server, tmp_path)
        started = time.monotonic()
        blocked = await check_ip_country(CLIENT_IP, _blocking(manager), manager)
        elapsed = time.monotonic() - started

    assert elapsed > READ_BOUND
    assert server.attempts == 1
    assert blocked is True
    assert manager.reader is not None


async def test_a_stall_past_the_idle_bound_is_retried_and_the_load_gets_a_reader(
    tmp_path: Path,
) -> None:
    with stalls_once_server() as server:
        manager = _manager_downloading_from(server, tmp_path)
        blocked = await check_ip_country(CLIENT_IP, _blocking(manager), manager)

    assert server.attempts == 2
    assert blocked is True
    assert manager.reader is not None


async def test_chunks_with_short_gaps_that_never_finish_end_at_the_total_bound(
    tmp_path: Path,
) -> None:
    with endless_server(gap=0.1) as server:
        manager = _manager_downloading_from(server, tmp_path)
        started = time.monotonic()
        denied = await check_ip_country(CLIENT_IP, _allow_list(manager), manager)
        elapsed = time.monotonic() - started

    assert server.attempts == 3
    assert 3 * TOTAL_BOUND <= elapsed < 3 * TOTAL_BOUND + 1.5
    assert denied is True
    assert manager.reader is None


async def test_gaps_just_under_the_idle_bound_end_each_attempt_at_the_total_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(IPInfoManager, "_download_read_timeout", 0.45)
    with endless_server(gap=0.4) as server:
        manager = _manager_downloading_from(server, tmp_path)
        started = time.monotonic()
        denied = await check_ip_country(CLIENT_IP, _allow_list(manager), manager)
        elapsed = time.monotonic() - started

    assert server.attempts == 3
    assert 3 * TOTAL_BOUND <= elapsed < 3 * TOTAL_BOUND + 0.3
    assert denied is True


async def test_a_retry_after_a_total_cut_starts_with_the_full_idle_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(IPInfoManager, "_download_read_timeout", 0.45)
    with trickles_then_delays_server(gap=0.4, delay=0.35) as server:
        manager = _manager_downloading_from(server, tmp_path)
        blocked = await check_ip_country(CLIENT_IP, _blocking(manager), manager)

    assert server.attempts == 2
    assert blocked is True
    assert manager.reader is not None


async def test_a_listener_that_never_answers_the_tls_hello_ends_at_the_connect_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(IPInfoManager, "_download_read_timeout", 3.0)
    with silent_server() as server:
        manager = _manager_downloading_from(server, tmp_path)
        manager._download_url = server.url.replace("http://", "https://")
        started = time.monotonic()
        denied = await check_ip_country(CLIENT_IP, _allow_list(manager), manager)
        elapsed = time.monotonic() - started

    assert server.attempts == 3
    assert 3 * READ_BOUND <= elapsed < 3 * READ_BOUND + 0.6
    assert denied is True


def test_the_shipped_download_bounds_are_30_30_and_300() -> None:
    assert SHIPPED_BOUNDS == (30, 30, 300)


async def test_a_fast_endless_body_ends_each_attempt_at_the_total_bound(
    tmp_path: Path,
) -> None:
    with endless_server(gap=0.0) as server:
        manager = _manager_downloading_from(server, tmp_path)
        started = time.monotonic()
        denied = await check_ip_country(CLIENT_IP, _allow_list(manager), manager)
        elapsed = time.monotonic() - started

    assert server.attempts == 3
    assert 3 * TOTAL_BOUND <= elapsed < 3 * TOTAL_BOUND + 0.3
    assert denied is True
