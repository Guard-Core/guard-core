import socket
import threading
import time
from collections.abc import Generator
from pathlib import Path
from typing import cast

import pytest
import requests
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.contrib import socks

from guard_core.models import SecurityConfig
from guard_core.sync._utils.access_control import check_ip_country
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from tests.geo_fixture import (
    CLIENT_IP,
    HOST,
    STALL_KINDS,
    close_delimited_prefix_server,
    connect_proxy_server,
    count_connections,
    make_tls_material,
    socks5_proxy_server,
    stalling_server,
    tls_server_context,
    trickles_then_delays_server,
    trickling_server,
)

READ_BOUND = 0.4
TOTAL_BOUND = 1.0
MARGIN = 0.5


@pytest.fixture(autouse=True)
def _bounded_downloads(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[None, None, None]:
    IPInfoManager._instance = None
    monkeypatch.setattr(IPInfoManager, "_sleep", lambda self, seconds: None)
    monkeypatch.setattr(IPInfoManager, "_download_connect_timeout", READ_BOUND)
    monkeypatch.setattr(IPInfoManager, "_download_read_timeout", READ_BOUND)
    monkeypatch.setattr(IPInfoManager, "_download_total_timeout", TOTAL_BOUND)
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    yield
    IPInfoManager._instance = None


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    return make_tls_material(tmp_path_factory.mktemp("geo-tls"))


@pytest.fixture
def trusted_tls(
    tls_material: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path]:
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tls_material[0]))
    return tls_material


def _manager(url: str, tmp_path: Path, retries: int = 1) -> IPInfoManager:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")
    manager._download_url = url
    manager._download_retries = retries
    return manager


def _seconds_until_the_attempt_fails(manager: IPInfoManager) -> float:
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        manager._fetch_and_store_database()
    return time.monotonic() - started


@pytest.mark.parametrize("tls", [False, True], ids=["plain", "tls"])
@pytest.mark.parametrize("keep_alive", [True, False], ids=["keep-alive", "close"])
@pytest.mark.parametrize("kind", STALL_KINDS)
def test_every_stall_ends_the_attempt_at_the_total_bound(
    kind: str,
    keep_alive: bool,
    tls: bool,
    trusted_tls: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    context = tls_server_context(*trusted_tls) if tls else None
    with stalling_server(kind, keep_alive, context) as server:
        url = server.url.replace("http://", "https://") if tls else server.url
        elapsed = _seconds_until_the_attempt_fails(_manager(url, tmp_path))

    assert TOTAL_BOUND <= elapsed < TOTAL_BOUND + MARGIN
    assert not (tmp_path / "geo.mmdb").exists()


def test_a_cut_close_delimited_body_is_never_written_as_the_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(IPInfoManager, "_download_read_timeout", 3.0)
    with close_delimited_prefix_server() as server:
        elapsed = _seconds_until_the_attempt_fails(_manager(server.url, tmp_path))

    assert TOTAL_BOUND <= elapsed < TOTAL_BOUND + MARGIN
    assert not (tmp_path / "geo.mmdb").exists()


@pytest.mark.parametrize("keep_alive", [True, False], ids=["keep-alive", "close"])
def test_a_silent_body_ends_each_attempt_at_the_idle_bound(
    keep_alive: bool, tmp_path: Path
) -> None:
    with stalling_server("idle", keep_alive) as server:
        manager = _manager(server.url, tmp_path, retries=3)
        config = SecurityConfig(
            enable_redis=False,
            ipinfo_token="tok",
            ipinfo_db_path=manager.db_path,
            whitelist_countries=["CN"],
        )
        started = time.monotonic()
        denied = check_ip_country(CLIENT_IP, config, manager)
        elapsed = time.monotonic() - started

    assert server.attempts == 3
    assert 3 * READ_BOUND <= elapsed < 3 * READ_BOUND + MARGIN
    assert denied is True


def test_an_http_proxy_for_an_http_url_ends_at_the_total_bound_on_one_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connections = count_connections(monkeypatch)
    with stalling_server("gzip", keep_alive=True) as proxy:
        monkeypatch.setenv("HTTP_PROXY", proxy.url.rsplit("/", 1)[0])
        elapsed = _seconds_until_the_attempt_fails(
            _manager(f"http://{HOST}/db", tmp_path)
        )

    assert TOTAL_BOUND <= elapsed < TOTAL_BOUND + MARGIN
    assert len(connections) == 1


def test_a_connect_tunnel_for_an_https_url_ends_at_the_total_bound_on_one_connection(
    trusted_tls: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connections = count_connections(monkeypatch)
    with connect_proxy_server("gzip", tls_server_context(*trusted_tls)) as proxy:
        monkeypatch.setenv("HTTPS_PROXY", proxy.url.rsplit("/", 1)[0])
        elapsed = _seconds_until_the_attempt_fails(
            _manager(f"https://{HOST}/db", tmp_path)
        )

    assert TOTAL_BOUND <= elapsed < TOTAL_BOUND + MARGIN
    assert len(connections) == 1


def test_a_socks5_env_proxy_keeps_its_connection_class_and_ends_at_the_total_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connections = count_connections(monkeypatch)
    socks_connections: list[object] = []
    new_connection = socks.SOCKSConnection._new_conn

    def counting_new_connection(self: socks.SOCKSConnection) -> socket.socket:
        socks_connections.append(self)
        return cast(socket.socket, new_connection(self))

    monkeypatch.setattr(socks.SOCKSConnection, "_new_conn", counting_new_connection)
    with socks5_proxy_server("gzip") as proxy:
        port = proxy.url.split(":")[2].split("/")[0]
        monkeypatch.setenv("ALL_PROXY", f"socks5h://127.0.0.1:{port}")
        elapsed = _seconds_until_the_attempt_fails(
            _manager(f"http://{HOST}/db", tmp_path)
        )

    assert TOTAL_BOUND <= elapsed < TOTAL_BOUND + MARGIN
    assert len(socks_connections) == 1
    assert len(connections) == 1


def test_a_cut_after_a_completed_attempt_touches_nothing() -> None:
    from guard_core.sync.handlers._ipinfo_download_cut import DownloadCut

    kept, other = socket.socketpair()
    with kept, other:
        cut = DownloadCut(total=60)
        cut.record(kept)
        assert cut.stop() is False
        cut.fire()
        other.sendall(b"still readable")
        assert kept.recv(64) == b"still readable"


def test_a_cut_shuts_down_a_socket_that_is_already_closed_without_raising() -> None:
    from guard_core.sync.handlers._ipinfo_download_cut import DownloadCut

    closed, other = socket.socketpair()
    other.close()
    closed.close()
    cut = DownloadCut(total=60)
    cut.record(closed)
    cut.fire()
    assert cut.stop() is True


def test_a_socket_that_connects_after_the_cut_is_shut_down_at_once() -> None:
    from guard_core.sync.handlers._ipinfo_download_cut import DownloadCut

    late, other = socket.socketpair()
    with late, other:
        late.settimeout(0.5)
        cut = DownloadCut(total=60)
        cut.fire()
        cut.record(late)
        assert late.recv(64) == b""
        assert cut.stop() is True


def test_a_download_that_finishes_before_the_total_leaves_no_timer_running(
    tmp_path: Path,
) -> None:
    timers_before = {t for t in threading.enumerate() if isinstance(t, threading.Timer)}
    with trickling_server(gap=0.05, pieces=3) as server:
        manager = _manager(server.url, tmp_path)
        manager._fetch_and_store_database()

    time.sleep(TOTAL_BOUND + 0.2)
    assert manager.db_path.exists()
    timers_after = {t for t in threading.enumerate() if isinstance(t, threading.Timer)}
    assert timers_after - timers_before == set()


def test_each_attempt_uses_a_fresh_session_and_the_retry_gets_the_full_idle_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sessions: list[requests.Session] = []

    class RecordingSession(requests.Session):
        def __init__(self) -> None:
            super().__init__()
            sessions.append(self)

    monkeypatch.setattr(requests, "Session", RecordingSession)
    monkeypatch.setattr(IPInfoManager, "_download_read_timeout", 0.45)
    with trickles_then_delays_server(gap=0.4, delay=0.35) as server:
        manager = _manager(server.url, tmp_path, retries=2)
        manager._fetch_and_store_database()

    assert server.attempts == 2
    assert len(sessions) == 2
    assert sessions[0] is not sessions[1]
    assert manager.db_path.exists()


def test_the_recording_adapter_keeps_the_proxy_pool_connection_classes() -> None:
    from guard_core.sync.handlers._ipinfo_download_cut import (
        DownloadCut,
        RecordingAdapter,
    )

    adapter = RecordingAdapter(DownloadCut(total=60))
    pools = adapter.proxy_manager_for("socks5h://127.0.0.1:1").pool_classes_by_scheme
    http_pool = cast(type[HTTPConnectionPool], pools["http"])
    https_pool = cast(type[HTTPConnectionPool], pools["https"])

    assert issubclass(http_pool.ConnectionCls, socks.SOCKSConnection)
    assert issubclass(https_pool.ConnectionCls, socks.SOCKSHTTPSConnection)
