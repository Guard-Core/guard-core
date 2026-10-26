import logging
import socket
from collections.abc import Generator
from pathlib import Path

import pytest

from guard_core.handlers.ipinfo_handler import IPInfoManager
from tests.geo_fixture import (
    GeoDownloadServer,
    country_database_bytes,
    database_server,
)


@pytest.fixture(autouse=True)
def _fresh_manager() -> Generator[None, None, None]:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


def _recording_server(
    seen: list[bytes], location: str | None, body: bytes
) -> GeoDownloadServer:
    def behavior(conn: socket.socket, attempt: int) -> None:
        request = b""
        while b"\r\n\r\n" not in request:
            request += conn.recv(4096)
        seen.append(request)
        if location is not None:
            conn.sendall(
                f"HTTP/1.1 302 Found\r\nLocation: {location}\r\n"
                "Content-Length: 0\r\nConnection: close\r\n\r\n".encode()
            )
            return
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%b"
            % (len(body), body)
        )

    return GeoDownloadServer(behavior, read_request=False)


async def test_the_configured_url_is_the_one_fetched(tmp_path: Path) -> None:
    body = country_database_bytes("CN")
    with database_server(body) as server:
        manager = IPInfoManager(
            token="tok", db_path=tmp_path / "geo.mmdb", download_url=server.url
        )
        await manager._download_database_file({})

    assert server.attempts == 1
    assert manager.db_path.read_bytes() == body


async def test_the_bearer_header_goes_only_to_the_configured_host(
    tmp_path: Path,
) -> None:
    body = country_database_bytes("CN")
    other: list[bytes] = []
    configured: list[bytes] = []
    with _recording_server(other, None, body) as elsewhere:
        with _recording_server(configured, elsewhere.url, body) as origin:
            manager = IPInfoManager(
                token="tok", db_path=tmp_path / "geo.mmdb", download_url=origin.url
            )
            await manager._download_database_file({"Authorization": "Bearer tok"})

    assert b"Authorization: Bearer tok" in configured[0]
    assert len(other) == 1
    assert b"authorization" not in other[0].lower()


FIRST_URL = "https://ipinfo.io/data/ipinfo_lite.mmdb"
SECOND_URL = "https://example.invalid/other.mmdb"
WARNING_LOGGER = "guard_core.handlers.ipinfo"


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == WARNING_LOGGER and r.levelno == logging.WARNING
    ]


def test_a_conflicting_second_url_is_logged_once_and_the_first_stays(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "geo.mmdb"
    first = IPInfoManager(token="tok", db_path=path, download_url=FIRST_URL)

    with caplog.at_level(logging.WARNING, logger=WARNING_LOGGER):
        second = IPInfoManager(token="sekret", db_path=path, download_url=SECOND_URL)
        IPInfoManager(token="sekret", db_path=path, download_url=SECOND_URL)

    assert second is first
    assert first._download_url == FIRST_URL
    [message] = _warnings(caplog)
    assert str(path.resolve()) in message
    assert FIRST_URL in message
    assert SECOND_URL in message
    assert "sekret" not in message


def test_the_same_url_or_none_does_not_warn(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "geo.mmdb"
    first = IPInfoManager(token="tok", db_path=path, download_url=FIRST_URL)

    with caplog.at_level(logging.WARNING, logger=WARNING_LOGGER):
        IPInfoManager(token="tok", db_path=path, download_url=FIRST_URL)
        IPInfoManager(token="tok", db_path=path)

    assert _warnings(caplog) == []
    assert first._download_url == FIRST_URL
