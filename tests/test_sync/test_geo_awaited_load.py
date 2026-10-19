import threading
import time
from collections.abc import Generator
from pathlib import Path
from types import TracebackType
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.exceptions import GeoDatabaseLoadError, GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.access_control import check_ip_country
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from tests.geo_fixture import CLIENT_IP, country_database_bytes


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


def _blocking_config(manager: IPInfoManager) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        ipinfo_token="tok",
        ipinfo_db_path=manager.db_path,
        blocked_countries=["CN"],
    )


def _allow_list_config(manager: IPInfoManager) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        ipinfo_token="tok",
        ipinfo_db_path=manager.db_path,
        whitelist_countries=["CN"],
    )


def _manager_without_database(tmp_path: Path) -> IPInfoManager:
    return IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")


def _manager_with_local_file(tmp_path: Path, country: str = "CN") -> IPInfoManager:
    db_path = tmp_path / "geo.mmdb"
    db_path.write_bytes(country_database_bytes(country))
    return IPInfoManager(token="tok", db_path=db_path)


def _gated_download(
    manager: IPInfoManager, started: threading.Event, release: threading.Event
) -> MagicMock:
    def download() -> None:
        started.set()
        release.wait()
        manager.db_path.write_bytes(country_database_bytes("CN"))

    return MagicMock(side_effect=download)


def test_the_first_request_enforces_a_blocked_country_from_a_local_file(
    tmp_path: Path,
) -> None:
    manager = _manager_with_local_file(tmp_path)

    blocked = check_ip_country(CLIENT_IP, _blocking_config(manager), manager)

    assert blocked is True


def test_the_first_request_allows_a_whitelisted_country_from_a_local_file(
    tmp_path: Path,
) -> None:
    manager = _manager_with_local_file(tmp_path)

    blocked = check_ip_country(CLIENT_IP, _allow_list_config(manager), manager)

    assert blocked is False


def test_the_first_request_enforces_a_blocked_country_from_a_download(
    tmp_path: Path,
) -> None:
    manager = _manager_without_database(tmp_path)
    started, release = threading.Event(), threading.Event()
    release.set()
    download = _gated_download(manager, started, release)

    with patch.object(manager, "_download_database", download):
        blocked = check_ip_country(CLIENT_IP, _blocking_config(manager), manager)

    assert blocked is True
    assert download.call_count == 1


def test_a_failing_download_is_attempted_once_per_backoff_window(
    tmp_path: Path,
) -> None:
    manager = _manager_without_database(tmp_path)
    download = MagicMock(side_effect=RuntimeError("network down"))

    with patch.object(manager, "_download_database", download):
        denied = [
            check_ip_country(CLIENT_IP, _allow_list_config(manager), manager)
            for _ in range(5)
        ]
        allowed = [
            check_ip_country(CLIENT_IP, _blocking_config(manager), manager)
            for _ in range(5)
        ]

    assert denied == [True] * 5
    assert allowed == [False] * 5
    assert download.call_count == 1
    assert manager._last_load_error is None


def test_a_load_that_fails_at_startup_is_retried_after_the_backoff(
    tmp_path: Path,
) -> None:
    manager = _manager_without_database(tmp_path)
    manager._RETRY_BACKOFF_SECONDS = 0.2

    with patch.object(
        manager, "_download_database", MagicMock(side_effect=RuntimeError("down"))
    ):
        manager.initialize()
    manager.db_path.write_bytes(country_database_bytes("CN"))

    within_the_backoff = check_ip_country(CLIENT_IP, _blocking_config(manager), manager)
    time.sleep(0.3)
    after_the_backoff = check_ip_country(CLIENT_IP, _blocking_config(manager), manager)

    assert within_the_backoff is False
    assert after_the_backoff is True


def test_a_download_that_does_not_open_counts_as_a_failed_attempt(
    tmp_path: Path,
) -> None:
    manager = _manager_without_database(tmp_path)

    def download_garbage() -> None:
        manager.db_path.write_bytes(b"not a database")

    download = MagicMock(side_effect=download_garbage)

    with patch.object(manager, "_download_database", download):
        verdicts = [
            check_ip_country(CLIENT_IP, _allow_list_config(manager), manager)
            for _ in range(3)
        ]

    assert verdicts == [True] * 3
    assert download.call_count == 1
    assert manager.reader is None
    assert not manager.db_path.exists()


def test_a_request_after_a_failed_attempt_retries_once_the_backoff_ends(
    tmp_path: Path,
) -> None:
    manager = _manager_without_database(tmp_path)
    manager._RETRY_BACKOFF_SECONDS = 0.0
    download = MagicMock(side_effect=RuntimeError("network down"))

    with patch.object(manager, "_download_database", download):
        for _ in range(3):
            check_ip_country(CLIENT_IP, _allow_list_config(manager), manager)

    assert download.call_count == 3


def _broken_load() -> Any:
    return MagicMock(side_effect=OSError("disk gone"))


def _traceback_depth(error: BaseException | None) -> int:
    depth = 0
    frame: TracebackType | None = error.__traceback__ if error else None
    while frame is not None:
        depth += 1
        frame = frame.tb_next
    return depth


def test_a_load_that_raises_fails_every_country_check_inside_the_backoff(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    manager = _manager_without_database(tmp_path)
    broken = _broken_load()

    with patch.object(manager, "_adopt_redis_copy", broken):
        for config in (_blocking_config(manager), _allow_list_config(manager)):
            with pytest.raises(GeoDatabaseLoadError) as raised:
                check_ip_country(CLIENT_IP, config, manager)
            assert isinstance(raised.value.__cause__, OSError)
            assert "OSError: disk gone" in str(raised.value)
            assert not isinstance(raised.value, GuardRedisError)

    assert broken.call_count == 1
    assert any("Background GeoIP database load failed" in m for m in caplog.messages)


def test_requests_inside_the_backoff_never_grow_the_stored_load_error(
    tmp_path: Path,
) -> None:
    manager = _manager_without_database(tmp_path)

    with patch.object(manager, "_adopt_redis_copy", _broken_load()):
        with pytest.raises(GeoDatabaseLoadError):
            check_ip_country(CLIENT_IP, _blocking_config(manager), manager)
        stored = manager._last_load_error
        depth = _traceback_depth(stored)
        for _ in range(1000):
            with pytest.raises(GeoDatabaseLoadError):
                check_ip_country(CLIENT_IP, _blocking_config(manager), manager)

    assert manager._last_load_error is stored
    assert _traceback_depth(stored) == depth


def test_a_raising_load_recovers_once_the_backoff_ends(tmp_path: Path) -> None:
    manager = _manager_without_database(tmp_path)
    manager._RETRY_BACKOFF_SECONDS = 0.2

    with patch.object(manager, "_adopt_redis_copy", _broken_load()):
        with pytest.raises(GeoDatabaseLoadError):
            check_ip_country(CLIENT_IP, _blocking_config(manager), manager)
    manager.db_path.write_bytes(country_database_bytes("CN"))

    with pytest.raises(GeoDatabaseLoadError):
        check_ip_country(CLIENT_IP, _blocking_config(manager), manager)
    time.sleep(0.3)
    blocked = check_ip_country(CLIENT_IP, _blocking_config(manager), manager)

    assert blocked is True
    assert manager._last_load_error is None


class _CountryCheck(SecurityCheck):
    def __init__(self, middleware: Mock, manager: IPInfoManager) -> None:
        super().__init__(middleware)
        self._manager = manager

    @property
    def check_name(self) -> str:
        return "ip_security"

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        check_ip_country(CLIENT_IP, self.config, self._manager)
        return None


def _pipeline_verdict(manager: IPInfoManager, **fields: Any) -> Mock:
    config = SecurityConfig(
        enable_redis=False,
        ipinfo_token="tok",
        ipinfo_db_path=manager.db_path,
        blocked_countries=["CN"],
        **fields,
    )
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=500))
    request = Mock()
    request.url_path = "/x"
    request.method = "GET"
    request.state = type("S", (), {})()
    pipeline = SecurityCheckPipeline([_CountryCheck(middleware, manager)])
    pipeline.execute(request)
    return middleware.create_error_response


@pytest.mark.parametrize(
    ("fields", "blocked"),
    [
        ({"fail_secure": True}, True),
        ({"fail_secure": True, "redis_fail_open": True}, True),
        ({"fail_secure": False}, False),
    ],
)
def test_a_raising_load_answers_as_fail_secure_says(
    tmp_path: Path, fields: dict[str, bool], blocked: bool
) -> None:
    manager = _manager_without_database(tmp_path)

    with patch.object(manager, "_adopt_redis_copy", _broken_load()):
        first = _pipeline_verdict(manager, **fields)
        inside_the_backoff = _pipeline_verdict(manager, **fields)

    for error_response in (first, inside_the_backoff):
        if blocked:
            error_response.assert_called_once_with(500, "Security check failed")
        else:
            error_response.assert_not_called()


def test_a_failed_stale_refresh_is_not_retried_inside_the_backoff(
    tmp_path: Path,
) -> None:
    manager = _manager_with_local_file(tmp_path)
    manager.initialize()
    download = MagicMock(side_effect=RuntimeError("network down"))

    with patch.object(manager, "_download_database", download):
        manager._mark_refresh_due()
        manager.get_country(CLIENT_IP)
        task = manager._background_task
        assert task is not None
        task.join(timeout=5)
        manager.get_country(CLIENT_IP)

    assert download.call_count == 1
    assert check_ip_country(CLIENT_IP, _blocking_config(manager), manager)
