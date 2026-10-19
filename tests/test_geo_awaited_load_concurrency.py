import asyncio
import threading
from collections.abc import Generator
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, patch

import pytest

from guard_core._utils.access_control import check_ip_country
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.models import SecurityConfig
from guard_core.protocols.redis_protocol import RedisHandlerProtocol
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
    manager: IPInfoManager, started: asyncio.Event, release: asyncio.Event
) -> AsyncMock:
    async def download() -> None:
        started.set()
        await release.wait()
        manager.db_path.write_bytes(country_database_bytes("CN"))

    return AsyncMock(side_effect=download)


async def test_five_concurrent_first_requests_share_one_load(
    tmp_path: Path,
) -> None:
    manager = _manager_without_database(tmp_path)
    started, release = asyncio.Event(), asyncio.Event()
    download = _gated_download(manager, started, release)

    with patch.object(manager, "_download_database", download):
        requests = [
            asyncio.create_task(
                check_ip_country(CLIENT_IP, _blocking_config(manager), manager)
            )
            for _ in range(5)
        ]
        await asyncio.wait_for(started.wait(), timeout=5)
        release.set()
        verdicts = await asyncio.gather(*requests)

    assert verdicts == [True] * 5
    assert download.await_count == 1


async def test_a_cancelled_waiter_does_not_cancel_the_shared_load(
    tmp_path: Path,
) -> None:
    manager = _manager_without_database(tmp_path)
    started, release = asyncio.Event(), asyncio.Event()
    download = _gated_download(manager, started, release)

    with patch.object(manager, "_download_database", download):
        requests = [
            asyncio.create_task(
                check_ip_country(CLIENT_IP, _blocking_config(manager), manager)
            )
            for _ in range(5)
        ]
        await asyncio.wait_for(started.wait(), timeout=5)
        requests[0].cancel()
        release.set()
        outcomes = await asyncio.gather(*requests, return_exceptions=True)

    assert isinstance(outcomes[0], asyncio.CancelledError)
    assert outcomes[1:] == [True] * 4
    assert download.await_count == 1


async def test_the_backoff_starts_when_the_attempt_ends_not_when_it_begins(
    tmp_path: Path,
) -> None:
    manager = _manager_without_database(tmp_path)
    started, release = asyncio.Event(), asyncio.Event()
    download = _gated_download(manager, started, release)

    with patch.object(manager, "_download_database", download):
        request = asyncio.create_task(
            check_ip_country(CLIENT_IP, _blocking_config(manager), manager)
        )
        await asyncio.wait_for(started.wait(), timeout=5)
        stamped_during_the_attempt = manager._last_attempt_at
        release.set()
        await request

    assert stamped_during_the_attempt is None
    assert manager._last_attempt_at is None


async def test_a_stale_database_refreshes_in_the_background_without_a_wait(
    tmp_path: Path,
) -> None:
    manager = _manager_with_local_file(tmp_path, "CN")
    await manager.initialize()
    started, release = asyncio.Event(), asyncio.Event()
    download = _gated_download(manager, started, release)

    with patch.object(manager, "_download_database", download):
        manager._mark_refresh_due()
        blocked = await asyncio.wait_for(
            check_ip_country(CLIENT_IP, _blocking_config(manager), manager), timeout=1
        )
        await asyncio.wait_for(started.wait(), timeout=5)
        refresh_finished = release.is_set()
        release.set()
        task = manager._background_task
        assert task is not None
        await asyncio.wait_for(task, timeout=5)

    assert blocked is True
    assert refresh_finished is False
    assert download.await_count == 1


def test_a_second_event_loop_starts_its_own_load() -> None:
    async def first_loop(db_path: Path) -> bool:
        manager = IPInfoManager(token="tok", db_path=db_path)
        hung = asyncio.Event()

        async def never_finishes() -> None:
            await hung.wait()

        with patch.object(manager, "_download_database", never_finishes):
            try:
                await asyncio.wait_for(
                    check_ip_country(CLIENT_IP, _blocking_config(manager), manager), 0.2
                )
            except asyncio.TimeoutError:
                return True
        return False

    async def second_loop(db_path: Path) -> bool:
        manager = IPInfoManager(token="tok", db_path=db_path)
        manager._last_attempt_at = None
        return await asyncio.wait_for(
            check_ip_country(CLIENT_IP, _blocking_config(manager), manager), 5
        )

    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        db_path = Path(directory) / "geo.mmdb"
        IPInfoManager._instance = None
        assert asyncio.run(first_loop(db_path)) is True
        db_path.write_bytes(country_database_bytes("CN"))
        assert asyncio.run(second_loop(db_path)) is True


async def test_a_request_during_the_startup_load_joins_it(
    tmp_path: Path,
) -> None:
    manager = _manager_without_database(tmp_path)
    started, release = asyncio.Event(), asyncio.Event()
    download = _gated_download(manager, started, release)

    with patch.object(manager, "_download_database", download):
        startup = asyncio.create_task(manager.initialize())
        await asyncio.wait_for(started.wait(), timeout=5)
        request = asyncio.create_task(
            check_ip_country(CLIENT_IP, _blocking_config(manager), manager)
        )
        await asyncio.sleep(0.05)
        release.set()
        await startup
        blocked = await request

    assert blocked is True
    assert download.await_count == 1


async def test_a_request_during_the_redis_startup_load_joins_it(
    tmp_path: Path,
) -> None:
    manager = _manager_without_database(tmp_path)
    started, release = asyncio.Event(), asyncio.Event()
    download = _gated_download(manager, started, release)
    redis = AsyncMock()
    redis.get_key = AsyncMock(return_value=None)
    redis.set_key_if_absent = AsyncMock(return_value=True)

    with patch.object(manager, "_download_database", download):
        startup = asyncio.create_task(
            manager.initialize_redis(cast(RedisHandlerProtocol, redis))
        )
        await asyncio.wait_for(started.wait(), timeout=5)
        request = asyncio.create_task(
            check_ip_country(CLIENT_IP, _blocking_config(manager), manager)
        )
        await asyncio.sleep(0.05)
        release.set()
        await startup
        blocked = await request

    assert blocked is True
    assert download.await_count == 1


def test_a_request_never_awaits_a_load_that_runs_on_another_loop(
    tmp_path: Path,
) -> None:
    manager = _manager_without_database(tmp_path)
    downloads: list[int] = []
    first_download_started = threading.Event()

    async def download() -> None:
        downloads.append(1)
        if len(downloads) == 1:
            first_download_started.set()
            await asyncio.Event().wait()
        manager.db_path.write_bytes(country_database_bytes("CN"))

    async def cancel_everything_on_the_loop() -> None:
        pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    other_loop = asyncio.new_event_loop()
    other_thread = threading.Thread(target=other_loop.run_forever, daemon=True)
    other_thread.start()
    try:
        with patch.object(manager, "_download_database", download):
            other_request = asyncio.run_coroutine_threadsafe(
                check_ip_country(CLIENT_IP, _blocking_config(manager), manager),
                other_loop,
            )
            assert first_download_started.wait(timeout=5)

            blocked = asyncio.run(
                asyncio.wait_for(
                    check_ip_country(CLIENT_IP, _blocking_config(manager), manager),
                    timeout=5,
                )
            )
    finally:
        asyncio.run_coroutine_threadsafe(
            cancel_everything_on_the_loop(), other_loop
        ).result(timeout=5)
        other_loop.call_soon_threadsafe(other_loop.stop)
        other_thread.join(timeout=5)
        other_loop.close()

    assert blocked is True
    assert other_request.cancelled() or other_request.done()
    assert len(downloads) == 2
