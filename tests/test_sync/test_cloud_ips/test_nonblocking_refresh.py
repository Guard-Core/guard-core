import ipaddress
import logging
import threading
import time
from collections.abc import Callable, Generator
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.cloud_ip_refresh import (
    CloudIpRefreshCheck,
)
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.handlers.cloud_ip_stores import InMemoryCloudIpStore

_AWS_NET = ipaddress.ip_network("192.168.0.0/24")


@pytest.fixture(autouse=True)
def reset_cloud_handler() -> Generator[None, None]:
    cloud_handler.ip_ranges = {provider: set() for provider in cloud_handler.ip_ranges}
    cloud_handler._store = InMemoryCloudIpStore()
    cloud_handler.redis_handler = None
    cloud_handler._refresh_task = None
    cloud_handler._refresh_in_flight = False
    yield
    task: threading.Thread | None = cloud_handler._refresh_task
    if task is not None and task.is_alive():
        task.join(timeout=1)
    cloud_handler._refresh_task = None
    cloud_handler._refresh_in_flight = False


def _make_check(interval: int = 3600, last_refresh: int = 0) -> CloudIpRefreshCheck:
    middleware = MagicMock()
    middleware.config = SyncSecurityConfig(
        block_cloud_providers={"AWS"},
        cloud_ip_refresh_interval=interval,
    )
    middleware.logger = logging.getLogger("test.cloud_ip_refresh")
    middleware.last_cloud_ip_refresh = last_refresh
    middleware.route_resolver.get_cloud_providers_to_check = MagicMock(
        return_value=["AWS"]
    )

    def _adapter_refresh() -> None:
        cloud_handler.refresh_async({"AWS"}, ttl=interval)

    middleware.refresh_cloud_ip_ranges = _adapter_refresh
    return CloudIpRefreshCheck(middleware)


def _aws_ok() -> set:
    return {_AWS_NET}


class _InstantThread:
    """A threading.Thread stand-in that runs its target synchronously inside
    start(), simulating a background thread that finishes before the caller's
    next line executes. Used to prove schedule_refresh() sets
    `_refresh_in_flight = True` BEFORE starting the thread, not after, if the
    ordering regresses, the target's `finally: _refresh_in_flight = False`
    runs inside start() and gets clobbered back to True by the caller,
    permanently wedging future refreshes off."""

    def __init__(self, target: Callable[[], None], daemon: bool = True) -> None:
        self._target = target

    def start(self) -> None:
        self._target()

    def join(self, timeout: float | None = None) -> None:
        return None

    def is_alive(self) -> bool:
        return False


def test_schedule_refresh_runs_fetch_in_background() -> None:
    with patch(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges", new=_aws_ok
    ):
        started = cloud_handler.schedule_refresh({"AWS"}, ttl=3600)
        assert started is True
        task = cloud_handler._refresh_task
        assert task is not None
        task.join(timeout=1)

    assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})


def test_schedule_refresh_is_single_flight() -> None:
    started_evt = threading.Event()
    release_evt = threading.Event()

    def slow_aws() -> set:
        started_evt.set()
        release_evt.wait(timeout=2)
        return {_AWS_NET}

    with patch(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges", new=slow_aws
    ):
        assert cloud_handler.schedule_refresh({"AWS"}) is True
        assert started_evt.wait(timeout=2)
        first_task = cloud_handler._refresh_task
        assert first_task is not None

        assert cloud_handler.schedule_refresh({"AWS"}) is False
        assert cloud_handler._refresh_task is first_task

        release_evt.set()
        first_task.join(timeout=2)


def test_check_returns_immediately_when_fetch_hangs() -> None:
    hang = threading.Event()

    def hanging_aws() -> set:
        hang.wait(timeout=2)
        return set()

    check = _make_check(last_refresh=0)
    with patch(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges", new=hanging_aws
    ):
        start = time.monotonic()
        result = check.check(MagicMock())
        elapsed = time.monotonic() - start

    hang.set()
    task = cloud_handler._refresh_task
    if task is not None:
        task.join(timeout=2)

    assert result is None
    assert elapsed < 1.0
    assert check.middleware.last_cloud_ip_refresh > 0
    assert cloud_handler._refresh_task is not None


def test_check_skips_refresh_within_interval() -> None:
    check = _make_check(last_refresh=int(time.time()))
    with patch.object(cloud_handler, "schedule_refresh") as spy:
        result = check.check(MagicMock())

    assert result is None
    spy.assert_not_called()


def test_check_noop_without_block_cloud_providers() -> None:
    middleware = MagicMock()
    middleware.config = SyncSecurityConfig(block_cloud_providers=None)
    middleware.logger = logging.getLogger("test.cloud_ip_refresh")
    middleware.last_cloud_ip_refresh = 0
    middleware.route_resolver.get_cloud_providers_to_check = MagicMock(return_value=[])
    check = CloudIpRefreshCheck(middleware)

    with patch.object(cloud_handler, "schedule_refresh") as spy:
        result = check.check(MagicMock())

    assert result is None
    spy.assert_not_called()
    assert middleware.last_cloud_ip_refresh == 0


def test_schedule_refresh_logs_and_recovers_on_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def boom() -> set:
        raise RuntimeError("azure down")

    with patch("guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges", new=boom):
        with caplog.at_level(logging.ERROR, logger="guard_core.sync.handlers.cloud"):
            assert cloud_handler.schedule_refresh({"AWS"}) is True
            task = cloud_handler._refresh_task
            assert task is not None
            task.join(timeout=2)

        assert "Failed to refresh AWS IP ranges" in caplog.text
        assert cloud_handler._refresh_in_flight is False
        assert cloud_handler.schedule_refresh({"AWS"}) is True
        second = cloud_handler._refresh_task
        if second is not None:
            second.join(timeout=2)


def test_schedule_refresh_sets_in_flight_before_starting_thread() -> None:
    """Regression test: a fast-finishing background thread must not be able to
    clobber `_refresh_in_flight` back to True after the target's own
    `finally: _refresh_in_flight = False` has already run. This requires
    `_refresh_in_flight = True` to be set BEFORE the thread starts, not after;
    if it regressed, the completed thread's False would be stomped back to
    True, wedging future refreshes off."""
    with patch(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges", new=_aws_ok
    ):
        with patch(
            "guard_core.sync.handlers.cloud_handler.threading.Thread",
            new=_InstantThread,
        ):
            started = cloud_handler.schedule_refresh({"AWS"}, ttl=3600)

    assert started is True
    assert cloud_handler._refresh_in_flight is False
    with patch(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges", new=_aws_ok
    ):
        with patch(
            "guard_core.sync.handlers.cloud_handler.threading.Thread",
            new=_InstantThread,
        ):
            assert cloud_handler.schedule_refresh({"AWS"}, ttl=3600) is True


def test_run_refresh_logs_when_refresh_async_itself_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with patch.object(cloud_handler, "refresh_async", side_effect=RuntimeError("boom")):
        with caplog.at_level(logging.ERROR, logger="guard_core.sync.handlers.cloud"):
            assert cloud_handler.schedule_refresh({"AWS"}) is True
            task = cloud_handler._refresh_task
            assert task is not None
            task.join(timeout=2)

    assert "Background cloud IP refresh failed" in caplog.text
    assert cloud_handler._refresh_in_flight is False


def test_schedule_refresh_recovers_when_thread_start_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _NoStartThread:
        def __init__(self, target: Callable[[], None], daemon: bool = True) -> None:
            pass

        def start(self) -> None:
            raise RuntimeError("can't start thread")

        def is_alive(self) -> bool:
            return False

        def join(self, timeout: float | None = None) -> None:
            return None

    with patch(
        "guard_core.sync.handlers.cloud_handler.threading.Thread", new=_NoStartThread
    ):
        with caplog.at_level(logging.ERROR, logger="guard_core.sync.handlers.cloud"):
            started = cloud_handler.schedule_refresh({"AWS"})

    assert started is False
    assert "Could not schedule cloud IP refresh" in caplog.text
    assert cloud_handler._refresh_in_flight is False


def test_in_memory_store_expires_after_ttl() -> None:
    store = InMemoryCloudIpStore()
    with patch("guard_core.sync.handlers.cloud_ip_stores.time.monotonic") as clock:
        clock.return_value = 1000.0
        store.set("AWS", {"10.0.0.0/8"}, ttl=60)
        assert store.get("AWS") == {"10.0.0.0/8"}
        clock.return_value = 1059.9
        assert store.get("AWS") == {"10.0.0.0/8"}
        clock.return_value = 1060.0
        assert store.get("AWS") is None
        assert store.get("AWS") is None


def test_in_memory_store_without_ttl_never_expires() -> None:
    store = InMemoryCloudIpStore()
    with patch("guard_core.sync.handlers.cloud_ip_stores.time.monotonic") as clock:
        clock.return_value = 1000.0
        store.set("AWS", {"10.0.0.0/8"}, ttl=60)
        store.set("AWS", {"10.0.0.0/8"})
        clock.return_value = 10_000_000.0
        assert store.get("AWS") == {"10.0.0.0/8"}


def test_in_memory_store_clear_drops_expiries() -> None:
    store = InMemoryCloudIpStore()
    store.set("AWS", {"10.0.0.0/8"}, ttl=60)
    store.clear()
    assert store.get("AWS") is None
    assert store._expires_at == {}


def test_refresh_async_refetches_after_ttl_expiry() -> None:
    calls = []

    def counting_aws() -> set:
        calls.append(1)
        return {_AWS_NET}

    with patch(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges", new=counting_aws
    ):
        with patch("guard_core.sync.handlers.cloud_ip_stores.time.monotonic") as clock:
            clock.return_value = 0.0
            cloud_handler.refresh_async({"AWS"}, ttl=3600)
            cloud_handler.refresh_async({"AWS"}, ttl=3600)
            assert len(calls) == 1
            clock.return_value = 3600.0
            cloud_handler.refresh_async({"AWS"}, ttl=3600)

    assert len(calls) == 2
    assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})


def test_schedule_refresh_runs_provided_refresh_callable() -> None:
    ran = threading.Event()

    def custom_refresh() -> None:
        ran.set()

    with patch.object(cloud_handler, "refresh_async") as spy:
        started = cloud_handler.schedule_refresh({"AWS"}, refresh=custom_refresh)
        assert started is True
        task = cloud_handler._refresh_task
        assert task is not None
        task.join(timeout=2)

    assert ran.is_set()
    spy.assert_not_called()
    assert cloud_handler._refresh_in_flight is False


def test_check_routes_refresh_through_middleware_protocol() -> None:
    check = _make_check(last_refresh=0)
    spy = MagicMock(return_value=True)
    with patch.object(cloud_handler, "schedule_refresh", new=spy):
        check.check(MagicMock())

    assert spy.call_args.kwargs["refresh"] is check.middleware.refresh_cloud_ip_ranges


def test_check_restores_debounce_when_scheduling_fails() -> None:
    check = _make_check(last_refresh=7)
    with patch.object(
        cloud_handler, "schedule_refresh", new=MagicMock(return_value=False)
    ):
        result = check.check(MagicMock())

    assert result is None
    assert check.middleware.last_cloud_ip_refresh == 7


def test_check_keeps_debounce_when_scheduling_succeeds() -> None:
    check = _make_check(last_refresh=7)
    with patch.object(
        cloud_handler, "schedule_refresh", new=MagicMock(return_value=True)
    ):
        check.check(MagicMock())

    assert check.middleware.last_cloud_ip_refresh > 7
