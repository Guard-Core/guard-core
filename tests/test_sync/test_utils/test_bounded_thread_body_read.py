import inspect
import logging
import socket
import threading
import time
from typing import cast
from unittest.mock import MagicMock

import pytest

from guard_core.exceptions import (
    BodyReadFailedError,
    BodyReadSlotsExhaustedError,
    BodyReadStalledError,
)
from guard_core.models import SyncSecurityConfig
from guard_core.sync import utils
from guard_core.sync._utils.body_reader import _read_capped_body_or_raise
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from tests.test_sync.conftest import SyncMockGuardRequest

GUARD_THREAD_NAMES = {"guard-body-read"}


def _guard_body_read_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name in GUARD_THREAD_NAMES]


class _HoldingRequest(SyncMockGuardRequest):
    def __init__(self, release: threading.Event) -> None:
        super().__init__(
            method="POST",
            path="/x",
            headers={"content-type": "text/plain", "content-length": "4"},
        )
        self._release = release
        self.read_on: list[threading.Thread] = []

    def read_body_prefix_until_idle(self, max_bytes: int, idle_timeout: float) -> bytes:
        self.read_on.append(threading.current_thread())
        self._release.wait()
        return b"held"


def _honest(body: bytes) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        method="POST",
        path="/x",
        headers={"content-type": "text/plain", "content-length": str(len(body))},
        body_content=body,
    )


def _config(**overrides: object) -> SyncSecurityConfig:
    values: dict[str, object] = {"enable_redis": False, "rate_limit": 10000}
    values.update(overrides)
    return SyncSecurityConfig(**values)


def _hold_slots(
    config: SyncSecurityConfig, count: int, release: threading.Event
) -> list[threading.Thread]:
    holders = [
        threading.Thread(
            target=_read_capped_body_or_raise, args=(_HoldingRequest(release), config)
        )
        for _ in range(count)
    ]
    for holder in holders:
        holder.start()
    time.sleep(0.1)
    return holders


def test_a_request_body_is_read_on_the_request_thread_and_spawns_no_thread() -> None:
    release = threading.Event()
    release.set()
    request = _HoldingRequest(release)

    body = _read_capped_body_or_raise(request, _config())

    assert body == b"held"
    assert request.read_on == [threading.current_thread()]
    assert _guard_body_read_threads() == []


def test_the_sync_slot_field_bounds_the_reads_in_flight() -> None:
    release = threading.Event()
    config = _config(sync_body_read_max_concurrent=2, body_read_timeout=0.1)
    holders = _hold_slots(config, 2, release)

    with pytest.raises(BodyReadSlotsExhaustedError):
        _read_capped_body_or_raise(_honest(b"late"), config)

    release.set()
    for holder in holders:
        holder.join(timeout=2)
    assert _read_capped_body_or_raise(_honest(b"free"), config) == b"free"


def test_the_sync_default_is_64_slots_and_the_async_field_is_not_read() -> None:
    config = _config(async_body_read_max_concurrent=1)

    assert config.sync_body_read_max_concurrent == 64
    release = threading.Event()
    release.set()
    holders = _hold_slots(config, 3, release)
    for holder in holders:
        holder.join(timeout=2)
    assert _read_capped_body_or_raise(_honest(b"fine"), config) == b"fine"


def test_a_slot_wait_that_expires_answers_408_through_the_check() -> None:
    release = threading.Event()
    config = _config(
        sync_body_read_max_concurrent=1,
        body_read_timeout=0.1,
        fail_secure=True,
        enable_penetration_detection=True,
    )
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_bounded_thread_body_read")
    middleware.suspicious_request_counts = {}
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    check = SuspiciousActivityCheck(middleware)
    holders = _hold_slots(config, 1, release)
    waiter = _honest(b"late")
    waiter.state.client_ip = "203.0.113.9"
    waiter.state.route_config = None

    response = check.check(waiter)

    assert response is not None
    assert response.status_code == 408
    assert middleware.suspicious_request_counts == {}
    release.set()
    for holder in holders:
        holder.join(timeout=2)


def test_a_slot_is_released_after_a_stall_a_failure_and_a_success() -> None:
    config = _config(sync_body_read_max_concurrent=1, body_read_timeout=0.2)

    class _Outcome(SyncMockGuardRequest):
        def __init__(self, outcome: bytes | Exception) -> None:
            super().__init__(method="POST", path="/x", headers={"content-length": "4"})
            self.outcome = outcome

        def read_body_prefix_until_idle(
            self, max_bytes: int, idle_timeout: float
        ) -> bytes:
            if isinstance(self.outcome, Exception):
                raise self.outcome
            return self.outcome

    with pytest.raises(BodyReadStalledError):
        _read_capped_body_or_raise(_Outcome(BodyReadStalledError()), config)
    with pytest.raises(BodyReadFailedError):
        _read_capped_body_or_raise(_Outcome(OSError("reset")), config)
    assert _read_capped_body_or_raise(_Outcome(b"okay"), config) == b"okay"


def test_a_stalled_client_socket_answers_408() -> None:
    server, client = socket.socketpair()
    config = _config(fail_secure=True, body_read_timeout=0.1)

    class _SocketRequest(SyncMockGuardRequest):
        def __init__(self) -> None:
            super().__init__(
                method="POST",
                path="/x",
                headers={"content-type": "text/plain", "content-length": "4"},
            )

        def read_body_prefix_until_idle(
            self, max_bytes: int, idle_timeout: float
        ) -> bytes:
            server.settimeout(idle_timeout)
            try:
                return server.recv(max_bytes)
            except TimeoutError as exc:
                raise BodyReadStalledError() from exc

    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_bounded_thread_body_read")
    middleware.suspicious_request_counts = {}
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    request = _SocketRequest()
    request.state.client_ip = "203.0.113.10"
    request.state.route_config = None
    try:
        started = time.monotonic()
        response = SuspiciousActivityCheck(middleware).check(request)
        elapsed = time.monotonic() - started
    finally:
        server.close()
        client.close()

    assert response is not None
    assert response.status_code == 408
    assert elapsed < 2.0
    assert middleware.suspicious_request_counts == {}


def test_no_thread_pool_executor_machinery_is_used() -> None:
    assert not hasattr(utils, "ThreadPoolExecutor")
    assert "ThreadPoolExecutor" not in inspect.getsource(utils._safe_read)
    assert "threading.Thread" not in inspect.getsource(utils._safe_read)


def test_a_successful_read_returns_the_value() -> None:
    result = utils._safe_read(lambda: b"payload", timeout=1.0, max_concurrent=21)

    assert result == b"payload"


def test_a_raising_reader_degrades_to_none() -> None:
    def _raise() -> bytes:
        raise RuntimeError("adapter stream closed")

    result = utils._safe_read(_raise, timeout=1.0, max_concurrent=22)

    assert result is None


def test_the_response_side_reader_runs_on_the_calling_thread() -> None:
    seen: list[threading.Thread] = []

    def _reader() -> bytes:
        seen.append(threading.current_thread())
        return b"response"

    assert utils._safe_read(_reader, timeout=1.0, max_concurrent=23) == b"response"
    assert seen == [threading.current_thread()]
    assert _guard_body_read_threads() == []


def test_the_response_side_slot_wait_gives_up_and_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    release = threading.Event()

    def _hold() -> bytes:
        release.wait()
        return b"late"

    holder = threading.Thread(
        target=utils._safe_read, args=(_hold, 5.0, 1), name="holder"
    )
    holder.start()
    time.sleep(0.1)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = utils._safe_read(_hold, timeout=0.1, max_concurrent=1)

    assert result is None
    assert "concurrency limit" in caplog.text.lower()
    release.set()
    holder.join(timeout=2)


def test_forty_concurrent_ordinary_reads_skip_zero_even_with_a_small_limit() -> None:
    config = _config(sync_body_read_max_concurrent=5, body_read_timeout=2.0)
    n = 40
    results: list[bytes | None] = [None] * n
    barrier = threading.Barrier(n)

    class _Ordinary(SyncMockGuardRequest):
        def __init__(self, i: int) -> None:
            super().__init__(method="POST", path="/x", headers={"content-length": "8"})
            self.i = i

        def read_body_prefix_until_idle(
            self, max_bytes: int, idle_timeout: float
        ) -> bytes:
            time.sleep(0.02)
            return f"order-{self.i:02d}".encode()

    def _worker(i: int) -> None:
        barrier.wait()
        results[i] = _read_capped_body_or_raise(
            cast(SyncGuardRequest, _Ordinary(i)), config
        )

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert results == [f"order-{i:02d}".encode() for i in range(n)]
