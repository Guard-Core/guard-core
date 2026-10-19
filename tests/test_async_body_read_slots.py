import asyncio
import logging
import socket
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core._utils.body_reader import _read_capped_body, _read_capped_body_or_raise
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.exceptions import BodyReadSlotsExhaustedError, BodyReadStalledError
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest


class _Probe:
    def __init__(self, hold: float) -> None:
        self.hold = hold
        self.in_flight = 0
        self.peak = 0

    async def read(self) -> bytes:
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            await asyncio.sleep(self.hold)
            return b"body"
        finally:
            self.in_flight -= 1


class _DripRequest(MockGuardRequest):
    def __init__(self, gate: asyncio.Event, body: bytes = b"drip") -> None:
        super().__init__(
            method="POST",
            path="/x",
            headers={"content-type": "text/plain", "content-length": "4"},
        )
        self._gate = gate
        self._drip = body

    async def read_body_prefix_until_idle(
        self, max_bytes: int, idle_timeout: float
    ) -> bytes:
        await self._gate.wait()
        return self._drip


def _honest(body: bytes) -> MockGuardRequest:
    return MockGuardRequest(
        method="POST",
        path="/x",
        headers={
            "content-type": "text/plain",
            "content-length": str(len(body)),
        },
        body_content=body,
    )


async def _start(gate: asyncio.Event, count: int, config: SecurityConfig) -> list[Any]:
    readers = [
        asyncio.ensure_future(_read_capped_body_or_raise(_DripRequest(gate), config))
        for _ in range(count)
    ]
    await asyncio.sleep(0.05)
    return readers


async def test_no_limit_by_default_and_a_further_body_is_scanned() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=10000)
    assert config.async_body_read_max_concurrent is None
    gate = asyncio.Event()
    drips = await _start(gate, 65, config)

    attack = await detect_penetration_attempt(_honest(b"1' OR '1'='1' --"), config)
    clean = await detect_penetration_attempt(_honest(b"hello"), config)

    assert attack.is_threat is True
    assert attack.body_read_error is None
    assert clean.is_threat is False
    assert clean.body_read_error is None

    gate.set()
    assert await asyncio.gather(*drips) == [b"drip"] * 65


async def test_the_async_default_ignores_the_sync_limit() -> None:
    config = SecurityConfig(
        enable_redis=False, sync_body_read_max_concurrent=1, body_read_timeout=0.05
    )
    gate = asyncio.Event()
    drips = await _start(gate, 3, config)

    assert await _read_capped_body_or_raise(_honest(b"fine"), config) == b"fine"

    gate.set()
    assert await asyncio.gather(*drips) == [b"drip"] * 3


async def test_a_set_limit_bounds_the_request_body_reads() -> None:
    config = SecurityConfig(
        enable_redis=False, async_body_read_max_concurrent=1, body_read_timeout=5.0
    )
    probe = _Probe(hold=0.03)

    class _Request(MockGuardRequest):
        async def body(self) -> bytes:
            return await probe.read()

    requests = [
        _Request(method="POST", headers={"content-length": "4"}) for _ in range(4)
    ]

    results = await asyncio.gather(*(_read_capped_body(r, config) for r in requests))

    assert results == [b"body"] * 4
    assert probe.peak == 1


async def test_a_slot_wait_that_expires_raises_the_stall_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        enable_redis=False, async_body_read_max_concurrent=2, body_read_timeout=0.05
    )
    gate = asyncio.Event()
    drips = await _start(gate, 2, config)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        with pytest.raises(BodyReadSlotsExhaustedError):
            await _read_capped_body_or_raise(_honest(b"late"), config)

    assert "Body read concurrency limit reached (max_concurrent=2)" in caplog.text
    gate.set()
    await asyncio.gather(*drips)
    assert await _read_capped_body_or_raise(_honest(b"free"), config) == b"free"


async def test_a_slot_wait_that_expires_answers_408_not_a_silent_skip() -> None:
    config = SecurityConfig(
        enable_redis=False,
        async_body_read_max_concurrent=1,
        body_read_timeout=0.05,
        fail_secure=True,
        enable_penetration_detection=True,
    )
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_async_body_read_concurrency")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    check = SuspiciousActivityCheck(middleware)
    gate = asyncio.Event()
    drips = await _start(gate, 1, config)
    waiter = _honest(b"late")
    waiter.state.client_ip = "203.0.113.9"
    waiter.state.route_config = None

    response = await check.check(waiter)

    assert response is not None
    assert response.status_code == 408
    assert middleware.suspicious_request_counts == {}
    gate.set()
    await asyncio.gather(*drips)


def test_the_slot_field_descriptions_state_the_default_and_the_outcome() -> None:
    fields = SecurityConfig.model_fields
    async_text = fields["async_body_read_max_concurrent"].description or ""
    sync_text = fields["sync_body_read_max_concurrent"].description or ""
    timeout_text = fields["body_read_timeout"].description or ""

    assert "None (the default) means no limit" in async_text
    assert "408" in async_text and "fail_secure" in async_text
    assert "408" in sync_text and "fail_secure" in sync_text
    assert "daemon" not in sync_text + timeout_text + async_text
    assert "ASYNC tree it bounds" not in sync_text


@pytest.mark.parametrize("value", [0, -1, 10001])
def test_the_async_slot_field_rejects_values_outside_1_to_10000(
    value: int,
) -> None:
    with pytest.raises(ValueError):
        SecurityConfig(enable_redis=False, async_body_read_max_concurrent=value)


def test_the_generated_sync_body_reader_reads_the_sync_slot_field() -> None:
    generated = (
        Path(__file__).resolve().parents[1]
        / "guard_core"
        / "sync"
        / "_utils"
        / "body_reader.py"
    ).read_text()

    assert "config.sync_body_read_max_concurrent" in generated
    assert "async_body_read_max_concurrent" not in generated


async def test_a_stalled_client_socket_answers_408() -> None:
    server_sock, client_sock = socket.socketpair()
    reader, writer = await asyncio.open_connection(sock=server_sock)
    config = SecurityConfig(enable_redis=False, fail_secure=True, body_read_timeout=0.1)

    class _StreamRequest(MockGuardRequest):
        def __init__(self) -> None:
            super().__init__(
                method="POST",
                path="/x",
                headers={"content-type": "text/plain", "content-length": "4"},
            )

        async def read_body_prefix_until_idle(
            self, max_bytes: int, idle_timeout: float
        ) -> bytes:
            try:
                return await asyncio.wait_for(reader.read(max_bytes), idle_timeout)
            except asyncio.TimeoutError as exc:
                raise BodyReadStalledError() from exc

    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_async_body_read_slots")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    request = _StreamRequest()
    request.state.client_ip = "203.0.113.11"
    request.state.route_config = None
    try:
        started = time.monotonic()
        response = await SuspiciousActivityCheck(middleware).check(request)
        elapsed = time.monotonic() - started
    finally:
        writer.close()
        client_sock.close()

    assert response is not None
    assert response.status_code == 408
    assert elapsed < 2.0
    assert middleware.suspicious_request_counts == {}
