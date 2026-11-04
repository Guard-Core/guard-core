import asyncio
import logging
from collections.abc import Awaitable, Callable, Generator
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core._utils.body_reader import _finish_started, _safe_read
from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.responses import reads_response_body
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.core.responses.modifier_view import RecordingHeaders
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse, GuardResponseHeaders
from tests.conftest import MockGuardRequest, MockGuardResponseFactory


async def _no_wait_for(*_args: object, **_kwargs: object) -> bytes:
    raise AssertionError("a read that never waits must not create a task or a timer")


async def test_a_read_that_never_waits_takes_no_task_and_no_timer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(asyncio, "wait_for", _no_wait_for)

    async def reader() -> bytes:
        return b"abc"

    assert await _safe_read(reader, 1.0) == b"abc"


async def test_a_zero_timeout_behaves_as_wait_for_does() -> None:
    async def reader() -> bytes:
        return b"abc"

    try:
        expected: bytes | None = await asyncio.wait_for(reader(), timeout=0.0)
    except asyncio.TimeoutError:
        expected = None

    assert await _safe_read(reader, 0.0) == expected


async def test_a_read_that_waits_still_finishes_inside_its_timeout() -> None:
    async def reader() -> bytes:
        await asyncio.sleep(0)
        await asyncio.sleep(0.01)
        return b"late"

    assert await _safe_read(reader, 1.0) == b"late"


async def test_a_read_that_waits_past_its_timeout_is_unavailable_and_closed() -> None:
    closed = asyncio.Event()

    async def reader() -> bytes:
        try:
            await asyncio.Event().wait()
        finally:
            closed.set()
        return b"never"

    assert await _safe_read(reader, 0.05) is None
    assert closed.is_set()


async def test_a_reader_that_answers_its_cancellation_still_returns_its_bytes() -> None:
    async def reader() -> bytes:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            return b"swallowed"
        return b"never"

    assert await _safe_read(reader, 0.05) == b"swallowed"


async def test_cancelling_a_waiting_read_closes_the_reader() -> None:
    started = asyncio.Event()
    closed = asyncio.Event()

    async def reader() -> bytes:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            closed.set()
        return b"never"

    task = asyncio.create_task(_safe_read(reader, 30.0))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert closed.is_set()


async def test_a_reader_that_raises_is_unavailable() -> None:
    async def raises_at_once() -> bytes:
        raise OSError("boom")

    async def raises_after_waiting() -> bytes:
        await asyncio.sleep(0)
        raise OSError("boom")

    assert await _safe_read(raises_at_once, 1.0) is None
    assert await _safe_read(raises_after_waiting, 1.0) is None


class _NotAwaitable(Awaitable[bytes]):
    def __await__(self) -> Generator[object, None, bytes]:
        raise TypeError("object is not awaitable")


async def test_a_reader_that_is_not_awaitable_is_unavailable() -> None:
    def reader() -> Awaitable[bytes]:
        return _NotAwaitable()

    assert await _safe_read(reader, 1.0) is None


class _Waiting(Awaitable[bytes]):
    def __init__(self, marker: object) -> None:
        self.marker = marker
        self.closed = False

    def __await__(self) -> Generator[object, object, bytes]:
        try:
            yield self.marker
        finally:
            self.closed = True
        return b"never"


async def test_closing_a_continued_read_closes_the_started_one() -> None:
    marker = object()
    waiting = _Waiting(marker)
    started = waiting.__await__()
    pending = started.send(None)
    finishing = _finish_started(started, pending)
    assert finishing.send(None) is marker
    assert not waiting.closed
    finishing.close()
    assert waiting.closed


class _Response:
    def __init__(self) -> None:
        self.status_code = 200
        self.headers: dict[str, str] = {"Content-Length": "3"}

    @property
    def body(self) -> bytes:
        raise AttributeError("streamed response has no materialized body")

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        return b"abc"[:max_bytes]


async def _process(
    modifier: Callable[[GuardResponse], Awaitable[GuardResponse]],
    response: _Response,
) -> GuardResponse:
    config = SecurityConfig(enable_redis=False)
    config.custom_response_modifier = modifier
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = AsyncMock()
    factory = ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=logging.getLogger("guard_core.core.responses.factory"),
            metrics_collector=metrics,
            response_factory=MockGuardResponseFactory(),
        )
    )
    return await factory.process_response(MockGuardRequest(), response, 0.0, None)


def _count_recorders(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    made: list[int] = []
    original = RecordingHeaders.__init__

    def counting(self: RecordingHeaders, real: GuardResponseHeaders) -> None:
        made.append(1)
        original(self, real)

    monkeypatch.setattr(RecordingHeaders, "__init__", counting)
    return made


async def test_a_marked_modifier_writes_straight_through_with_no_undo_log(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    made = _count_recorders(monkeypatch)

    @reads_response_body
    async def modifier(response: GuardResponse) -> GuardResponse:
        response.headers["X-Marked"] = str(len(response.body or b""))
        return response

    response = _Response()
    await _process(modifier, response)
    assert response.headers["X-Marked"] == "3"
    assert made == []


async def test_only_the_first_call_of_a_replayed_modifier_keeps_an_undo_log(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    made = _count_recorders(monkeypatch)

    async def modifier(response: GuardResponse) -> GuardResponse:
        response.headers["X-Len"] = str(len(response.body or b""))
        return response

    response = _Response()
    await _process(modifier, response)
    assert response.headers["X-Len"] == "3"
    assert made == [1]
