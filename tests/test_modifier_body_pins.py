import logging
from collections.abc import Awaitable, Callable
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from tests.conftest import MockGuardRequest, MockGuardResponseFactory


class _StreamedResponse:
    """What an adapter returns for a streamed route: ``body`` raises."""

    def __init__(self, raw: bytes, declared: int) -> None:
        self.status_code = 200
        self.headers = {"Content-Length": str(declared)}
        self.raw = raw
        self.reads = 0

    @property
    def body(self) -> bytes:
        raise AttributeError("streamed response has no materialized body")

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        self.reads += 1
        return self.raw[:max_bytes]


async def _process(
    modifier: Callable[[Any], Awaitable[Any]], response: _StreamedResponse
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
    return await factory.process_response(
        MockGuardRequest(), cast(GuardResponse, response), 0.0, None
    )


async def test_body_reading_modifier_on_declared_size_stream_gets_bytes() -> None:
    seen: list[bytes | None] = []

    async def modifier(response: Any) -> Any:
        seen.append(response.body)
        response.headers["X-Body-Length"] = str(len(response.body))
        return response

    response = _StreamedResponse(b"hello world", 11)
    result = await _process(modifier, response)
    assert cast(object, result) is response
    assert seen == [b"hello world"]
    assert response.headers["X-Body-Length"] == "11"


async def test_only_the_replays_header_writes_reach_the_response() -> None:
    calls = 0

    async def modifier(response: Any) -> Any:
        nonlocal calls
        calls += 1
        response.headers[f"X-Call-{calls}"] = "1"
        _ = response.body
        return response

    response = _StreamedResponse(b"abc", 3)
    await _process(modifier, response)
    assert calls == 2
    assert "X-Call-1" not in response.headers
    assert response.headers["X-Call-2"] == "1"
    assert response.reads == 1


async def test_header_only_modifier_on_declared_size_stream_reads_nothing_ahead() -> (
    None
):
    calls = 0

    async def modifier(response: Any) -> Any:
        nonlocal calls
        calls += 1
        response.headers["X-Only"] = "1"
        return response

    response = _StreamedResponse(b"abc", 3)
    await _process(modifier, response)
    assert (calls, response.reads) == (1, 0)
    assert response.headers["X-Only"] == "1"
