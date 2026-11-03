import logging
from collections.abc import Awaitable, Callable
from typing import Any, cast

import pytest

from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.exceptions import CallableShapeError
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse


class _Metrics:
    async def collect_request_metrics(self, *args: object, **kwargs: object) -> None:
        return None


class _Request:
    def __init__(self) -> None:
        self.url_path = "/api"
        self.method = "GET"
        self.headers: dict[str, str] = {}
        self.state = type("State", (), {})()


class _StreamedResponse:
    """An adapter response whose body is not in memory, so the bounded read runs."""

    def __init__(self, body: bytes) -> None:
        self.status_code = 200
        self.headers = {"Content-Length": str(len(body))}
        self._body = body

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        return self._body[:max_bytes]


async def _process(
    modifier: Callable[[GuardResponse], Awaitable[GuardResponse]],
) -> GuardResponse:
    config = SecurityConfig(enable_redis=False)
    config.custom_response_modifier = modifier
    factory = ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=logging.getLogger("guard_core.test_shape_error"),
            metrics_collector=cast(Any, _Metrics()),
            response_factory=None,
        )
    )
    return await factory.process_response(
        cast(Any, _Request()),
        cast(GuardResponse, _StreamedResponse(b"hello")),
        0.0,
        None,
    )


async def test_a_shape_error_on_the_call_that_reads_the_body_is_not_swallowed() -> None:
    calls: list[None] = []
    seen: list[bytes | None] = []

    async def modifier(response: GuardResponse) -> GuardResponse:
        calls.append(None)
        seen.append(response.body)
        if len(calls) > 1:
            raise CallableShapeError("custom_response_modifier")
        return response

    with pytest.raises(CallableShapeError):
        await _process(modifier)
    assert len(calls) == 2
