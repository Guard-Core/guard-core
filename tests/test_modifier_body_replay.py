import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.responses import reads_response_body
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.core.responses.modifier_view import _reported_refusals
from guard_core.exceptions import ResponseBodyUnavailableError
from guard_core.handlers.behavior_handler import BehaviorTracker
from guard_core.models import BehaviorRuleConfig, SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from tests.conftest import MockGuardRequest, MockGuardResponseFactory

_CAP = 2048


class _Streamed:
    """An adapter response with a bounded reader that counts its reads."""

    def __init__(
        self,
        body: bytes,
        headers: dict[str, str] | None = None,
        status_code: int = 200,
        declared: int | None = -1,
    ) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = dict(headers or {})
        if declared == -1:
            declared = len(body)
        if declared is not None:
            self.headers["Content-Length"] = str(declared)
        self.raw = body
        self.reads = 0

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        self.reads += 1
        return self.raw[:max_bytes]


@pytest.fixture(autouse=True)
def _fresh_sampling() -> None:
    _reported_refusals.clear()


def _factory(
    modifier: Callable[[Any], Awaitable[Any]] | None,
    agent_handler: Any | None = None,
    **config_overrides: Any,
) -> ErrorResponseFactory:
    config = SecurityConfig(enable_redis=False, **config_overrides)
    config.custom_response_modifier = modifier
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = AsyncMock()
    return ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=logging.getLogger("guard_core.core.responses.factory"),
            metrics_collector=metrics,
            response_factory=MockGuardResponseFactory(),
            agent_handler=agent_handler,
        )
    )


def _as_response(response: _Streamed) -> GuardResponse:
    return cast(GuardResponse, response)


def _same(result: object, response: object) -> bool:
    return result is response


class _Calls:
    def __init__(self) -> None:
        self.count = 0
        self.seen_body: bytes | None = None
        self.error: ResponseBodyUnavailableError | None = None


def _reading_modifier(calls: _Calls) -> Callable[[Any], Awaitable[Any]]:
    async def modifier(response: Any) -> Any:
        calls.count += 1
        response.headers[f"X-Call-{calls.count}"] = "1"
        try:
            calls.seen_body = response.body
            response.headers["X-Body-Length"] = str(len(calls.seen_body))
        except ResponseBodyUnavailableError as error:
            calls.error = error
            response.headers["X-Refused"] = "1"
        return response

    return modifier


async def _run(
    modifier: Callable[[Any], Awaitable[Any]],
    response: _Streamed,
    method: str = "GET",
    agent_handler: Any | None = None,
    **config_overrides: Any,
) -> GuardResponse:
    factory = _factory(modifier, agent_handler, **config_overrides)
    request = MockGuardRequest(method=method)
    return await factory.apply_modifier(_as_response(response), request)


async def test_body_reading_modifier_gets_the_bytes_and_only_the_replay_commits() -> (
    None
):
    calls = _Calls()
    response = _Streamed(b"x" * 100)
    result = await _run(_reading_modifier(calls), response)
    assert calls.count == 2
    assert calls.seen_body == b"x" * 100
    assert _same(result, response)
    assert "X-Call-1" not in response.headers
    assert response.headers["X-Call-2"] == "1"
    assert response.headers["X-Body-Length"] == "100"
    assert response.reads == 1


async def test_header_only_modifier_is_called_once_with_no_read_ahead() -> None:
    count = 0

    async def modifier(response: Any) -> Any:
        nonlocal count
        count += 1
        response.headers["X-Only"] = "1"
        return response

    response = _Streamed(b"x" * 100)
    result = await _run(modifier, response)
    assert (count, response.reads) == (1, 0)
    assert _same(result, response)
    assert response.headers["X-Only"] == "1"


async def test_no_modifier_never_reads_ahead() -> None:
    factory = _factory(None)
    response = _Streamed(b"x" * 100)
    request = MockGuardRequest()
    result = await factory.process_response(request, _as_response(response), 0.0, None)
    assert _same(result, response)
    assert response.reads == 0


@pytest.mark.parametrize(
    "response, method, reason",
    [
        (_Streamed(b"x" * (_CAP + 1)), "GET", "over"),
        (_Streamed(b"x" * 10, declared=None), "GET", "declares no Content-Length"),
        (
            _Streamed(b"x", headers={"Content-Type": "text/event-stream"}),
            "GET",
            "text/event-stream",
        ),
        (_Streamed(b"x"), "HEAD", "HEAD"),
        (_Streamed(b"", status_code=204, declared=0), "GET", "204"),
        (_Streamed(b"", status_code=304, declared=0), "GET", "304"),
    ],
)
async def test_refused_body_raises_dedicated_error_keeps_edits_and_never_prefetches(
    response: _Streamed,
    method: str,
    reason: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls = _Calls()
    agent = MagicMock()
    agent.send_event = AsyncMock()
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = await _run(
            _reading_modifier(calls),
            response,
            method,
            agent,
            custom_response_modifier_max_body_bytes=_CAP,
        )
    assert _same(result, response)
    assert calls.count == 1
    assert response.reads == 0
    assert isinstance(calls.error, ResponseBodyUnavailableError)
    assert isinstance(calls.error, AttributeError)
    assert reason in calls.error.reason
    assert response.headers["X-Call-1"] == "1"
    assert response.headers["X-Refused"] == "1"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "unavailable" in warnings[0].getMessage()
    agent.send_event.assert_awaited_once()
    event = agent.send_event.await_args.args[0]
    assert event.event_type == "response_body_unavailable"


async def test_first_byte_at_the_cap_is_served_and_one_past_is_refused() -> None:
    at_cap = _Streamed(b"y" * _CAP)
    calls = _Calls()
    await _run(
        _reading_modifier(calls), at_cap, custom_response_modifier_max_body_bytes=_CAP
    )
    assert calls.seen_body == b"y" * _CAP
    assert (calls.count, at_cap.reads) == (2, 1)

    past_cap = _Streamed(b"y" * (_CAP + 1))
    calls = _Calls()
    await _run(
        _reading_modifier(calls),
        past_cap,
        custom_response_modifier_max_body_bytes=_CAP,
    )
    assert calls.error is not None
    assert (calls.count, past_cap.reads) == (1, 0)


@pytest.mark.parametrize("real_length", [10, 500])
async def test_body_shorter_or_longer_than_content_length_is_refused_not_truncated(
    real_length: int,
) -> None:
    calls = _Calls()
    response = _Streamed(b"z" * real_length, declared=100)
    await asyncio.wait_for(_run(_reading_modifier(calls), response), timeout=5)
    assert calls.seen_body is None
    assert calls.error is not None
    assert (calls.count, response.reads) == (1, 1)
    assert response.headers["X-Call-1"] == "1"


async def test_a_stalled_prefetch_does_not_hang_and_keeps_the_first_call() -> None:
    class _Stalled(_Streamed):
        async def read_body_prefix(self, max_bytes: int) -> bytes:
            await asyncio.sleep(30)
            return b""

    calls = _Calls()
    response = _Stalled(b"x" * 10)
    await asyncio.wait_for(
        _run(_reading_modifier(calls), response, body_read_timeout=0.05), timeout=5
    )
    assert calls.error is not None
    assert calls.count == 1


async def test_a_replay_that_raises_commits_its_writes_before_the_raise_and_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    count = 0

    async def modifier(response: Any) -> Any:
        nonlocal count
        count += 1
        response.headers[f"X-Before-{count}"] = "1"
        body = response.body
        response.headers["X-After-Body"] = str(len(body))
        raise RuntimeError("boom")

    response = _Streamed(b"x" * 10)
    with caplog.at_level(logging.ERROR):
        result = await _run(modifier, response)
    assert _same(result, response)
    assert count == 2
    assert "X-Before-1" not in response.headers
    assert response.headers["X-Before-2"] == "1"
    assert response.headers["X-After-Body"] == "10"
    assert "custom_response_modifier raised" in caplog.text


async def test_a_modifier_that_raises_before_any_body_access_keeps_todays_behavior(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def modifier(response: Any) -> Any:
        response.headers["X-Early"] = "1"
        raise RuntimeError("boom")

    response = _Streamed(b"x")
    with caplog.at_level(logging.ERROR):
        result = await _run(modifier, response)
    assert _same(result, response)
    assert response.headers["X-Early"] == "1"
    assert "custom_response_modifier raised" in caplog.text


async def test_a_replay_never_replays() -> None:
    calls = _Calls()

    async def modifier(response: Any) -> Any:
        calls.count += 1
        _ = response.body
        _ = response.body
        return response

    response = _Streamed(b"x" * 10)
    await _run(modifier, response)
    assert (calls.count, response.reads) == (2, 1)


async def test_a_second_refused_access_reports_nothing_more() -> None:
    async def modifier(response: Any) -> Any:
        for _ in range(2):
            try:
                _ = response.body
            except ResponseBodyUnavailableError:
                response.headers["X-Seen"] = "1"
        return response

    response = _Streamed(b"x", declared=None)
    agent = MagicMock()
    agent.send_event = AsyncMock()
    await _run(modifier, response, agent_handler=agent)
    assert response.headers["X-Seen"] == "1"
    agent.send_event.assert_awaited_once()


async def test_the_refusal_warning_and_event_are_sampled_per_reason(
    caplog: pytest.LogCaptureFixture,
) -> None:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        for _ in range(3):
            await _run(
                _reading_modifier(_Calls()),
                _Streamed(b"x", headers={"Content-Type": "text/event-stream"}),
                agent_handler=agent,
            )
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1
    assert agent.send_event.await_count == 1


async def test_a_marked_modifier_is_called_once_with_the_body_read_up_front() -> None:
    calls = _Calls()
    marked = reads_response_body(_reading_modifier(calls))
    response = _Streamed(b"m" * 64)
    result = await _run(marked, response)
    assert _same(result, response)
    assert (calls.count, response.reads) == (1, 1)
    assert calls.seen_body == b"m" * 64
    assert response.headers["X-Call-1"] == "1"


async def test_a_marked_modifier_on_a_refused_response_is_called_once() -> None:
    calls = _Calls()
    marked = reads_response_body(_reading_modifier(calls))
    response = _Streamed(b"m" * (_CAP + 1))
    await _run(marked, response, custom_response_modifier_max_body_bytes=_CAP)
    assert (calls.count, response.reads) == (1, 0)
    assert calls.error is not None
    assert response.headers["X-Refused"] == "1"


async def test_a_marked_modifier_that_never_reads_the_body_reports_nothing() -> None:
    async def modifier(response: Any) -> Any:
        response.headers["X-M"] = "1"
        return response

    agent = MagicMock()
    agent.send_event = AsyncMock()
    response = _Streamed(b"x" * (_CAP + 1))
    await _run(
        reads_response_body(modifier),
        response,
        agent_handler=agent,
        custom_response_modifier_max_body_bytes=_CAP,
    )
    agent.send_event.assert_not_awaited()
    assert response.headers["X-M"] == "1"


async def test_another_returned_response_is_returned_and_writes_commit() -> None:
    other = _Streamed(b"other")

    async def modifier(response: Any) -> Any:
        response.headers["X-On-Original"] = "1"
        return other

    response = _Streamed(b"x")
    result = await _run(modifier, response)
    assert _same(result, other)
    assert response.headers["X-On-Original"] == "1"


async def test_the_view_forwards_reads_and_records_other_attribute_writes() -> None:
    seen: dict[str, Any] = {}

    async def modifier(response: Any) -> Any:
        seen["status"] = response.status_code
        response.status_code = 418
        seen["after"] = response.status_code
        seen["has_headers"] = "Content-Length" in response.headers
        response.headers["A"] = "1"
        del response.headers["A"]
        seen["len"] = len(response.headers)
        return response

    response = _Streamed(b"x")
    await _run(modifier, response)
    assert seen == {"status": 200, "after": 418, "has_headers": True, "len": 1}
    assert response.status_code == 418
    assert "A" not in response.headers


async def test_one_prefetch_serves_the_return_pattern_scan_and_the_modifier() -> None:
    calls = _Calls()
    factory = _factory(
        _reading_modifier(calls),
        behavior_scan_response_body=True,
        behavior_max_response_body_inspect_bytes=_CAP,
        custom_response_modifier_max_body_bytes=_CAP,
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="return_pattern", pattern="needle", threshold=99
            ),
        ),
    )
    tracker = BehaviorTracker(factory.context.config)
    matched: list[bool | None] = []

    async def process_global(
        request: Any, response: Any, client_ip: str, _rule_list: Any
    ) -> None:
        matched.append(await tracker._check_response_pattern(response, "needle"))

    response = _Streamed(b"has a needle inside")
    request = MockGuardRequest()
    result = await factory.process_response(
        request,
        _as_response(response),
        0.0,
        None,
        process_global_behavioral_rules=process_global,
    )
    assert _same(result, response)
    assert matched == [True]
    assert response.reads == 1
    assert calls.seen_body == b"has a needle inside"


async def test_error_responses_keep_a_directly_readable_body() -> None:
    seen: list[bytes | None] = []

    async def modifier(response: Any) -> Any:
        seen.append(response.body)
        return response

    factory = _factory(modifier)
    await factory.create_error_response(403, "Forbidden")
    assert seen == [b"Forbidden"]


async def test_a_second_consumer_asking_for_more_bytes_reads_again() -> None:
    from guard_core._utils.response_prefetch import ResponseBodyPrefetch

    response = _Streamed(b"q" * 100)
    prefetch = ResponseBodyPrefetch(_as_response(response))
    assert await prefetch.read(10, 1.0) == b"q" * 10
    assert await prefetch.read(5, 1.0) == b"q" * 5
    assert response.reads == 1
    assert await prefetch.read(100, 1.0) == b"q" * 100
    assert response.reads == 2
    assert await prefetch.read(1000, 1.0) == b"q" * 100
    assert response.reads == 3
    assert await prefetch.read(5000, 1.0) == b"q" * 100
    assert response.reads == 3
