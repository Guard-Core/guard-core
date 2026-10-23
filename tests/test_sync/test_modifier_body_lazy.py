import logging
from collections.abc import Callable
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from guard_core.exceptions import ResponseBodyUnavailableError
from guard_core.models import BehaviorRuleConfig, SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.events.metrics import MetricsCollector
from guard_core.sync.core.responses import reads_response_body
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory
from guard_core.sync.core.responses.modifier_view import _reported_refusals
from guard_core.sync.handlers.behavior_handler import BehaviorTracker
from tests.test_sync.conftest import MockGuardResponseFactory, SyncMockGuardRequest

_CAP = 2048


class _Streamed:
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

    def read_body_prefix(self, max_bytes: int) -> bytes:
        self.reads += 1
        return self.raw[:max_bytes]


@pytest.fixture(autouse=True)
def _fresh_sampling() -> None:
    _reported_refusals.clear()


def _factory(
    modifier: Callable[[Any], Any] | None,
    agent_handler: Any | None = None,
    **config_overrides: Any,
) -> ErrorResponseFactory:
    config = SecurityConfig(enable_redis=False, **config_overrides)
    config.custom_response_modifier = cast(Any, modifier)
    return ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=logging.getLogger("guard_core.core.responses.factory"),
            metrics_collector=MagicMock(spec=MetricsCollector),
            response_factory=MockGuardResponseFactory(),
            agent_handler=agent_handler,
        )
    )


def _apply(
    modifier: Callable[[Any], Any],
    response: _Streamed,
    method: str = "GET",
    agent_handler: Any | None = None,
    **config_overrides: Any,
) -> object:
    factory = _factory(modifier, agent_handler, **config_overrides)
    return factory.apply_modifier(
        cast(GuardResponse, response), SyncMockGuardRequest(method=method)
    )


def _reading(calls: list[Any]) -> Callable[[Any], Any]:
    def modifier(response: Any) -> Any:
        calls.append(1)
        response.headers[f"X-Call-{len(calls)}"] = "1"
        try:
            calls.append(response.body)
        except ResponseBodyUnavailableError as error:
            calls.append(error)
            response.headers["X-Refused"] = "1"
        return response

    return modifier


def test_body_access_reads_the_bounded_prefix_once_inside_one_call() -> None:
    calls: list[Any] = []
    response = _Streamed(b"x" * 100)
    assert _apply(_reading(calls), response) is response
    assert calls == [1, b"x" * 100]
    assert response.reads == 1
    assert response.headers["X-Call-1"] == "1"


def test_header_only_modifier_never_reads_ahead() -> None:
    def modifier(response: Any) -> Any:
        response.headers["X-Only"] = "1"
        return response

    response = _Streamed(b"x" * 100)
    assert _apply(modifier, response) is response
    assert response.reads == 0
    assert response.headers["X-Only"] == "1"


@pytest.mark.parametrize(
    "response, method",
    [
        (_Streamed(b"x" * (_CAP + 1)), "GET"),
        (_Streamed(b"x", declared=None), "GET"),
        (_Streamed(b"x", headers={"Content-Type": "text/event-stream"}), "GET"),
        (_Streamed(b"x"), "HEAD"),
        (_Streamed(b"", status_code=204, declared=0), "GET"),
        (_Streamed(b"", status_code=304, declared=0), "GET"),
        (_Streamed(b"z" * 10, declared=100), "GET"),
        (_Streamed(b"z" * 500, declared=100), "GET"),
    ],
)
def test_refused_body_raises_the_dedicated_error_and_keeps_header_edits(
    response: _Streamed,
    method: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list[Any] = []
    agent = MagicMock()
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = _apply(
            _reading(calls),
            response,
            method,
            agent,
            custom_response_modifier_max_body_bytes=_CAP,
        )
    assert result is response
    assert isinstance(calls[1], ResponseBodyUnavailableError)
    assert response.headers["X-Refused"] == "1"
    assert response.headers["X-Call-1"] == "1"
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1
    agent.send_event.assert_called_once()


def test_a_second_refused_access_does_not_read_or_report_again() -> None:
    def modifier(response: Any) -> Any:
        for _ in range(2):
            try:
                _ = response.body
            except ResponseBodyUnavailableError:
                response.headers["X-Seen"] = "1"
        return response

    response = _Streamed(b"z" * 10, declared=100)
    agent = MagicMock()
    _apply(modifier, response, agent_handler=agent)
    assert response.reads == 1
    agent.send_event.assert_called_once()


def test_a_raising_modifier_commits_its_earlier_writes_and_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def modifier(response: Any) -> Any:
        response.headers["X-Before"] = "1"
        _ = response.body
        raise RuntimeError("boom")

    response = _Streamed(b"x" * 10)
    with caplog.at_level(logging.ERROR):
        result = _apply(modifier, response)
    assert result is response
    assert response.headers["X-Before"] == "1"
    assert "custom_response_modifier raised" in caplog.text


def test_marked_modifier_is_called_once_like_every_sync_modifier() -> None:
    calls: list[Any] = []
    response = _Streamed(b"m" * 64)
    _apply(reads_response_body(_reading(calls)), response)
    assert calls == [1, b"m" * 64]
    assert response.reads == 1


def test_another_returned_response_is_returned() -> None:
    other = _Streamed(b"other")

    def modifier(response: Any) -> Any:
        response.headers["X-On-Original"] = "1"
        return other

    response = _Streamed(b"x")
    assert _apply(modifier, response) is other
    assert response.headers["X-On-Original"] == "1"


def test_one_prefetch_serves_the_return_pattern_scan_and_the_modifier() -> None:
    calls: list[Any] = []
    factory = _factory(
        _reading(calls),
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

    def process_global(
        request: Any, response: Any, client_ip: str, _rule_list: Any
    ) -> None:
        matched.append(tracker._check_response_pattern(response, "needle"))

    response = _Streamed(b"has a needle inside")
    result = factory.process_response(
        SyncMockGuardRequest(),
        cast(GuardResponse, response),
        0.0,
        None,
        process_global_behavioral_rules=process_global,
    )
    assert cast(object, result) is response
    assert matched == [True]
    assert response.reads == 1
    assert calls[1] == b"has a needle inside"
