from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.request_size_content import (
    RequestSizeContentCheck,
)
from guard_core.sync.decorators.base import RouteConfig
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

_LOG = "guard_core.sync.core.checks.implementations.request_size_content.log_activity"


class _StreamedRequest(SyncMockGuardRequest):
    def __init__(
        self, body: bytes, headers: dict[str, str] | None = None, method: str = "POST"
    ) -> None:
        super().__init__(method=method, headers=headers or {})
        self._streamed = body

    def read_body_prefix_until_idle(self, max_bytes: int, idle_timeout: float) -> bytes:
        return self._streamed[:max_bytes]


def _check(passive_mode: bool = False) -> RequestSizeContentCheck:
    mw = MagicMock()
    mw.config = SyncSecurityConfig(enable_redis=False, passive_mode=passive_mode)
    mw.logger = MagicMock()
    mw.event_bus = MagicMock()
    mw.event_bus.send_middleware_event = MagicMock()
    mw.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    return RequestSizeContentCheck(mw)


def _with_route(
    request: SyncMockGuardRequest,
    max_request_size: int | None = None,
    allowed: list[str] | None = None,
) -> SyncMockGuardRequest:
    route = RouteConfig()
    route.max_request_size = max_request_size
    route.allowed_content_types = allowed
    request.state.route_config = route
    return request


@pytest.mark.parametrize(
    "headers", [{"transfer-encoding": "chunked"}, {}], ids=["chunked", "length-less"]
)
def test_streamed_body_over_limit_is_refused(headers: dict[str, str]) -> None:
    request = _with_route(_StreamedRequest(b"x" * 101, headers), 100)
    with patch(_LOG):
        response = _check().check(request)
    assert response is not None
    assert response.status_code == 413


@pytest.mark.parametrize(
    "headers", [{"transfer-encoding": "chunked"}, {}], ids=["chunked", "length-less"]
)
def test_streamed_body_at_limit_passes(headers: dict[str, str]) -> None:
    request = _with_route(_StreamedRequest(b"x" * 100, headers), 100)
    assert _check().check(request) is None


def test_chunked_body_over_limit_in_passive_mode_logs_and_passes() -> None:
    request = _with_route(
        _StreamedRequest(b"x" * 101, {"transfer-encoding": "chunked"}), 100
    )
    with patch(_LOG) as log:
        assert _check(passive_mode=True).check(request) is None
    log.assert_called_once()


def test_transfer_encoding_wins_over_a_small_content_length() -> None:
    headers = {"transfer-encoding": "chunked", "content-length": "5"}
    request = _with_route(_StreamedRequest(b"x" * 101, headers), 100)
    with patch(_LOG):
        response = _check().check(request)
    assert response is not None
    assert response.status_code == 413


@pytest.mark.parametrize(
    "headers",
    [{"transfer-encoding": "chunked"}, {}, {"content-length": "1"}],
    ids=["chunked", "length-less", "declared"],
)
def test_zero_max_request_size_refuses_any_body_byte(
    headers: dict[str, str],
) -> None:
    request = _with_route(_StreamedRequest(b"x", headers), 0)
    with patch(_LOG):
        response = _check().check(request)
    assert response is not None
    assert response.status_code == 413


@pytest.mark.parametrize(
    "headers",
    [{"content-length": "0"}, {}, {"transfer-encoding": "chunked"}],
    ids=["zero-length", "no-body", "empty-chunked"],
)
def test_zero_max_request_size_passes_an_empty_body(
    headers: dict[str, str],
) -> None:
    request = _with_route(_StreamedRequest(b"", headers), 0)
    assert _check().check(request) is None


def test_zero_max_request_size_in_passive_mode_logs_and_passes() -> None:
    request = _with_route(_StreamedRequest(b"x", {"content-length": "1"}), 0)
    with patch(_LOG) as log:
        assert _check(passive_mode=True).check(request) is None
    log.assert_called_once()


@pytest.mark.parametrize("value", ["abc", "", "-1", "1.5", "1 2", "+5", "0x10"])
def test_non_numeric_content_length_answers_400(value: str) -> None:
    request = _with_route(
        _StreamedRequest(b"", {"content-length": value}), max_request_size=100
    )
    with patch(_LOG) as log:
        response = _check().check(request)
    assert response is not None
    assert response.status_code == 400
    log.assert_called_once()


def test_non_numeric_content_length_in_passive_mode_logs_and_passes() -> None:
    request = _with_route(
        _StreamedRequest(b"", {"content-length": "abc"}), max_request_size=100
    )
    with patch(_LOG) as log:
        assert _check(passive_mode=True).check(request) is None
    log.assert_called_once()


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "DELETE"])
def test_bodyless_request_is_not_content_type_filtered(method: str) -> None:
    request = _with_route(
        SyncMockGuardRequest(method=method), allowed=["application/json"]
    )
    assert _check().check(request) is None


def test_zero_content_length_is_not_content_type_filtered() -> None:
    request = _with_route(
        SyncMockGuardRequest(method="DELETE", headers={"content-length": "0"}),
        allowed=["application/json"],
    )
    assert _check().check(request) is None


def test_delete_with_a_body_is_content_type_filtered() -> None:
    request = _with_route(
        SyncMockGuardRequest(
            method="DELETE",
            headers={"content-length": "4", "content-type": "text/html"},
        ),
        allowed=["application/json"],
    )
    with patch(_LOG):
        response = _check().check(request)
    assert response is not None
    assert response.status_code == 415


def test_chunked_request_without_content_type_is_filtered() -> None:
    request = _with_route(
        SyncMockGuardRequest(method="POST", headers={"transfer-encoding": "chunked"}),
        allowed=["application/json"],
    )
    with patch(_LOG):
        response = _check().check(request)
    assert response is not None
    assert response.status_code == 415


@pytest.mark.parametrize(
    "content_type",
    [
        "Application/JSON ; charset=utf-8",
        "application/json;charset=utf-8",
        " APPLICATION/json",
    ],
)
def test_media_type_is_compared_normalized(content_type: str) -> None:
    request = _with_route(
        SyncMockGuardRequest(
            method="POST",
            headers={"content-length": "2", "content-type": content_type},
        ),
        allowed=["application/json"],
    )
    assert _check().check(request) is None


def test_allowed_types_are_normalized_too() -> None:
    request = _with_route(
        SyncMockGuardRequest(
            method="POST",
            headers={"content-length": "2", "content-type": "application/json"},
        ),
        allowed=["Application/JSON"],
    )
    assert _check().check(request) is None


def test_post_with_disallowed_type_still_gets_415() -> None:
    request = _with_route(
        SyncMockGuardRequest(
            method="POST",
            headers={"content-length": "2", "content-type": "text/html; charset=x"},
        ),
        allowed=["application/json"],
    )
    with patch(_LOG):
        response = _check().check(request)
    assert response is not None
    assert response.status_code == 415
