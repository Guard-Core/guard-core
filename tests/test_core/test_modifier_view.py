import logging
from typing import Any, cast

import pytest

from guard_core._utils.response_prefetch import (
    SHARED_PREFETCH,
    ResponseBodyPrefetch,
    read_shared_prefix,
)
from guard_core.core.responses.modifier_view import (
    ModifierResponseView,
    RecordingHeaders,
    _reported_refusals,
    body_gate_refusal,
    declared_content_length,
    modifier_reads_response_body,
    reads_response_body,
    report_body_refused,
)
from guard_core.exceptions import ResponseBodyUnavailableError
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse


class _Response:
    def __init__(
        self,
        headers: dict[str, str] | None = None,
        status_code: int = 200,
        prefix: object = b"",
    ) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = dict(headers or {})
        self.prefix = prefix
        self.reads = 0

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        self.reads += 1
        if isinstance(self.prefix, Exception):
            raise self.prefix
        return cast(bytes, self.prefix)[:max_bytes]


class _NoReader:
    status_code = 200
    headers: dict[str, str] = {}


def _guard(response: object) -> GuardResponse:
    return cast(GuardResponse, response)


def test_recording_headers_read_through_and_commit_in_order() -> None:
    real = {"Keep": "1", "Gone": "2", "Swap": "3"}
    recorded = RecordingHeaders(real)
    recorded["New"] = "n"
    del recorded["Gone"]
    recorded["swap"] = "4"
    assert recorded["Keep"] == "1"
    assert recorded["NEW"] == "n"
    assert "Gone" not in recorded
    assert sorted(recorded) == ["Keep", "New", "swap"]
    assert len(recorded) == 3
    assert real == {"Keep": "1", "Gone": "2", "Swap": "3"}
    recorded.commit()
    assert real == {"Keep": "1", "Swap": "3", "New": "n", "swap": "4"}


def test_recording_headers_missing_key_and_set_then_delete() -> None:
    real: dict[str, str] = {}
    recorded = RecordingHeaders(real)
    with pytest.raises(KeyError):
        del recorded["Nope"]
    with pytest.raises(KeyError):
        recorded["Nope"]
    recorded["Temp"] = "1"
    del recorded["Temp"]
    with pytest.raises(KeyError):
        recorded["Temp"]
    recorded.commit()
    assert real == {}


def test_recording_headers_support_the_mutable_mapping_helpers() -> None:
    real = {"A": "1"}
    recorded = RecordingHeaders(real)
    recorded.update({"B": "2"})
    assert recorded.pop("A") == "1"
    assert recorded.setdefault("C", "3") == "3"
    recorded.commit()
    assert real == {"B": "2", "C": "3"}
    recorded.clear()
    recorded.commit()
    assert real == {}


class _AppendingHeaders(dict[str, str]):
    def __init__(self, items: dict[str, str]) -> None:
        super().__init__(items)
        self.appended: list[tuple[str, str]] = []

    def append(self, key: str, value: str) -> None:
        self.appended.append((key, value))
        self[key] = value


def test_recording_headers_record_append_and_forward_other_attributes() -> None:
    real = _AppendingHeaders({"A": "1"})
    recorded = RecordingHeaders(real)
    recorded.append("B", "2")
    recorded.append("A", "3")
    assert recorded["B"] == "2"
    assert recorded["A"] == "1"
    assert real.appended == []
    assert recorded.appended == []
    recorded.commit()
    assert real.appended == [("B", "2"), ("A", "3")]


@pytest.mark.parametrize(
    "headers, status, method, expected",
    [
        ({"content-length": "10"}, 200, "GET", None),
        ({"CONTENT-LENGTH": "10"}, 200, "get", None),
        ({"Content-Length": " 10 "}, 200, "GET", None),
        ({"Content-Length": "abc"}, 200, "GET", "declares no Content-Length"),
        ({"Content-Length": "-1"}, 200, "GET", "declares no Content-Length"),
        ({}, 200, "GET", "declares no Content-Length"),
        ({"Content-Length": "9999999"}, 200, "GET", "is over"),
        (
            {"Content-Length": "1", "content-type": " Text/Event-Stream; x=y"},
            200,
            "GET",
            "text/event-stream",
        ),
        ({"Content-Length": "1"}, 200, "HEAD", "HEAD"),
        ({"Content-Length": "1"}, 204, "GET", "204"),
        ({"Content-Length": "1"}, 304, "GET", "304"),
        ({"Content-Length": "1"}, 101, "GET", "101"),
    ],
)
def test_gate_refusal_reasons(
    headers: dict[str, str], status: int, method: str, expected: str | None
) -> None:
    refusal = body_gate_refusal(_guard(_Response(headers, status)), method, 1024)
    if expected is None:
        assert refusal is None
    else:
        assert refusal is not None
        assert expected in refusal


def test_declared_content_length_parses_digits_only() -> None:
    assert declared_content_length(_guard(_Response({"Content-Length": "42"}))) == 42
    assert declared_content_length(_guard(_Response({"Content-Length": "4x"}))) is None


def test_marker_is_recognised_only_on_marked_callables() -> None:
    def plain() -> None: ...

    assert modifier_reads_response_body(plain) is False
    assert modifier_reads_response_body(reads_response_body(plain)) is True


def test_view_body_raises_the_dedicated_error_and_never_the_real_body() -> None:
    real: Any = _Response({"Content-Length": "3"})
    real.body = b"abc"
    view: Any = ModifierResponseView(_guard(real))
    assert hasattr(view, "body") is False
    assert view.body_requested is True
    with pytest.raises(ResponseBodyUnavailableError) as raised:
        _ = view.body
    assert isinstance(raised.value, AttributeError)


def test_view_assigned_headers_and_attributes_commit_to_the_real_response() -> None:
    real: Any = _Response({"A": "1"})
    view: Any = ModifierResponseView(_guard(real))
    view.headers = {"Z": "9"}
    view.marker = "m"
    assert view.headers == {"Z": "9"}
    assert view.marker == "m"
    view.commit()
    assert real.headers == {"Z": "9"}
    assert real.marker == "m"


def test_view_with_the_body_returns_it_and_with_a_refusal_names_it() -> None:
    view: Any = ModifierResponseView(_guard(_Response()), body=b"abc")
    assert view.body == b"abc"
    refused = ModifierResponseView(_guard(_Response()), refusal="because")
    with pytest.raises(ResponseBodyUnavailableError, match="because"):
        _ = refused.body


async def test_prefetch_reads_once_and_slices_for_each_consumer() -> None:
    response = _Response(prefix=b"0123456789")
    prefetch = ResponseBodyPrefetch(_guard(response))
    assert await prefetch.read(4, 1.0) == b"0123"
    assert await prefetch.read(3, 1.0) == b"012"
    assert response.reads == 1
    assert await prefetch.read(8, 1.0) == b"01234567"
    assert response.reads == 2
    assert await prefetch.read(8, 1.0) == b"01234567"
    assert response.reads == 2


async def test_prefetch_without_a_bounded_reader_or_on_a_failed_read_returns_none() -> (
    None
):
    assert await ResponseBodyPrefetch(_guard(_NoReader())).read(8, 1.0) is None
    failing = _Response(prefix=ConnectionResetError("reset"))
    prefetch = ResponseBodyPrefetch(_guard(failing))
    assert await prefetch.read(8, 1.0) is None
    assert await prefetch.read(16, 1.0) is None
    assert failing.reads == 1
    assert (
        await ResponseBodyPrefetch(_guard(_Response(prefix=123))).read(8, 1.0) is None
    )


async def test_prefetch_of_an_empty_body_is_empty_bytes() -> None:
    assert await ResponseBodyPrefetch(_guard(_Response(prefix=b""))).read(8, 1.0) == b""


async def test_read_shared_prefix_uses_the_shared_prefetch_only_for_its_response() -> (
    None
):
    mine = _Response(prefix=b"mine")
    other = _Response(prefix=b"other")
    token = SHARED_PREFETCH.set(ResponseBodyPrefetch(_guard(mine)))
    try:
        assert await read_shared_prefix(_guard(mine), 8, 1.0) == b"mine"
        assert await read_shared_prefix(_guard(mine), 8, 1.0) == b"mine"
        assert mine.reads == 1
        assert await read_shared_prefix(_guard(other), 8, 1.0) == b"other"
    finally:
        SHARED_PREFETCH.reset(token)
    assert await read_shared_prefix(_guard(mine), 8, 1.0) == b"mine"
    assert mine.reads == 2


def test_dedicated_error_is_exported_for_adapters() -> None:
    error: Any = ResponseBodyUnavailableError("why")
    assert error.reason == "why"


def test_view_gate_is_asked_once_and_attribute_writes_read_back() -> None:
    asked: list[int] = []

    def gate() -> str | None:
        asked.append(1)
        return "gate says no"

    view: Any = ModifierResponseView(_guard(_Response()), gate=gate)
    for _ in range(2):
        with pytest.raises(ResponseBodyUnavailableError, match="gate says no"):
            _ = view.body
    assert view.gate_refusal() == "gate says no"
    assert asked == [1]
    view.note = "n"
    assert view.note == "n"
    assert view.status_code == 200


async def test_report_body_refused_samples_per_reason_and_skips_events_without_agent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    _reported_refusals.clear()
    logger = logging.getLogger("guard_core.test_modifier_view")
    request: Any = None
    with caplog.at_level(logging.WARNING, logger=logger.name):
        await report_body_refused(
            logger, SecurityConfig(enable_redis=False), None, request, "r1"
        )
        await report_body_refused(
            logger, SecurityConfig(enable_redis=False), None, request, "r1"
        )
        await report_body_refused(
            logger,
            SecurityConfig(enable_redis=False, agent_enable_events=False),
            object(),
            request,
            "r2",
        )
    assert [r.getMessage() for r in caplog.records].count(
        "custom_response_modifier read .body but it is unavailable: r1; "
        "header edits still apply"
    ) == 1
    assert len(caplog.records) == 2
    _reported_refusals.clear()
