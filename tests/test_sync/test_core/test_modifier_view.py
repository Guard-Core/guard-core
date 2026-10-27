import logging
from typing import Any, cast

import pytest

from guard_core.exceptions import ResponseBodyUnavailableError
from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.response_prefetch import (
    SHARED_PREFETCH,
    ResponseBodyPrefetch,
    read_shared_prefix,
)
from guard_core.sync.core.responses.modifier_view import (
    ModifierResponseView,
    RecordingHeaders,
    _reported_refusals,
    body_gate_refusal,
    declared_content_length,
    modifier_reads_response_body,
    reads_response_body,
    report_body_refused,
)


class _Response:
    def __init__(
        self,
        headers: dict[str, str] | None = None,
        status_code: int = 200,
        prefix: object = b"",
    ) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = {} if headers is None else headers
        self.prefix = prefix
        self.reads = 0

    def read_body_prefix(self, max_bytes: int) -> bytes:
        self.reads += 1
        if isinstance(self.prefix, Exception):
            raise self.prefix
        return cast(bytes, self.prefix)[:max_bytes]


class _NoReader:
    status_code = 200
    headers: dict[str, str] = {}


def _guard(response: object) -> GuardResponse:
    return cast(GuardResponse, response)


def test_undo_headers_write_through_and_undo_in_reverse() -> None:
    real = {"Keep": "1", "Gone": "2", "Swap": "3"}
    headers = RecordingHeaders(real)
    headers["New"] = "n"
    del headers["Gone"]
    headers["Swap"] = "4"
    assert real == {"Keep": "1", "Swap": "4", "New": "n"}
    assert headers["Keep"] == "1"
    assert sorted(headers) == ["Keep", "New", "Swap"]
    assert len(headers) == 3
    headers.undo()
    assert real == {"Keep": "1", "Gone": "2", "Swap": "3"}
    headers.undo()
    assert real == {"Keep": "1", "Gone": "2", "Swap": "3"}


def test_undo_headers_missing_key_and_set_then_delete() -> None:
    real: dict[str, str] = {}
    headers = RecordingHeaders(real)
    with pytest.raises(KeyError):
        del headers["Nope"]
    with pytest.raises(KeyError):
        headers["Nope"]
    headers["Temp"] = "1"
    del headers["Temp"]
    headers.undo()
    assert real == {}


def test_undo_headers_undo_tolerates_a_header_removed_behind_its_back() -> None:
    real: dict[str, str] = {}
    headers = RecordingHeaders(real)
    headers["Temp"] = "1"
    del real["Temp"]
    headers.undo()
    assert real == {}


def test_undo_headers_support_the_mutable_mapping_helpers() -> None:
    real = {"A": "1"}
    headers = RecordingHeaders(real)
    headers.update({"B": "2"})
    assert headers.pop("A") == "1"
    assert headers.setdefault("C", "3") == "3"
    assert real == {"B": "2", "C": "3"}
    headers.undo()
    assert real == {"A": "1"}


class _AppendingHeaders(dict[str, str]):
    def __init__(self, items: dict[str, str]) -> None:
        super().__init__(items)
        self.pairs: list[tuple[str, str]] = list(items.items())

    def append(self, key: str, value: str) -> None:
        self.pairs.append((key, value))
        self[key] = value

    def __setitem__(self, key: str, value: str) -> None:
        super().__setitem__(key, value)

    def items(self) -> Any:
        return list(self.pairs)

    def __delitem__(self, key: str) -> None:
        super().__delitem__(key)
        self.pairs = [pair for pair in self.pairs if pair[0] != key]


def test_undo_headers_append_is_undone_from_a_snapshot() -> None:
    real = _AppendingHeaders({"A": "1"})
    headers = RecordingHeaders(real)
    headers.append("B", "2")
    headers.append("A", "3")
    assert real.pairs == [("A", "1"), ("B", "2"), ("A", "3")]
    headers.undo()
    assert real.pairs == [("A", "1")]


def test_undo_headers_forward_other_attributes() -> None:
    real = _AppendingHeaders({"A": "1"})
    assert RecordingHeaders(real).pairs == [("A", "1")]


@pytest.mark.parametrize(
    "headers, status, method, expected",
    [
        ({"content-length": "10"}, 200, "GET", None),
        ({"CONTENT-LENGTH": "10"}, 200, "GET", None),
        ({"Content-Length": " 10 "}, 200, "GET", "declares no Content-Length"),
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


def test_declared_content_length_reads_a_lower_case_key_directly() -> None:
    assert declared_content_length(_guard(_Response({"content-length": "7"}))) == 7


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


def test_view_writes_through_and_undo_restores_headers_and_attributes() -> None:
    real: Any = _Response({"A": "1"})
    real.status_code = 200
    view: Any = ModifierResponseView(_guard(real))
    view.headers["B"] = "2"
    view.status_code = 418
    view.marker = "m"
    assert (real.headers, real.status_code, real.marker) == (
        {"A": "1", "B": "2"},
        418,
        "m",
    )
    view.undo()
    assert real.headers == {"A": "1"}
    assert real.status_code == 200


def test_view_assigned_headers_write_through_with_a_fresh_undo_log() -> None:
    real: Any = _Response({"A": "1"})
    view: Any = ModifierResponseView(_guard(real))
    view.headers = {"Z": "9"}
    view.headers["Y"] = "8"
    assert real.headers == {"Z": "9", "Y": "8"}
    view.undo()
    assert real.headers == {"A": "1"}


def test_view_with_the_body_returns_it_and_with_a_refusal_names_it() -> None:
    view: Any = ModifierResponseView(_guard(_Response()), body=b"abc")
    assert view.body == b"abc"
    refused = ModifierResponseView(_guard(_Response()), refusal="because")
    with pytest.raises(ResponseBodyUnavailableError, match="because"):
        _ = refused.body


def test_prefetch_reads_once_and_slices_for_each_consumer() -> None:
    response = _Response(prefix=b"0123456789")
    prefetch = ResponseBodyPrefetch(_guard(response))
    assert prefetch.read(4, 1.0) == b"0123"
    assert prefetch.read(3, 1.0) == b"012"
    assert response.reads == 1
    assert prefetch.read(8, 1.0) == b"01234567"
    assert response.reads == 2
    assert prefetch.read(8, 1.0) == b"01234567"
    assert response.reads == 2


def test_prefetch_without_a_bounded_reader_or_on_a_failed_read_returns_none() -> None:
    assert ResponseBodyPrefetch(_guard(_NoReader())).read(8, 1.0) is None
    failing = _Response(prefix=ConnectionResetError("reset"))
    prefetch = ResponseBodyPrefetch(_guard(failing))
    assert prefetch.read(8, 1.0) is None
    assert prefetch.read(16, 1.0) is None
    assert failing.reads == 1
    assert ResponseBodyPrefetch(_guard(_Response(prefix=123))).read(8, 1.0) is None


def test_prefetch_of_an_empty_body_is_empty_bytes() -> None:
    assert ResponseBodyPrefetch(_guard(_Response(prefix=b""))).read(8, 1.0) == b""


def test_read_shared_prefix_uses_the_shared_prefetch_only_for_its_response() -> None:
    mine = _Response(prefix=b"mine")
    other = _Response(prefix=b"other")
    token = SHARED_PREFETCH.set(ResponseBodyPrefetch(_guard(mine)))
    try:
        assert read_shared_prefix(_guard(mine), 8, 1.0) == b"mine"
        assert read_shared_prefix(_guard(mine), 8, 1.0) == b"mine"
        assert mine.reads == 1
        assert read_shared_prefix(_guard(other), 8, 1.0) == b"other"
    finally:
        SHARED_PREFETCH.reset(token)
    assert read_shared_prefix(_guard(mine), 8, 1.0) == b"mine"
    assert mine.reads == 2


def test_dedicated_error_is_exported_for_adapters() -> None:
    error: Any = ResponseBodyUnavailableError("why")
    assert error.reason == "why"


def test_view_gate_is_asked_once_and_attribute_writes_read_back() -> None:
    response = _guard(_Response({"Content-Length": "9999"}))
    view: Any = ModifierResponseView(response, gate_args=(response, "GET", 10))
    for _ in range(2):
        with pytest.raises(ResponseBodyUnavailableError, match="is over 10 bytes"):
            _ = view.body
    assert view.gate_refusal() is not None
    assert view.__dict__["_gate_args"] is None
    view.note = "n"
    assert view.note == "n"
    assert view.status_code == 200


def test_report_body_refused_samples_per_reason_and_skips_events_without_agent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    _reported_refusals.clear()
    logger = logging.getLogger("guard_core.test_modifier_view")
    request: Any = None
    with caplog.at_level(logging.WARNING, logger=logger.name):
        report_body_refused(
            logger, SyncSecurityConfig(enable_redis=False), None, request, "r1"
        )
        report_body_refused(
            logger, SyncSecurityConfig(enable_redis=False), None, request, "r1"
        )
        report_body_refused(
            logger,
            SyncSecurityConfig(enable_redis=False, agent_enable_events=False),
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


def test_commit_is_a_no_op_because_writes_go_through() -> None:
    real: Any = _Response({"A": "1"})
    view: Any = ModifierResponseView(_guard(real))
    view.headers["B"] = "2"
    view.headers.commit()
    assert view.commit() is real
    assert real.headers == {"A": "1", "B": "2"}


def test_report_body_refused_reports_again_after_the_window_and_stays_bounded(
    caplog: pytest.LogCaptureFixture,
) -> None:
    _reported_refusals.clear()
    logger = logging.getLogger("guard_core.test_modifier_view_window")
    config = SyncSecurityConfig(enable_redis=False)
    request: Any = None
    with caplog.at_level(logging.WARNING, logger=logger.name):
        report_body_refused(logger, config, None, request, "again")
        _reported_refusals["again"] -= 61
        report_body_refused(logger, config, None, request, "again")
        for index in range(70):
            report_body_refused(logger, config, None, request, f"r{index}")
    assert len(caplog.records) == 72
    assert len(_reported_refusals) <= 64
    _reported_refusals.clear()


def test_gate_refusal_method_asks_the_gate_once() -> None:
    response = _guard(_Response({"Content-Length": "9999"}))
    view: Any = ModifierResponseView(response, gate_args=(response, "GET", 10))
    assert view.gate_refusal() is not None
    assert view.gate_refusal() == view.gate_refusal()
    assert view.__dict__["_gate_args"] is None


@pytest.mark.parametrize(
    "headers, expected",
    [
        ({"Content-Type": "text/event-stream", "Content-Length": "5"}, "no end"),
        ({"Content-Type": "text/plain", "Content-Length": "5"}, None),
        ({"Content-Type": "text/plain", "content-length": " 5 "}, "no Content-Length"),
        ({"content-type": "text/plain", "Content-Length": " x "}, "no Content-Length"),
        ({"x-other": "1"}, "no Content-Length"),
        ({"content-type": "text/plain", "content-length": "5"}, None),
    ],
)
def test_gate_finds_plain_dict_headers_in_either_casing(
    headers: dict[str, str], expected: str | None
) -> None:
    refusal = body_gate_refusal(_guard(_Response(headers)), "GET", 1024)
    if expected is None:
        assert refusal is None
    else:
        assert refusal is not None
        assert expected in refusal


class _CaseInsensitive(dict[str, str]):
    def get(self, key: str, default: Any = None) -> Any:
        return super().get(key.lower(), default)


def test_gate_uses_one_lookup_for_a_case_insensitive_mapping() -> None:
    allowed = _guard(_Response(_CaseInsensitive({"content-length": "5"})))
    assert body_gate_refusal(allowed, "GET", 1024) is None
    missing = _guard(_Response(_CaseInsensitive({"x-other": "1"})))
    assert body_gate_refusal(missing, "GET", 1024) is not None


def test_a_view_that_records_no_writes_hands_out_the_real_headers() -> None:
    real: Any = _Response({"A": "1"})
    view: Any = ModifierResponseView(_guard(real), record_writes=False)
    assert view.headers is real.headers
    view.headers["B"] = "2"
    assert real.headers == {"A": "1", "B": "2"}


class _HeadersWithoutIteration:
    def __getitem__(self, key: str) -> str:
        return key

    def __setitem__(self, key: str, value: str) -> None:
        pass

    def __delitem__(self, key: str) -> None:
        pass

    def __contains__(self, key: str) -> bool:
        return True

    def get(self, key: str) -> str | None:
        return None

    def keys(self) -> list[str]:
        return []

    def items(self) -> list[tuple[str, str]]:
        return []


def test_recording_headers_over_a_container_without_iteration_raise_type_error() -> (
    None
):
    headers = RecordingHeaders(_HeadersWithoutIteration())
    with pytest.raises(TypeError, match="'_HeadersWithoutIteration' object is not"):
        iter(headers)
    with pytest.raises(TypeError, match="'_HeadersWithoutIteration' has no len"):
        len(headers)
