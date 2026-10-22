import logging
from typing import cast

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import (
    _parse_content_length,
    _read_capped_body,
    detect_penetration_attempt,
)

_SQLI_BODY = b'{"q": "1 OR 1=1 UNION SELECT password FROM users--"}'


class _BodyRequest:
    def __init__(
        self, body: bytes = b"", content_length: int | str | None = None
    ) -> None:
        self._body = body
        self.query_params: dict[str, str] = {}
        self.headers: dict[str, str] = {}
        if content_length is not None:
            self.headers["content-length"] = str(content_length)
        self.url_path = "/"
        self.method = "POST"
        self.client_host = "127.0.0.1"
        self.state = type("S", (), {})()
        self.body_read = False

    def body(self) -> bytes:
        self.body_read = True
        return self._body


class _BoundedBodyReaderRequest(_BodyRequest):
    def __init__(self, body: bytes) -> None:
        super().__init__(body=body, content_length=None)
        self.prefix_requested_max_bytes: int | None = None
        self.read_body_prefix_calls = 0

    def read_body_prefix(self, max_bytes: int) -> bytes:
        self.read_body_prefix_calls += 1
        self.prefix_requested_max_bytes = max_bytes
        return self._body[:max_bytes]


def test_over_cap_declared_length_no_bounded_reader_flags_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = _BodyRequest(body=_SQLI_BODY, content_length=10_000_000)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert request.body_read is False
    assert result.is_threat is False
    assert result.body_read_error == "failed"
    assert "past detection_max_body_inspect_bytes (1024)" in result.body_read_detail
    assert "detection_max_body_inspect_bytes (1024) reached" in caplog.text
    assert "does not implement a bounded reader" in caplog.text


def test_over_cap_declared_length_bounded_reader_reads_prefix_at_the_cap(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = _BoundedBodyReaderRequest(body=_SQLI_BODY)
    request.headers["content-length"] = "10000000"
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert request.body_read is False
    assert request.prefix_requested_max_bytes == 1024
    assert result.is_threat is True
    assert "detection_max_body_inspect_bytes (1024) reached" in caplog.text


def test_at_cap_body_is_still_read_and_scanned() -> None:
    request = _BodyRequest(body=_SQLI_BODY, content_length=1024)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert request.body_read is True
    assert result.is_threat is True


def test_missing_content_length_no_bounded_reader_skips_body() -> None:
    request = _BodyRequest(body=_SQLI_BODY, content_length=None)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert request.body_read is False
    assert result.is_threat is False


def test_missing_content_length_bounded_reader_scans_within_cap() -> None:
    request = _BoundedBodyReaderRequest(body=_SQLI_BODY)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert request.body_read is False
    assert request.prefix_requested_max_bytes == 1024
    assert result.is_threat is True


def test_missing_content_length_bounded_reader_prefix_is_truncated_to_cap() -> None:
    class _OverReportingReader(_BodyRequest):
        def read_body_prefix(self, max_bytes: int) -> bytes:
            return self._body

    oversized_body = _SQLI_BODY + b"A" * 10_000
    request = _OverReportingReader(body=oversized_body, content_length=None)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert request.body_read is False
    assert result.is_threat is True


def test_missing_content_length_bounded_reader_error_not_scanned() -> None:
    class _RaisingReader(_BodyRequest):
        def read_body_prefix(self, max_bytes: int) -> bytes:
            raise RuntimeError("stream closed")

    request = _RaisingReader(body=_SQLI_BODY, content_length=None)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert request.body_read is False
    assert result.is_threat is False


def test_at_cap_body_invalid_utf8_is_read_and_scanned_lossily() -> None:
    invalid_utf8_body = b"\xff\xfe not valid utf8"
    request = _BodyRequest(
        body=invalid_utf8_body, content_length=len(invalid_utf8_body)
    )
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert request.body_read is True
    assert result.is_threat is False


def test_malformed_content_length_not_read_or_scanned() -> None:
    request = _BodyRequest(body=_SQLI_BODY, content_length="not-a-number")
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert request.body_read is False
    assert result.is_threat is False


def test_negative_content_length_not_read_or_scanned() -> None:
    request = _BodyRequest(body=_SQLI_BODY, content_length=-1)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert request.body_read is False
    assert result.is_threat is False


def test_zero_content_length_not_read_or_scanned() -> None:
    request = _BodyRequest(body=_SQLI_BODY, content_length=0)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert request.body_read is False
    assert result.is_threat is False


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1024", 1024),
        (" 1024", 1024),
        ("1024 ", 1024),
        ("\t1024\n", 1024),
        ("007", 7),
        ("+1024", None),
        ("-1024", None),
        ("1024,1024", None),
        ("0x400", None),
        ("1_024", None),
        ("۱۰۲۴", None),
        ("１０２４", None),
        ("", None),
        ("0", None),
    ],
)
def test_parse_content_length_tolerates_whitespace_rejects_malformed(
    raw: str, expected: int | None
) -> None:
    assert _parse_content_length(raw) == expected


def test_content_length_with_surrounding_whitespace_is_still_scanned() -> None:
    request = _BodyRequest(body=_SQLI_BODY, content_length=f"  {len(_SQLI_BODY)}  ")
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert request.body_read is True
    assert result.is_threat is True


def test_content_length_with_leading_plus_not_read_or_scanned() -> None:
    request = _BodyRequest(body=_SQLI_BODY, content_length=f"+{len(_SQLI_BODY)}")
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert request.body_read is False
    assert result.is_threat is False


def test_bounded_reader_returning_non_bytes_is_logged_and_not_scanned(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _StringReturningReader(_BodyRequest):
        def read_body_prefix(self, max_bytes: int) -> bytes:
            return cast(bytes, "not bytes")

    request = _StringReturningReader(body=_SQLI_BODY, content_length=None)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert request.body_read is False
    assert result.is_threat is False
    assert "read_body_prefix returned str, not bytes" in caplog.text


def test_second_capped_read_with_same_request_reuses_the_first_stream_read() -> None:
    request = _BoundedBodyReaderRequest(body=_SQLI_BODY)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    first = _read_capped_body(cast(SyncGuardRequest, request), config)
    second = _read_capped_body(cast(SyncGuardRequest, request), config)

    assert request.read_body_prefix_calls == 1
    assert first == _SQLI_BODY
    assert second == _SQLI_BODY


def test_second_capped_read_with_a_smaller_cap_slices_the_cached_prefix() -> None:
    oversized_body = _SQLI_BODY + b"A" * 4000
    request = _BoundedBodyReaderRequest(body=oversized_body)
    config = SecurityConfig(detection_max_body_inspect_bytes=4096)

    first = _read_capped_body(cast(SyncGuardRequest, request), config)
    smaller_config = SecurityConfig(detection_max_body_inspect_bytes=1024)
    second = _read_capped_body(cast(SyncGuardRequest, request), smaller_config)

    assert request.read_body_prefix_calls == 1
    assert first == oversized_body[:4096]
    assert second == oversized_body[:1024]
    assert len(second) <= 1024


def test_second_capped_read_with_a_different_request_reads_independently() -> None:
    request_a = _BoundedBodyReaderRequest(body=_SQLI_BODY)
    request_b = _BoundedBodyReaderRequest(body=_SQLI_BODY)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    _read_capped_body(cast(SyncGuardRequest, request_a), config)
    _read_capped_body(cast(SyncGuardRequest, request_b), config)

    assert request_a.read_body_prefix_calls == 1
    assert request_b.read_body_prefix_calls == 1


def test_capped_read_cache_survives_the_reader_going_single_use_empty() -> None:
    request = _BoundedBodyReaderRequest(body=_SQLI_BODY)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    first = _read_capped_body(cast(SyncGuardRequest, request), config)
    request._body = b""

    second = _read_capped_body(cast(SyncGuardRequest, request), config)

    assert request.read_body_prefix_calls == 1
    assert first == second == _SQLI_BODY


class _FlakyBoundedBodyReaderRequest(_BodyRequest):
    def __init__(self, body: bytes) -> None:
        super().__init__(body=body, content_length=None)
        self.read_body_prefix_calls = 0

    def read_body_prefix(self, max_bytes: int) -> bytes:
        self.read_body_prefix_calls += 1
        if self.read_body_prefix_calls == 1:
            raise ConnectionResetError("simulated transient network blip")
        return self._body[:max_bytes]


def test_a_transient_read_failure_is_retried_by_the_next_consumer() -> None:
    request = _FlakyBoundedBodyReaderRequest(body=_SQLI_BODY)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    first = _read_capped_body(cast(SyncGuardRequest, request), config)
    second = _read_capped_body(cast(SyncGuardRequest, request), config)

    assert first is None
    assert second == _SQLI_BODY
    assert request.read_body_prefix_calls == 2


def test_a_genuinely_empty_body_is_cached_and_not_retried() -> None:
    request = _BoundedBodyReaderRequest(body=b"")
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    first = _read_capped_body(cast(SyncGuardRequest, request), config)
    second = _read_capped_body(cast(SyncGuardRequest, request), config)

    assert first == b""
    assert second == b""
    assert request.read_body_prefix_calls == 1
