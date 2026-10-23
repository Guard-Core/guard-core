from typing import cast

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker

_CAP = 1024


class _CountingResponse:
    def __init__(self, body: bytes, status_code: int = 200) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self._body = body
        self.read_body_prefix_calls = 0

    def read_body_prefix(self, max_bytes: int) -> bytes:
        self.read_body_prefix_calls += 1
        return self._body[:max_bytes]


class _FlakyCountingResponse:
    def __init__(self, body: bytes) -> None:
        self.status_code = 200
        self.headers: dict[str, str] = {}
        self._body = body
        self.read_body_prefix_calls = 0

    def read_body_prefix(self, max_bytes: int) -> bytes:
        self.read_body_prefix_calls += 1
        if self.read_body_prefix_calls == 1:
            raise ConnectionResetError("simulated transient network blip")
        return self._body[:max_bytes]


class _SlottedResponse:
    __slots__ = ("status_code", "headers", "_body")

    def __init__(self, body: bytes, status_code: int = 200) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self._body = body

    def read_body_prefix(self, max_bytes: int) -> bytes:
        return self._body[:max_bytes]


class _PoolableResponse:
    def __init__(self) -> None:
        self.status_code = 200
        self.headers: dict[str, str] = {}
        self._body = b""

    def reset_for_next_response(self, body: bytes) -> None:
        self._body = body

    def read_body_prefix(self, max_bytes: int) -> bytes:
        return self._body[:max_bytes]


class _TeeingStreamResponse:
    def __init__(self, chunks: list[bytes], status_code: int = 200) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self._chunks = chunks
        self.chunks_consumed_by_prefix_read = 0
        self._replay_buffer: bytes | None = None
        self._leftover_chunks: list[bytes] = []

    def read_body_prefix(self, max_bytes: int) -> bytes:
        buffered = bytearray()
        consumed = 0
        for chunk in self._chunks:
            buffered.extend(chunk)
            consumed += 1
            if len(buffered) >= max_bytes:
                break

        self.chunks_consumed_by_prefix_read = consumed
        self._replay_buffer = bytes(buffered)
        self._leftover_chunks = self._chunks[consumed:]
        return bytes(buffered[:max_bytes])

    def stream_to_client(self) -> bytes:
        sent = bytearray()
        if self._replay_buffer is not None:
            sent.extend(self._replay_buffer)
            for chunk in self._leftover_chunks:
                sent.extend(chunk)
        else:
            for chunk in self._chunks:
                sent.extend(chunk)
        return bytes(sent)


def _security_config_with_cap(max_bytes: int = _CAP) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        behavior_scan_response_body=True,
        behavior_max_response_body_inspect_bytes=max_bytes,
    )


class _RaisingBodyPropertyResponse:
    def __init__(self, prefix: bytes, status_code: int = 200) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self._prefix = prefix

    @property
    def body(self) -> bytes:
        raise AttributeError("body is not available until the stream is drained")

    def read_body_prefix(self, max_bytes: int) -> bytes:
        return self._prefix[:max_bytes]


def test_response_with_raising_body_property_still_matches() -> None:
    response = _RaisingBodyPropertyResponse(b"contains attack payload here")
    config = _security_config_with_cap()
    tracker = BehaviorTracker(config)

    result = tracker._check_response_pattern(
        cast(GuardResponse, response), "attack payload"
    )

    assert result is True


def test_bounded_read_never_retains_more_than_the_cap_for_a_large_body() -> None:
    chunk_size = 100
    total_chunks = 500
    chunks = [bytes([65]) * chunk_size for _ in range(total_chunks)]
    response = _TeeingStreamResponse(chunks)
    config = _security_config_with_cap()
    tracker = BehaviorTracker(config)

    result = tracker._check_response_pattern(cast(GuardResponse, response), "needle")

    assert result is False
    consumed_bytes = response.chunks_consumed_by_prefix_read * chunk_size
    assert consumed_bytes < len(chunks) * chunk_size
    assert consumed_bytes < _CAP + chunk_size


def _numbered_chunks(count: int) -> list[bytes]:
    return [b"chunk%04d;" % i for i in range(count)]


def test_streaming_response_delivers_full_body_after_inspection() -> None:
    chunks = _numbered_chunks(200)
    original_full_body = b"".join(chunks)
    response = _TeeingStreamResponse(chunks)
    config = _security_config_with_cap()
    tracker = BehaviorTracker(config)

    tracker._check_response_pattern(cast(GuardResponse, response), "chunk0005")

    delivered = response.stream_to_client()
    assert delivered == original_full_body


def test_pattern_within_the_cap_still_matches_on_a_streaming_response() -> None:
    chunks = _numbered_chunks(200)
    response = _TeeingStreamResponse(chunks)
    config = _security_config_with_cap()
    tracker = BehaviorTracker(config)

    result = tracker._check_response_pattern(cast(GuardResponse, response), "chunk0000")

    assert result is True


def test_pattern_beyond_the_cap_is_not_matched_on_a_streaming_response() -> None:
    chunks = _numbered_chunks(200)
    response = _TeeingStreamResponse(chunks)
    config = _security_config_with_cap()
    tracker = BehaviorTracker(config)

    result = tracker._check_response_pattern(cast(GuardResponse, response), "chunk0150")

    assert result is False
    delivered = response.stream_to_client()
    assert b"chunk0150;" in delivered


def test_short_lived_stream_returns_available_bytes() -> None:
    chunks = [b"data: ping\n\n", b"data: pong\n\n"]
    response = _TeeingStreamResponse(chunks)
    config = _security_config_with_cap(65536)
    tracker = BehaviorTracker(config)

    result = tracker._check_response_pattern(cast(GuardResponse, response), "ping")

    assert result is True
    assert response.chunks_consumed_by_prefix_read == len(chunks)
    delivered = response.stream_to_client()
    assert delivered == b"".join(chunks)


@pytest.mark.parametrize("body_size", [0, 1, 1023, 1024, 1025, 10_000])
def test_cap_is_respected_across_body_sizes_around_the_boundary(
    body_size: int,
) -> None:
    body = b"X" * body_size
    response = _TeeingStreamResponse([body] if body else [])
    config = _security_config_with_cap()
    tracker = BehaviorTracker(config)

    tracker._check_response_pattern(cast(GuardResponse, response), "needle")

    delivered = response.stream_to_client()
    assert delivered == body


def test_two_return_pattern_rules_against_one_response_read_independently() -> None:
    response = _CountingResponse(b'{"status": "ok", "flag": "needle-value"}')
    config = _security_config_with_cap()
    tracker = BehaviorTracker(config)

    first = tracker._check_response_pattern(cast(GuardResponse, response), "ok")
    second = tracker._check_response_pattern(
        cast(GuardResponse, response), "needle-value"
    )

    assert first is True
    assert second is True
    assert response.read_body_prefix_calls == 2


def test_track_return_pattern_across_rules_reads_once_per_rule() -> None:
    response = _CountingResponse(b"nothing interesting here")
    config = _security_config_with_cap()
    tracker = BehaviorTracker(config)
    rules = [
        BehaviorRule(
            rule_type="return_pattern",
            threshold=0,
            window=3600,
            pattern=f"needle-{i}",
            action="log",
        )
        for i in range(4)
    ]

    for rule in rules:
        tracker.track_return_pattern(
            "ep:/api/report", "203.0.113.7", cast(GuardResponse, response), rule
        )

    assert response.read_body_prefix_calls == len(rules)


def test_two_different_responses_are_read_independently() -> None:
    response_a = _CountingResponse(b"needle-a")
    response_b = _CountingResponse(b"needle-b")
    config = _security_config_with_cap()
    tracker = BehaviorTracker(config)

    tracker._check_response_pattern(cast(GuardResponse, response_a), "needle-a")
    tracker._check_response_pattern(cast(GuardResponse, response_b), "needle-b")

    assert response_a.read_body_prefix_calls == 1
    assert response_b.read_body_prefix_calls == 1


def test_a_failed_response_body_read_is_retried_for_a_later_pattern() -> None:
    response = _FlakyCountingResponse(b'{"status":"error","code":"unauthorized"}')
    config = _security_config_with_cap()
    tracker = BehaviorTracker(config)

    first = tracker._check_response_pattern(
        cast(GuardResponse, response), "unauthorized"
    )
    second = tracker._check_response_pattern(
        cast(GuardResponse, response), "unauthorized"
    )

    assert first is None
    assert second is True
    assert response.read_body_prefix_calls == 2


def test_response_without_a_weakref_slot_still_matches_return_pattern() -> None:
    response = _SlottedResponse(b'{"status":"pwned"}')
    config = _security_config_with_cap()
    tracker = BehaviorTracker(config)

    result = tracker._check_response_pattern(cast(GuardResponse, response), "pwned")

    assert result is True


def test_pooled_response_object_reused_across_requests_is_not_stale() -> None:
    config = _security_config_with_cap()
    tracker = BehaviorTracker(config)
    pooled = _PoolableResponse()

    pooled.reset_for_next_response(b'{"error":"unauthorized"}')
    first = tracker._check_response_pattern(cast(GuardResponse, pooled), "unauthorized")

    pooled.reset_for_next_response(b'{"status":"ok"}')
    second = tracker._check_response_pattern(
        cast(GuardResponse, pooled), "unauthorized"
    )

    assert first is True
    assert second is False
