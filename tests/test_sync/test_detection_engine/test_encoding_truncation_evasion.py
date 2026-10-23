import base64
import gzip
from collections.abc import Iterator
from typing import cast

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_MARKER = "1' UNION SELECT username, password FROM users--"
_BLIND_MARKER = "1' OR '1'='1"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> Iterator[None]:
    sus_patterns_handler.configure(SyncSecurityConfig())
    yield


def _json_body_request(payload: str) -> SyncMockGuardRequest:
    body = f'{{"q": "{payload}"}}'.encode()
    return SyncMockGuardRequest(
        method="POST",
        headers={"content-length": str(len(body)), "content-type": "application/json"},
        body_content=body,
    )


def _is_threat(payload: str) -> bool:
    request = _json_body_request(payload)
    result = detect_penetration_attempt(
        cast(SyncGuardRequest, request), SyncSecurityConfig()
    )
    return result.is_threat


def test_baseline_marker_is_detected_unwrapped() -> None:
    assert _is_threat(_MARKER) is True


def test_base64_mime_whitespace_wrapped_marker_is_detected() -> None:
    single_b64 = base64.b64encode(_MARKER.encode()).decode()
    wrapped = "\n".join(single_b64[i : i + 20] for i in range(0, len(single_b64), 20))

    assert _is_threat(wrapped) is True


def test_base64_crlf_wrapped_marker_is_detected() -> None:
    single_b64 = base64.b64encode(_MARKER.encode()).decode()
    wrapped = "\r\n".join(single_b64[i : i + 20] for i in range(0, len(single_b64), 20))

    assert _is_threat(wrapped) is True


def test_gzip_then_base64_marker_is_detected() -> None:
    gz_b64 = base64.b64encode(gzip.compress(_MARKER.encode())).decode()

    assert _is_threat(gz_b64) is True


def test_double_base64_depth_2_marker_is_detected() -> None:
    depth_2 = base64.b64encode(base64.b64encode(_MARKER.encode())).decode()

    assert _is_threat(depth_2) is True


def test_double_base64_depth_8_marker_is_detected() -> None:
    content = _MARKER.encode()
    for _ in range(8):
        content = base64.b64encode(content)

    assert _is_threat(content.decode()) is True


def test_truncation_front_placed_marker_is_detected() -> None:
    body = _BLIND_MARKER + " " + "B" * 20000

    assert _is_threat(body) is True


def test_truncation_back_placed_marker_is_detected() -> None:
    body = "A" * 20000 + " " + _BLIND_MARKER

    assert _is_threat(body) is True


def test_truncation_dead_center_placed_marker_is_detected() -> None:
    body = "A" * 100000 + " " + _BLIND_MARKER + " " + "B" * 100000

    assert _is_threat(body) is True


def test_malformed_content_length_still_scans_body_via_prefix_reader() -> None:
    class _BoundedBodyReaderRequest(SyncMockGuardRequest):
        def read_body_prefix(self, max_bytes: int) -> bytes:
            return self._body[:max_bytes]

    body = f'{{"q": "{_MARKER}"}}'.encode()
    request = _BoundedBodyReaderRequest(
        method="POST",
        headers={"content-length": "not-a-number", "content-type": "application/json"},
        body_content=body,
    )

    result = detect_penetration_attempt(
        cast(SyncGuardRequest, request), SyncSecurityConfig()
    )

    assert result.is_threat is True


def test_negative_content_length_still_scans_body_via_prefix_reader() -> None:
    class _BoundedBodyReaderRequest(SyncMockGuardRequest):
        def read_body_prefix(self, max_bytes: int) -> bytes:
            return self._body[:max_bytes]

    body = f'{{"q": "{_MARKER}"}}'.encode()
    request = _BoundedBodyReaderRequest(
        method="POST",
        headers={"content-length": "-1", "content-type": "application/json"},
        body_content=body,
    )

    result = detect_penetration_attempt(
        cast(SyncGuardRequest, request), SyncSecurityConfig()
    )

    assert result.is_threat is True


def test_short_single_base64_blind_marker_is_detected() -> None:
    single_b64 = base64.b64encode(_BLIND_MARKER.encode()).decode()

    assert _is_threat(single_b64) is True


def test_short_double_base64_blind_marker_is_detected() -> None:
    double_b64 = base64.b64encode(base64.b64encode(_BLIND_MARKER.encode())).decode()

    assert _is_threat(double_b64) is True


_REPRESENTATIVE_SHORT_BENIGN_TOKENS = [
    ("uuid_dashed", "550e8400-e29b-41d4-a716-446655440000"),
    ("uuid_nodash", "550e8400e29b41d4a716446655440000"),
    ("git_sha_short7", "a1b2c3d"),
    ("git_sha_full40", "a3f5e7d9c1b3a5f7e9d1c3b5a7f9e1d3c5b7a9f1"),
    ("md5_hash", "5d41402abc4b2a76b9719d911017c592"),
    ("session_token", "sess_9f8a7b6c5d4e3f2a"),
    ("product_key", "XK7M2-9PQRT-4WZLB-8NCFY-3HJDV"),
    ("jwt_header_fragment", "eyJhbGciOiJIUzI1"),
    ("png_fragment", "iVBORw0KGgoAAAA"),
    ("api_key", "sk_live_4eC39HqLyjW"),
    ("etag_weak", "W/a1b2c3d4e5f6"),
    ("csp_nonce", "R2V0R2V0R2V0R2V0"),
    ("numeric_id", "9876543210123456"),
    ("slug_fragment", "quarterlyreport2024"),
]


@pytest.mark.parametrize(
    ("label", "token"),
    _REPRESENTATIVE_SHORT_BENIGN_TOKENS,
    ids=[label for label, _ in _REPRESENTATIVE_SHORT_BENIGN_TOKENS],
)
def test_representative_short_benign_tokens_stay_clean(label: str, token: str) -> None:
    assert _is_threat(token) is False


def test_oversized_declared_content_length_still_scans_the_actual_body() -> None:
    class _BoundedBodyReaderRequest(SyncMockGuardRequest):
        def read_body_prefix(self, max_bytes: int) -> bytes:
            return self._body[:max_bytes]

    body = f'{{"q": "{_MARKER}"}}'.encode()
    config = SyncSecurityConfig(detection_max_body_inspect_bytes=1024)
    request = _BoundedBodyReaderRequest(
        method="POST",
        headers={"content-length": "10000000", "content-type": "application/json"},
        body_content=body,
    )

    result = detect_penetration_attempt(cast(SyncGuardRequest, request), config)

    assert result.is_threat is True
