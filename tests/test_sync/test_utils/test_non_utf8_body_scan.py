import hashlib
from typing import cast

from pytest_mock import MockerFixture

from guard_core.models import SyncSecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import detect_penetration_attempt


class _BodyRequest:
    def __init__(self, body: bytes, content_length: int | None = None) -> None:
        self._body = body
        self.query_params: dict[str, str] = {}
        self.headers: dict[str, str] = {
            "content-length": str(
                content_length if content_length is not None else len(body)
            )
        }
        self.url_path = "/"
        self.method = "POST"
        self.client_host = "127.0.0.1"
        self.state = type("S", (), {})()
        self.body_read = False

    def body(self) -> bytes:
        self.body_read = True
        return self._body


_CONFIG = SyncSecurityConfig(detection_max_body_inspect_bytes=65536)


def _png_bytes() -> bytes:
    return bytes.fromhex(
        "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
        "1f15c4890000000a49444154789c636000000200010"
        "0ffff030000060005574bb1060000000049454e44ae426082"
    )


def _detect(body: bytes) -> tuple[bool, str]:
    request = _BodyRequest(body=body)
    result = detect_penetration_attempt(cast(SyncGuardRequest, request), _CONFIG)
    return result.is_threat, result.trigger_info


def test_latin1_body_with_embedded_sqli_is_detected() -> None:
    body = ("café " + "1' OR '1'='1").encode("latin-1")
    is_threat, _ = _detect(body)
    assert is_threat is True


def test_invalid_utf8_prefix_before_xss_is_detected() -> None:
    body = b"\xff\xfe<script>alert(1)</script>"
    is_threat, _ = _detect(body)
    assert is_threat is True


def test_valid_sqli_with_trailing_invalid_byte_is_detected() -> None:
    body = b"1' OR '1'='1" + b"\xff"
    is_threat, _ = _detect(body)
    assert is_threat is True


def test_binary_blob_with_embedded_base64_serialized_payload_is_detected() -> None:
    body = b"\x00\x01\x02\xff\xfe" + b"rO0ABXNyABFqYXZhLnV0aWw=" + b"\x00\x01"
    is_threat, _ = _detect(body)
    assert is_threat is True


def test_body_of_only_invalid_bytes_is_not_a_false_positive() -> None:
    body = b"\xff" * 50
    is_threat, _ = _detect(body)
    assert is_threat is False
    assert body.decode("utf-8", errors="replace") == "�" * 50


def test_real_png_binary_upload_stays_clean() -> None:
    is_threat, _ = _detect(_png_bytes())
    assert is_threat is False


def test_latin1_accented_benign_text_stays_clean() -> None:
    body = "café résumé naïve".encode("latin-1")
    is_threat, _ = _detect(body)
    assert is_threat is False


def test_protobuf_like_binary_blob_stays_clean() -> None:
    body = (
        b"\x08\x96\x01"
        b"\x12\x07example"
        b"\x1a\x03foo"
        b"\x22\x04user"
        b"\x28\x01"
        b"\xff\xfe\x00\x01\x02\x03"
    )
    is_threat, _ = _detect(body)
    assert is_threat is False


def test_deterministic_pseudo_random_binary_blob_stays_clean() -> None:
    body = b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(8))
    is_threat, _ = _detect(body)
    assert is_threat is False


def test_body_decode_boundary_uses_surrogateescape_not_replace(
    mocker: MockerFixture,
) -> None:
    captured: dict[str, str] = {}

    def _capture_raw_body(
        raw_body: str, *args: object, **kwargs: object
    ) -> tuple[bool, str, list[dict]]:
        captured["raw_body"] = raw_body
        return False, "", []

    mocker.patch(
        "guard_core.sync._utils.penetration_detection._scan_request_body",
        side_effect=_capture_raw_body,
    )

    body = b"\xff\xfe<script>alert(1)</script>"
    request = _BodyRequest(body=body)
    detect_penetration_attempt(cast(SyncGuardRequest, request), _CONFIG)

    assert captured["raw_body"] == body.decode("utf-8", errors="surrogateescape")
    assert captured["raw_body"] != body.decode("utf-8", errors="replace")
