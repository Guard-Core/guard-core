import random
import zlib

from guard_core.models import SyncSecurityConfig
from guard_core.sync.detection_engine.binary_islands import (
    extract_binary_islands,
    value_is_binary_like,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_CONTENT_TYPE_MULTIPART = "multipart/form-data; boundary=B0"
_CONTENT_TYPE_OCTET_STREAM = "application/octet-stream"
_CONTENT_TYPE_TEXT = "text/plain"
_SCRIPT = b"<script>alert(1)</script>"
_TAUTOLOGY = b"1 OR 1=1"


def _noise_bytes(seed: int, size: int = 4096) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(size))


def _compressed_bytes(seed: int, size: int = 65536) -> bytes:
    rng = random.Random(seed)
    return zlib.compress(bytes(rng.getrandbits(8) for _ in range(size)), 9)


def _multipart_request(body: bytes) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": _CONTENT_TYPE_MULTIPART,
            "content-length": str(len(body)),
        },
    )


def _octet_stream_request(body: bytes) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": _CONTENT_TYPE_OCTET_STREAM,
            "content-length": str(len(body)),
        },
    )


def _text_request(body: bytes) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": _CONTENT_TYPE_TEXT,
            "content-length": str(len(body)),
        },
    )


def _file_part_body(filename: str, content: bytes) -> bytes:
    return (
        b'--B0\r\nContent-Disposition: form-data; name="upload"; filename="'
        + filename.encode()
        + b'"\r\n\r\n'
        + content
        + b"\r\n--B0--\r\n"
    )


def _extract_islands(content: bytes, min_run_length: int = 16) -> list[str]:
    return extract_binary_islands(
        content.decode("utf-8", errors="surrogateescape"), min_run_length
    )


def test_extract_keeps_runs_at_or_above_min_length() -> None:
    islands = _extract_islands(b"\x00abc\x00" + b"x" * 16 + b"\x00def\x00")

    assert islands == ["x" * 16]


def test_extract_returns_runs_separately() -> None:
    islands = _extract_islands(b"\x00" + b"a" * 16 + b"\x00" + b"b" * 16 + b"\x00")

    assert islands == ["a" * 16, "b" * 16]


def test_extract_preserves_non_ascii_text_runs() -> None:
    text = "Café résumé naïve décor sélection"

    assert extract_binary_islands(text, 16) == [text]


def test_extract_below_min_run_length_returns_content() -> None:
    content = "anything\x00at all"

    assert extract_binary_islands(content, 1) == [content]


def test_extract_keeps_tab_newline_carriage_return_inside_runs() -> None:
    islands = _extract_islands(b"\x00select 1\nfrom t\r\nwhere x=1\x00")

    assert islands == ["select 1\nfrom t\r\nwhere x=1"]


def test_binary_like_rejects_text_and_accepts_noise() -> None:
    assert value_is_binary_like("") is False
    assert value_is_binary_like("plain text body with attack 1 OR 1=1") is False
    assert value_is_binary_like("one null\x00byte") is False
    assert (
        value_is_binary_like(_noise_bytes(7).decode("utf-8", errors="surrogateescape"))
        is True
    )


def test_patterns_cannot_span_separate_islands() -> None:
    run_one = b"choose one: SELECT"
    run_two = b"* FROM x" + b"Y" * 10
    payload = _compressed_bytes(17) + b"\x00" + run_one + b"\x00" + run_two + b"\x00"
    request = _multipart_request(_file_part_body("dump.bin", payload))

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is False


def test_compressed_file_part_with_short_fragment_not_detected() -> None:
    payload = _compressed_bytes(11) + b"\x00" + _TAUTOLOGY + b"\x00"
    request = _multipart_request(_file_part_body("installer.zip", payload))

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is False


def test_compressed_file_part_with_embedded_script_detected() -> None:
    payload = (
        _compressed_bytes(12) + b"\x00" + _SCRIPT + b"\x00" + _compressed_bytes(13)
    )
    request = _multipart_request(_file_part_body("page.html.bin", payload))

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True


def test_text_file_part_fully_scanned() -> None:
    payload = b"-- benign --\r\nSELECT name FROM users; " + _SCRIPT + b"\r\n"
    request = _multipart_request(_file_part_body("notes.txt", payload))

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True


def test_lower_min_run_length_restores_short_fragment_detection() -> None:
    payload = _compressed_bytes(14) + b"\x00" + _TAUTOLOGY + b"\x00"
    request = _multipart_request(_file_part_body("data.bin", payload))
    config = SyncSecurityConfig(detection_binary_min_run_length=4)

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is True


def test_octet_stream_binary_body_still_fully_scanned() -> None:
    body = _compressed_bytes(15) + b"\x00" + _TAUTOLOGY + b"\x00"
    request = _octet_stream_request(body)

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True


def test_octet_stream_binary_body_with_embedded_script_detected() -> None:
    body = _compressed_bytes(16) + b"\x00" + _SCRIPT + b"\x00"
    request = _octet_stream_request(body)

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True


def test_short_text_body_keeps_full_scan() -> None:
    request = _text_request(_TAUTOLOGY)

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True


def test_mostly_text_body_with_single_null_keeps_full_scan() -> None:
    request = _text_request(b"benign body with 1 OR 1=1\x00")

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True
