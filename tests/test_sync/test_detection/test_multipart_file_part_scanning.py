import base64
import email.message
import email.parser
import os
from typing import TextIO
from unittest.mock import patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import (
    _multipart_text_parts,
    _scan_multipart_body,
    _scan_request_body,
    detect_penetration_attempt,
)
from tests.test_sync.conftest import SyncMockGuardRequest

_CONFIG = SyncSecurityConfig()
_CONTENT_TYPE = "multipart/form-data; boundary=B0"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _body_request(payload: bytes, content_type: str) -> SyncMockGuardRequest:
    headers = {"content-length": str(len(payload))}
    if content_type:
        headers["content-type"] = content_type
    return SyncMockGuardRequest(body_content=payload, headers=headers)


def _file_part_body(filename: str, content: str, field_name: str = "file") -> bytes:
    return (
        f'--B0\r\nContent-Disposition: form-data; name="{field_name}"; '
        f'filename="{filename}"\r\nContent-Type: application/octet-stream'
        f"\r\n\r\n{content}\r\n--B0--\r\n"
    ).encode()


def _text_field_body(name: str, value: str) -> bytes:
    return (
        f'--B0\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
        f"{value}\r\n--B0--\r\n"
    ).encode()


def _raw_disposition_file_part_body(disposition_value: str, content: str) -> bytes:
    return (
        f"--B0\r\nContent-Disposition: {disposition_value}\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n{content}\r\n--B0--\r\n"
    ).encode()


def _no_name_file_part_body(filename: str, content: str) -> bytes:
    return _raw_disposition_file_part_body(f'form-data; filename="{filename}"', content)


def _no_disposition_part_body(content: str) -> bytes:
    return (f"--B0\r\nContent-Type: text/plain\r\n\r\n{content}\r\n--B0--\r\n").encode()


def _nested_multipart_mixed_file_body(
    filename: str, content: str, field_name: str = "files"
) -> bytes:
    return (
        f'--B0\r\nContent-Disposition: form-data; name="{field_name}"\r\n'
        "Content-Type: multipart/mixed; boundary=INNER\r\n\r\n"
        f'--INNER\r\nContent-Disposition: attachment; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n{content}"
        "\r\n--INNER--\r\n--B0--\r\n"
    ).encode()


@pytest.mark.parametrize("filename", ["shell.php.jpg", "evil.php%00.jpg"])
def test_malicious_upload_filename_detected(filename: str) -> None:
    request = _body_request(_file_part_body(filename, "harmless-bytes"), _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["file_upload"]


@pytest.mark.parametrize("pad_len", [254, 255, 256, 320])
def test_malicious_upload_long_filename_prefix_still_detected(
    pad_len: int,
) -> None:
    filename = "A" * pad_len + ".php.jpg"
    request = _body_request(_file_part_body(filename, "harmless-bytes"), _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["file_upload"]


def test_malicious_upload_realistic_long_filename_detected() -> None:
    filename = (
        "invoice_2026_Q1_report_report_client_summary_final_final_v2_"
        "reviewed_approved_by_finance_manager_signed_document_backup_"
        "copy_2026_do_not_delete_archived_original_scanned_version_"
        "notarized_certified_true_copy_of_the_original_final_"
        "resubmission_requested_by_client_after_audit_review_"
        "second_pass_correction_applied_before_quarterly_close.php.jpg"
    )
    assert len(filename) > 255
    request = _body_request(_file_part_body(filename, "harmless-bytes"), _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["file_upload"]


@pytest.mark.parametrize(
    ("content", "category"),
    [
        ("<script>alert(1)</script>", "xss"),
        ("1' OR '1'='1", "sqli"),
    ],
)
def test_malicious_upload_content_detected(content: str, category: str) -> None:
    request = _body_request(_file_part_body("note.txt", content), _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == [category]


_BASE64_TRANSFER_ENCODED_CATEGORY_PAYLOADS = [
    ("<script>alert(document.cookie)</script>", "xss"),
    ("' OR '1'='1' -- comment for admin bypass", "sqli"),
    (";cat /etc/passwd;whoami;id;uname -a", "cmd_injection"),
    ("*)(uid=*))(|(uid=*", "ldap"),
    ("../../../../../../etc/passwd%00.jpg", "dir_traversal"),
]


def _base64_transfer_encoded_file_part_body(content: str) -> bytes:
    encoded = base64.b64encode(content.encode()).decode()
    return (
        '--B0\r\nContent-Disposition: form-data; name="file"; '
        'filename="payload.b64"\r\nContent-Type: text/plain\r\n'
        f"Content-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--B0--\r\n"
    ).encode()


@pytest.mark.parametrize(
    ("content", "category"), _BASE64_TRANSFER_ENCODED_CATEGORY_PAYLOADS
)
def test_base64_transfer_encoded_upload_content_detected(
    content: str, category: str
) -> None:
    request = _body_request(
        _base64_transfer_encoded_file_part_body(content), _CONTENT_TYPE
    )
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert category in result.threat_categories


@pytest.mark.parametrize(
    ("content", "category"), _BASE64_TRANSFER_ENCODED_CATEGORY_PAYLOADS
)
def test_base64_transfer_encoded_upload_survives_boundary_mismatch(
    content: str, category: str
) -> None:
    raw_body = _base64_transfer_encoded_file_part_body(content).decode()
    assert (
        _multipart_text_parts(raw_body, "multipart/form-data; boundary=DOES-NOT-MATCH")
        is None
    )

    detected, trigger, threats = _scan_request_body(
        raw_body,
        "multipart/form-data; boundary=DOES-NOT-MATCH",
        set(),
        None,
        "127.0.0.1",
        "corr-1",
        "WARNING",
    )
    assert detected is True
    assert any(t.get("category") == category for t in threats)


def _decoy_prefixed_file_part_body(content: str) -> bytes:
    encoded = base64.b64encode(content.encode()).decode()
    file_bytes = f"AAAAAAAAAAAA\nB\n{encoded}"
    return _file_part_body("notes.txt", file_bytes)


@pytest.mark.parametrize(
    ("content", "category"), _BASE64_TRANSFER_ENCODED_CATEGORY_PAYLOADS
)
def test_wellformed_upload_with_decoy_prefixed_base64_content_detected(
    content: str, category: str
) -> None:
    raw_body = _decoy_prefixed_file_part_body(content)
    assert _multipart_text_parts(raw_body.decode(), _CONTENT_TYPE) is not None

    request = _body_request(raw_body, _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert category in result.threat_categories


def _fragmented_below_run_floor_file_part_body(content: str) -> bytes:
    import string

    raw = content.encode()
    chunk_bytes = 3
    parts = []
    for index in range(0, len(raw), chunk_bytes):
        decoy = string.ascii_uppercase[(index // chunk_bytes) % 26] * 12
        chunk = base64.b64encode(raw[index : index + chunk_bytes]).decode()
        parts.append(decoy)
        parts.append(chunk)
    return _file_part_body("notes.txt", "\n".join(parts))


@pytest.mark.parametrize(
    ("content", "category"), _BASE64_TRANSFER_ENCODED_CATEGORY_PAYLOADS
)
def test_wellformed_upload_with_fragmented_below_floor_base64_content_detected(
    content: str, category: str
) -> None:
    raw_body = _fragmented_below_run_floor_file_part_body(content)
    assert _multipart_text_parts(raw_body.decode(), _CONTENT_TYPE) is not None

    request = _body_request(raw_body, _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert category in result.threat_categories


def test_benign_upload_filename_and_content_not_detected() -> None:
    request = _body_request(_file_part_body("note.txt", "hello world"), _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


def test_excluded_field_name_skips_malicious_file_part() -> None:
    raw_body = _file_part_body("shell.php.jpg", "<script>alert(1)</script>").decode()
    detected, trigger, threats = _scan_multipart_body(
        raw_body,
        _CONTENT_TYPE,
        {"file"},
        None,
        "127.0.0.1",
        "corr-1",
        "WARNING",
    )
    assert detected is False


def test_no_name_file_part_still_detected_when_excluded_by_fallback_label() -> None:
    raw_body = _no_name_file_part_body(
        "shell.php.jpg", "<script>alert(1)</script>"
    ).decode()
    detected, trigger, threats = _scan_multipart_body(
        raw_body,
        _CONTENT_TYPE,
        {"file"},
        None,
        "127.0.0.1",
        "corr-1",
        "WARNING",
    )
    assert detected is True


def test_nested_multipart_no_real_name_not_suppressed_by_exclusion() -> None:
    raw_body = _nested_multipart_mixed_file_body(
        "shell.php.jpg", "<script>alert(1)</script>"
    ).decode()
    detected, trigger, threats = _scan_multipart_body(
        raw_body, _CONTENT_TYPE, {"file"}, None, "127.0.0.1", "corr-1", "WARNING"
    )
    assert detected is True


def test_no_content_disposition_part_malicious_content_detected() -> None:
    raw_body = _no_disposition_part_body("<script>alert(1)</script>").decode()
    detected, trigger, threats = _scan_multipart_body(
        raw_body, _CONTENT_TYPE, set(), None, "127.0.0.1", "corr-1", "WARNING"
    )
    assert detected is True


def test_no_content_disposition_part_excluded_field_does_not_suppress() -> None:
    raw_body = _no_disposition_part_body("<script>alert(1)</script>").decode()
    detected, trigger, threats = _scan_multipart_body(
        raw_body, _CONTENT_TYPE, {"file"}, None, "127.0.0.1", "corr-1", "WARNING"
    )
    assert detected is True


def test_text_field_without_filename_still_detected_as_before() -> None:
    request = _body_request(
        _text_field_body("comment", "<script>alert(1)</script>"), _CONTENT_TYPE
    )
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["xss"]


def test_text_field_without_filename_benign_not_detected() -> None:
    request = _body_request(_text_field_body("user_id", "1005"), _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


def test_multipart_text_parts_returns_filename_and_content_for_file_part() -> None:
    raw_body = _file_part_body("shell.php.jpg", "payload-bytes").decode()
    parts = _multipart_text_parts(raw_body, _CONTENT_TYPE)
    assert parts == [
        ("file", "file", 'filename="shell.php.jpg"'),
        (
            "file",
            "file",
            'Content-Disposition: form-data; name="file"; filename="shell.php.jpg"',
        ),
        ("file", "file", "Content-Type: application/octet-stream"),
        ("file", "file", "payload-bytes"),
    ]


def test_multipart_text_parts_scans_part_without_disposition_name() -> None:
    raw_body = (
        "--B0\r\nContent-Type: text/plain\r\n\r\nstray\r\n"
        '--B0\r\nContent-Disposition: form-data; name="ok"\r\n\r\nvalue\r\n--B0--\r\n'
    )
    parts = _multipart_text_parts(raw_body, _CONTENT_TYPE)
    assert parts == [
        (None, "file", "Content-Type: text/plain"),
        (None, "file", "stray"),
        ("ok", "ok", 'Content-Disposition: form-data; name="ok"'),
        ("ok", "ok", "value"),
    ]


def test_multipart_text_parts_no_name_file_part_has_no_exclusion_key() -> None:
    raw_body = _no_name_file_part_body("shell.php.jpg", "payload-bytes").decode()
    parts = _multipart_text_parts(raw_body, _CONTENT_TYPE)
    assert parts == [
        (None, "file", 'filename="shell.php.jpg"'),
        (None, "file", 'Content-Disposition: form-data; filename="shell.php.jpg"'),
        (None, "file", "Content-Type: application/octet-stream"),
        (None, "file", "payload-bytes"),
    ]


def test_multipart_text_parts_skips_non_string_payload() -> None:
    original_parse = email.parser.Parser.parse

    def fake_parse(
        self: email.parser.Parser, fp: TextIO, headersonly: bool = False
    ) -> email.message.Message:
        message = original_parse(self, fp, headersonly)
        for part in message.walk():
            if not part.is_multipart():
                object.__setattr__(part, "_payload", None)
        return message

    file_body = _file_part_body("shell.php.jpg", "payload-bytes").decode()
    with patch.object(email.parser.Parser, "parse", fake_parse):
        file_parts = _multipart_text_parts(file_body, _CONTENT_TYPE)
    assert file_parts == [
        ("file", "file", 'filename="shell.php.jpg"'),
        (
            "file",
            "file",
            'Content-Disposition: form-data; name="file"; filename="shell.php.jpg"',
        ),
        ("file", "file", "Content-Type: application/octet-stream"),
    ]

    text_body = _text_field_body("field", "value").decode()
    with patch.object(email.parser.Parser, "parse", fake_parse):
        text_parts = _multipart_text_parts(text_body, _CONTENT_TYPE)
    assert text_parts == [
        ("field", "field", 'Content-Disposition: form-data; name="field"'),
    ]


def test_nested_multipart_mixed_file_part_is_detected() -> None:
    request = _body_request(
        _nested_multipart_mixed_file_body("shell.php.jpg", "payload-bytes"),
        _CONTENT_TYPE,
    )
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["file_upload"]


def test_nested_multipart_mixed_matches_flat_equivalent() -> None:
    nested_request = _body_request(
        _nested_multipart_mixed_file_body("shell.php.jpg", "payload-bytes"),
        _CONTENT_TYPE,
    )
    flat_request = _body_request(
        _file_part_body("shell.php.jpg", "payload-bytes"), _CONTENT_TYPE
    )
    nested_result = detect_penetration_attempt(nested_request, _CONFIG)
    flat_result = detect_penetration_attempt(flat_request, _CONFIG)
    assert nested_result.is_threat is True
    assert flat_result.is_threat is True


def test_multipart_text_parts_uses_fallback_label_for_nested_file_part() -> None:
    raw_body = _nested_multipart_mixed_file_body(
        "shell.php.jpg", "payload-bytes"
    ).decode()
    parts = _multipart_text_parts(raw_body, _CONTENT_TYPE)
    assert parts == [
        (None, "file", 'filename="shell.php.jpg"'),
        (None, "file", 'Content-Disposition: attachment; filename="shell.php.jpg"'),
        (None, "file", "Content-Type: application/octet-stream"),
        (None, "file", "payload-bytes"),
    ]


def test_filename_with_escaped_embedded_double_quote_still_detected() -> None:
    body = _raw_disposition_file_part_body(
        'form-data; name="file"; filename="shell\\".php%00.jpg"', "harmless"
    )
    request = _body_request(body, _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["file_upload"]


def test_filename_with_embedded_single_quote_still_detected() -> None:
    body = _raw_disposition_file_part_body(
        'form-data; name="file"; filename="shell\'.php.jpg"', "harmless"
    )
    request = _body_request(body, _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["file_upload"]


def test_filename_with_embedded_newline_via_rfc2231_still_detected() -> None:
    body = _raw_disposition_file_part_body(
        "form-data; name=\"file\"; filename*=UTF-8''shell.php%0A.jpg", "harmless"
    )
    request = _body_request(body, _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["file_upload"]


def test_multipart_text_parts_strips_embedded_double_quote_from_filename() -> None:
    raw_body = _raw_disposition_file_part_body(
        'form-data; name="file"; filename="shell\\".php%00.jpg"', "harmless"
    ).decode()
    parts = _multipart_text_parts(raw_body, _CONTENT_TYPE)
    assert parts == [
        ("file", "file", 'filename="shell.php%00.jpg"'),
        (
            "file",
            "file",
            'Content-Disposition: form-data; name="file"; '
            'filename="shell\\".php%00.jpg"',
        ),
        ("file", "file", "Content-Type: application/octet-stream"),
        ("file", "file", "harmless"),
    ]


def test_multipart_text_parts_strips_embedded_single_quote_from_filename() -> None:
    raw_body = _raw_disposition_file_part_body(
        'form-data; name="file"; filename="shell\'.php.jpg"', "harmless"
    ).decode()
    parts = _multipart_text_parts(raw_body, _CONTENT_TYPE)
    assert parts == [
        ("file", "file", 'filename="shell.php.jpg"'),
        (
            "file",
            "file",
            'Content-Disposition: form-data; name="file"; filename="shell\'.php.jpg"',
        ),
        ("file", "file", "Content-Type: application/octet-stream"),
        ("file", "file", "harmless"),
    ]


def test_binary_file_content_not_detected() -> None:
    binary_blob = (bytes(range(256)) * 100).decode("latin-1")
    request = _body_request(_file_part_body("photo.jpg", binary_blob), _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


def test_malicious_filename_still_detected_with_binary_content() -> None:
    binary_blob = (bytes(range(256)) * 100).decode("latin-1")
    request = _body_request(
        _file_part_body("shell.php.jpg", binary_blob), _CONTENT_TYPE
    )
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["file_upload"]


def test_multipart_text_parts_reduces_binary_content_to_printable_islands() -> None:
    binary_blob = (bytes(range(256)) * 100).decode("latin-1")
    raw_body = _file_part_body("photo.jpg", binary_blob).decode()
    parts = _multipart_text_parts(raw_body, _CONTENT_TYPE)
    ascii_run = "".join(chr(c) for c in range(0x20, 0x7F))
    latin_run = "".join(chr(c) for c in range(0xA1, 0x100))
    assert (
        parts
        == [
            ("file", "file", 'filename="photo.jpg"'),
            (
                "file",
                "file",
                'Content-Disposition: form-data; name="file"; filename="photo.jpg"',
            ),
            ("file", "file", "Content-Type: application/octet-stream"),
        ]
        + [("file", "file", ascii_run), ("file", "file", latin_run)] * 100
    )


def _png_bytes(n: int = 4000) -> bytes:
    import random

    rng = random.Random(1)
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = b"\x00\x00\x00\rIHDR" + bytes(rng.getrandbits(8) for _ in range(17))
    idat = b"\x00\x00\x0f\xa0IDAT" + bytes(rng.getrandbits(8) for _ in range(n))
    iend = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    return sig + ihdr + idat + iend


def _jpeg_bytes(n: int = 4000) -> bytes:
    import random

    rng = random.Random(2)
    return (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        + bytes(rng.getrandbits(8) for _ in range(n))
        + b"\xff\xd9"
    )


def _gif_bytes(n: int = 4000) -> bytes:
    import random

    rng = random.Random(3)
    return b"GIF89a" + bytes(rng.getrandbits(8) for _ in range(n)) + b"\x00\x3b"


def _pdf_bytes(n: int = 4000) -> bytes:
    import random

    rng = random.Random(4)
    return (
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nstream\n"
        + bytes(rng.getrandbits(8) for _ in range(n))
        + b"\nendstream\nendobj\n%%EOF"
    )


def _zip_bytes(n: int = 4000) -> bytes:
    import random

    rng = random.Random(5)
    return (
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
        + bytes(rng.getrandbits(8) for _ in range(n))
        + b"PK\x05\x06"
        + b"\x00" * 18
    )


def _random_bytes(seed: int, n: int = 4000) -> bytes:
    import random

    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(n))


_BENIGN_BINARY_CORPUS = [
    pytest.param("photo.png", _png_bytes(), id="png"),
    pytest.param("photo.jpg", _jpeg_bytes(), id="jpeg"),
    pytest.param("anim.gif", _gif_bytes(), id="gif"),
    pytest.param("doc.pdf", _pdf_bytes(), id="pdf"),
    pytest.param("archive.zip", _zip_bytes(), id="zip"),
    pytest.param("random.bin", _random_bytes(6), id="urandom"),
    pytest.param("blob.bin", bytes(range(256)) * 20, id="full_byte_range"),
]


@pytest.mark.parametrize(("filename", "raw"), _BENIGN_BINARY_CORPUS)
def test_benign_binary_corpus_produces_no_threats(filename: str, raw: bytes) -> None:
    content = raw.decode("latin-1")
    request = _body_request(_file_part_body(filename, content), _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


def test_padded_webshell_detected_despite_binary_padding() -> None:
    payload = b"<?php system($_GET['cmd']); ?>"
    padding = os.urandom(len(payload))
    content = (payload + padding).decode("latin-1")
    request = _body_request(_file_part_body("shell.jpg", content), _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["cmd_injection"]


def test_padded_webshell_detected_with_majority_binary_padding() -> None:
    payload = b"<?php system($_GET['cmd']); ?>"
    padding = os.urandom(len(payload) * 4)
    content = (payload + padding).decode("latin-1")
    request = _body_request(_file_part_body("shell.jpg", content), _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True


def test_empty_payload_file_part_yields_no_payload_entries() -> None:
    from guard_core.sync._utils.body_form_scan import _part_payload_entries

    assert _part_payload_entries("file", "file", "empty.bin", "") == []
    assert _part_payload_entries(None, "file", None, "") == []


def test_empty_file_part_content_not_detected() -> None:
    request = _body_request(_file_part_body("empty.bin", ""), _CONTENT_TYPE)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False
