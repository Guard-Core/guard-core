import base64
import gzip
import json
import logging
import time
import zlib
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_SCRIPT = "<script>alert(1)</script>"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


@pytest.fixture
def mock_agent() -> Iterator[MagicMock]:
    agent = MagicMock()
    agent.send_event = MagicMock()
    sus_patterns_handler.agent_handler = agent
    try:
        yield agent
    finally:
        sus_patterns_handler.agent_handler = None


def _query_request(value: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path="/search", query_params={"q": value})


class _BoundedReaderRequest(SyncMockGuardRequest):
    def read_body_prefix(self, max_bytes: int) -> bytes:
        return self._body[:max_bytes]


def _body_request(
    body: bytes, content_type: str, **headers: str
) -> SyncMockGuardRequest:
    return _BoundedReaderRequest(
        method="POST",
        body_content=body,
        headers={
            "content-type": content_type,
            "content-length": str(len(body)),
            **headers,
        },
    )


def _event_metadata(mock_agent: MagicMock) -> str:
    return json.dumps(
        [
            dict(call.args[0].metadata)
            for call in mock_agent.send_event.call_args_list
            if getattr(call.args[0], "event_type", None) == "pattern_detected"
        ],
        default=str,
    )


@pytest.mark.parametrize(
    ("path", "secret", "attack_text"),
    [
        (
            "/reset/tok_9f8e7d6c5b4a3210SECRET/../../etc/passwd",
            "tok_9f8e7d6c5b4a3210SECRET",
            "etc/passwd",
        ),
        (
            "/users/alice.private@example.com/<script>alert(1)</script>",
            "alice.private@example.com",
            _SCRIPT,
        ),
        (
            "/users/alice.private%40example.com/<script>alert(1)</script>",
            "alice.private",
            _SCRIPT,
        ),
        (
            "/session/Zx9Kq3LmP0aTb7WvRn2YcD4eFh/<script>alert(1)</script>",
            "Zx9Kq3LmP0aTb7WvRn2YcD4eFh",
            _SCRIPT,
        ),
    ],
)
def test_secret_and_email_path_segments_stay_out_of_the_log_and_the_event(
    path: str,
    secret: str,
    attack_text: str,
    caplog: pytest.LogCaptureFixture,
    mock_agent: MagicMock,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(
            SyncMockGuardRequest(path=path), SyncSecurityConfig()
        )

    assert result.is_threat is True
    assert secret not in caplog.text
    assert secret not in _event_metadata(mock_agent)
    assert "[REDACTED]" in caplog.text
    assert attack_text in caplog.text


@pytest.mark.parametrize(
    "path",
    [
        "/files/Quarterly_Report_2024_Final.pdf/<script>alert(1)</script>",
        "/blog/how-to-write-a-long-readable-slug/<script>alert(1)</script>",
        "/orders/20241028/items/15/<script>alert(1)</script>",
    ],
)
def test_ordinary_path_segments_are_still_shown(
    path: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(
            SyncMockGuardRequest(path=path), SyncSecurityConfig()
        )

    assert result.is_threat is True
    assert path.rsplit("/", 1)[0] in caplog.text


_PAYLOADS = {
    "html_hex_entity_without_semicolon": ("&#x3cscript&#x3ealert(1)&#x3c/script&#x3e"),
    "hex_of_text": _SCRIPT.encode().hex(),
    "octal_escapes": "\\074script\\076alert(1)\\074/script\\076",
    "utf7": "+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
    "zlib_in_base64": base64.b64encode(zlib.compress(_SCRIPT.encode())).decode(),
    "gzip_in_base64": base64.b64encode(gzip.compress(_SCRIPT.encode())).decode(),
}


@pytest.mark.parametrize("name", sorted(_PAYLOADS))
def test_encoded_payload_in_a_query_value_is_decoded_and_flagged(
    name: str,
) -> None:
    result = detect_penetration_attempt(
        _query_request(_PAYLOADS[name]), SyncSecurityConfig()
    )

    assert result.is_threat is True, name


def test_multipart_part_with_quoted_printable_transfer_encoding_is_decoded() -> None:
    body = (
        b"--B\r\n"
        b'Content-Disposition: form-data; name="a"\r\n'
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
        b"=3Cscript=3Ealert(1)=3C/script=3E\r\n"
        b"--B--\r\n"
    )

    result = detect_penetration_attempt(
        _body_request(body, "multipart/form-data; boundary=B"), SyncSecurityConfig()
    )

    assert result.is_threat is True


def test_raw_gzip_request_body_is_decompressed_and_flagged() -> None:
    body = gzip.compress(_SCRIPT.encode())

    result = detect_penetration_attempt(
        _body_request(body, "text/plain"), SyncSecurityConfig()
    )

    assert result.is_threat is True


def test_gzip_bomb_body_ends_bounded_with_the_verdict_of_its_plain_content() -> None:
    plain = b"A" * 50_000_000
    body = gzip.compress(plain)
    assert len(body) < 100_000

    started = time.monotonic()
    result = detect_penetration_attempt(
        _body_request(body, "text/plain"), SyncSecurityConfig()
    )

    assert time.monotonic() - started < 5
    plain_result = detect_penetration_attempt(
        _body_request(plain[:300_000], "text/plain"), SyncSecurityConfig()
    )
    assert _verdict(result) == _verdict(plain_result)
    assert result.body_read_error == "failed"
    assert "unpacked content" in result.body_read_detail


def test_zlib_bomb_in_base64_ends_bounded_and_a_cut_alone_is_no_threat() -> None:
    packed = zlib.compress(b"A" * 50_000_000)
    assert len(packed) < 100_000
    value = base64.b64encode(packed).decode()

    started = time.monotonic()
    result = detect_penetration_attempt(_query_request(value), SyncSecurityConfig())

    assert time.monotonic() - started < 5
    assert result.is_threat is False


def _verdict(result: Any) -> tuple[bool, str | None]:
    return result.is_threat, result.body_read_error


def _json_lines(count: int) -> bytes:
    return "".join(
        json.dumps({"ts": 1700000000 + i, "level": "info", "msg": "request served"})
        + "\n"
        for i in range(count)
    ).encode()


@pytest.mark.parametrize(
    "content_type", ["application/octet-stream", "application/gzip"]
)
def test_benign_gzip_log_archive_keeps_the_verdict_of_its_plain_content(
    content_type: str,
) -> None:
    plain = _json_lines(60000)
    body = gzip.compress(plain)
    assert len(plain) > 1_000_000

    result = detect_penetration_attempt(_body_request(body, content_type))
    plain_result = detect_penetration_attempt(_body_request(plain, content_type))

    assert _verdict(result) == (False, None)
    assert _verdict(result) == _verdict(plain_result)


def test_zeros_gzip_body_and_a_gzip_under_the_cap_pass_like_plain() -> None:
    zeros = b"\0" * 3_000_000
    under = _json_lines(2000)
    assert len(under) < 200_000
    for plain in (zeros, under):
        result = detect_penetration_attempt(
            _body_request(gzip.compress(plain), "application/octet-stream")
        )
        assert _verdict(result) == (False, None)


_PAD = b"x" * 400_000
_DIFFERENTIAL_BODIES = {
    "benign_small": b'{"a": "hello"}',
    "attack_small": _SCRIPT.encode(),
    "benign_past_cap": _json_lines(20000),
    "attack_in_prefix_past_cap": _SCRIPT.encode() + _PAD,
    "attack_after_cap": _PAD + _SCRIPT.encode(),
    "zeros_past_cap": b"\0" * 3_000_000,
}


# Without a config a plain body is read whole and a gzip one inflates to the default
# cap, so a body whose attack starts past the cap is only compared with a config.
@pytest.mark.parametrize(
    ("name", "with_config"),
    [
        (name, with_config)
        for name in sorted(_DIFFERENTIAL_BODIES)
        for with_config in (False, True)
        if with_config or name != "attack_after_cap"
    ],
)
def test_verdict_of_a_gzip_body_equals_the_verdict_of_the_plain_body(
    name: str, with_config: bool
) -> None:
    plain = _DIFFERENTIAL_BODIES[name]
    config = SyncSecurityConfig() if with_config else None
    gz_result = detect_penetration_attempt(
        _body_request(gzip.compress(plain), "text/plain"), config
    )
    plain_result = detect_penetration_attempt(
        _body_request(plain, "text/plain"), config
    )

    assert _verdict(gz_result) == _verdict(plain_result), name


def test_attack_inside_the_inflated_prefix_of_a_big_gzip_is_flagged() -> None:
    result = detect_penetration_attempt(
        _body_request(gzip.compress(_SCRIPT.encode() + _PAD * 10), "text/plain")
    )

    assert result.is_threat is True


_SQLI = "' UNION SELECT username,password FROM users--"
_WORDS = "quarterly onboarding metrics for the regional sales team include revenue "


def _padding(size: int) -> str:
    return (_WORDS * (size // len(_WORDS) + 1))[:size]


_VALUE_CONTENTS = {
    "benign_small": "just some ordinary words in a value",
    "attack_small": _SQLI,
    "benign_past_cap": _padding(600_000),
    "attack_at_end_past_cap": _padding(600_000) + _SQLI,
    "attack_at_start_past_cap": _SQLI + _padding(600_000),
    "attack_at_end_under_cap": _padding(100_000) + _SQLI,
}


@pytest.mark.parametrize("fail_secure", [True, False])
@pytest.mark.parametrize("pack", [gzip.compress, zlib.compress])
@pytest.mark.parametrize("name", sorted(_VALUE_CONTENTS))
def test_b64_compressed_value_verdict_equals_the_plain_value_verdict(
    name: str, pack: Any, fail_secure: bool
) -> None:
    content = _VALUE_CONTENTS[name]
    config = SyncSecurityConfig(fail_secure=fail_secure)
    packed_value = base64.b64encode(pack(content.encode())).decode()

    packed = detect_penetration_attempt(
        _body_request(json.dumps({"blob": packed_value}).encode(), "application/json"),
        config,
    )
    plain = detect_penetration_attempt(
        _body_request(json.dumps({"blob": content}).encode(), "application/json"),
        config,
    )

    assert _verdict(packed) == _verdict(plain), name


@pytest.mark.parametrize("fail_secure", [True, False])
@pytest.mark.parametrize("name", sorted(_VALUE_CONTENTS))
def test_verdict_of_a_gzip_json_body_equals_the_verdict_of_its_plain_body(
    name: str, fail_secure: bool
) -> None:
    plain_body = json.dumps({"blob": _VALUE_CONTENTS[name]}).encode()
    config = SyncSecurityConfig(fail_secure=fail_secure)

    packed = detect_penetration_attempt(
        _body_request(gzip.compress(plain_body), "application/json"), config
    )
    plain = detect_penetration_attempt(
        _body_request(plain_body, "application/json"), config
    )

    assert _verdict(packed) == _verdict(plain), name


def test_a_cut_value_and_a_cut_body_name_the_unpacked_content() -> None:
    value = base64.b64encode(gzip.compress(_padding(600_000).encode())).decode()
    by_value = detect_penetration_attempt(
        _body_request(json.dumps({"blob": value}).encode(), "application/json"),
        SyncSecurityConfig(),
    )
    by_body = detect_penetration_attempt(
        _body_request(gzip.compress(b"\0" * 300_000), "application/json"),
        SyncSecurityConfig(),
    )

    assert "unpacked content" in by_value.body_read_detail
    assert "bomb" not in by_value.body_read_detail
    assert "unpacked content" in by_body.body_read_detail
    assert "likely decompression bomb" in by_body.body_read_detail
    assert "detection_max_body_inspect_bytes" in by_body.body_read_detail


@pytest.mark.parametrize(
    "value",
    [
        "0123456789abcdef0123456789abcdef",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "550e8400e29b41d4a716446655440000",
        "/var/2024/12/001/177/file.txt",
        "price+10-20",
        "1+2-3 and a+bcd-e",
    ],
)
def test_hashes_ids_and_plain_text_stay_clean(value: Any) -> None:
    result = detect_penetration_attempt(_query_request(value), SyncSecurityConfig())

    assert result.is_threat is False, value


def test_decoders_leave_what_is_not_text_alone() -> None:
    from guard_core.sync.detection_engine import encoding_decoders as d

    assert d.decode_html_hex_entities_without_semicolon("&#x01abc") == "&#x01abc"
    assert d.decode_html_hex_entities_without_semicolon("&#x3ea;") == "&#x3ea;"
    assert d.decode_html_hex_entities_without_semicolon("plain") == "plain"
    assert d.decode_html_hex_entities_without_semicolon("&#x3ealert") == ">alert"
    assert d.decode_octal_escapes("\\001 \\377") == "\\001 \\377"
    assert d.decode_octal_escapes("no escape") == "no escape"
    assert d.decode_octal_escapes("\\074a") == "<a"
    assert d.decode_hex_text_runs("deadbeefcafebabe") == "deadbeefcafebabe"
    assert d.decode_hex_text_runs("0x2f6574632f706173737764") == (
        "0x2f6574632f706173737764"
    )
    assert d.decode_utf7_shifted_runs("a+b") == "a+b"
    assert d.decode_utf7_shifted_runs("a+AAA-b") == "a+AAA-b"
    assert d.decode_utf7_shifted_runs("a+bcd-e") == "a+bcd-e"
    assert d.decode_utf7_shifted_runs("+ADw-") == "<"


def test_bounded_inflate_only_takes_gzip_and_zlib_streams() -> None:
    from guard_core.sync.detection_engine.compressed_payloads import (
        bounded_inflate,
        looks_like_zlib,
    )

    assert looks_like_zlib(b"x") is False
    assert bounded_inflate(b"plain text", 1000) is None
    assert bounded_inflate(b"\x1f\x8b" + b"\x00" * 30, 1000) is None
    assert bounded_inflate(zlib.compress(b"abc"), 1000) == (b"abc", False)
    assert bounded_inflate(gzip.compress(b"abc"), 1000) == (b"abc", False)
    assert bounded_inflate(zlib.compress(b"A" * 1_000_000), 1000) == (b"A" * 1000, True)


def test_the_bomb_wording_follows_the_ratio_and_the_allowance_only() -> None:
    from guard_core.sync.detection_engine.compressed_payloads import (
        is_likely_decompression_bomb,
    )

    assert is_likely_decompression_bomb(1000, 3_000_000) is True
    assert is_likely_decompression_bomb(1000, 50_000) is False
    assert is_likely_decompression_bomb(10, 1000) is False


def test_quoted_printable_entries_need_a_text_payload_that_changes() -> None:
    from guard_core.sync._utils.body_form_scan import _quoted_printable_payload_entries

    class _Part:
        def __init__(self, encoding: str) -> None:
            self._encoding = encoding

        def items(self) -> list[tuple[str, str]]:
            return [("Content-Transfer-Encoding", self._encoding)]

        def get_param(self, param: str, /, *, header: str) -> object:
            return None

        def get_filename(self) -> str | None:
            return None

        def get_params(self, *, header: str) -> list[tuple[str, str]] | None:
            return None

    qp = _Part(" Quoted-Printable ")
    assert _quoted_printable_payload_entries(qp, "a", "a", b"=3C") == []
    assert _quoted_printable_payload_entries(qp, "a", "a", "plain") == []
    assert _quoted_printable_payload_entries(qp, "a", "a", "=3Cb") == [("a", "a", "<b")]
    assert _quoted_printable_payload_entries(_Part("base64"), "a", "a", "=3Cb") == []
