import base64
import gzip
import json
import logging
import time
import zlib
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_SCRIPT = "<script>alert(1)</script>"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


@pytest.fixture
def mock_agent() -> Iterator[MagicMock]:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    sus_patterns_handler.agent_handler = agent
    try:
        yield agent
    finally:
        sus_patterns_handler.agent_handler = None


def _query_request(value: str) -> MockGuardRequest:
    return MockGuardRequest(path="/search", query_params={"q": value})


def _body_request(body: bytes, content_type: str, **headers: str) -> MockGuardRequest:
    return MockGuardRequest(
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
async def test_secret_and_email_path_segments_stay_out_of_the_log_and_the_event(
    path: str,
    secret: str,
    attack_text: str,
    caplog: pytest.LogCaptureFixture,
    mock_agent: MagicMock,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = await detect_penetration_attempt(
            MockGuardRequest(path=path), SecurityConfig()
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
async def test_ordinary_path_segments_are_still_shown(
    path: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = await detect_penetration_attempt(
            MockGuardRequest(path=path), SecurityConfig()
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
async def test_encoded_payload_in_a_query_value_is_decoded_and_flagged(
    name: str,
) -> None:
    result = await detect_penetration_attempt(
        _query_request(_PAYLOADS[name]), SecurityConfig()
    )

    assert result.is_threat is True, name


async def test_multipart_part_with_quoted_printable_transfer_encoding_is_decoded() -> (
    None
):
    body = (
        b"--B\r\n"
        b'Content-Disposition: form-data; name="a"\r\n'
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
        b"=3Cscript=3Ealert(1)=3C/script=3E\r\n"
        b"--B--\r\n"
    )

    result = await detect_penetration_attempt(
        _body_request(body, "multipart/form-data; boundary=B"), SecurityConfig()
    )

    assert result.is_threat is True


async def test_raw_gzip_request_body_is_decompressed_and_flagged() -> None:
    body = gzip.compress(_SCRIPT.encode())

    result = await detect_penetration_attempt(
        _body_request(body, "text/plain"), SecurityConfig()
    )

    assert result.is_threat is True


async def test_gzip_bomb_body_ends_bounded_and_is_not_a_clean_pass() -> None:
    body = gzip.compress(b"A" * 50_000_000)
    assert len(body) < 100_000

    started = time.monotonic()
    result = await detect_penetration_attempt(
        _body_request(body, "text/plain"), SecurityConfig()
    )

    assert time.monotonic() - started < 5
    assert result.body_read_error == "failed"
    assert "inflates past" in result.body_read_detail


async def test_zlib_bomb_in_base64_ends_bounded_and_is_not_a_clean_pass() -> None:
    packed = zlib.compress(b"A" * 50_000_000)
    assert len(packed) < 100_000
    value = base64.b64encode(packed).decode()

    started = time.monotonic()
    result = await detect_penetration_attempt(_query_request(value), SecurityConfig())

    assert time.monotonic() - started < 5
    assert result.is_threat is True


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
async def test_hashes_ids_and_plain_text_stay_clean(value: Any) -> None:
    result = await detect_penetration_attempt(_query_request(value), SecurityConfig())

    assert result.is_threat is False, value


def test_decoders_leave_what_is_not_text_alone() -> None:
    from guard_core.detection_engine import encoding_decoders as d

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
    from guard_core.detection_engine.compressed_payloads import (
        bounded_inflate,
        looks_like_zlib,
    )

    assert looks_like_zlib(b"x") is False
    assert bounded_inflate(b"plain text", 1000) is None
    assert bounded_inflate(b"\x1f\x8b" + b"\x00" * 30, 1000) is None
    assert bounded_inflate(zlib.compress(b"abc"), 1000) == (b"abc", False)
    assert bounded_inflate(gzip.compress(b"abc"), 1000) == (b"abc", False)
    inflated, cut = bounded_inflate(zlib.compress(b"A" * 1_000_000), 1_000_000) or (
        b"",
        False,
    )
    assert cut is True
    assert len(inflated) <= 100 * len(zlib.compress(b"A" * 1_000_000))


def test_quoted_printable_entries_need_a_text_payload_that_changes() -> None:
    from guard_core._utils.body_form_scan import _quoted_printable_payload_entries

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
