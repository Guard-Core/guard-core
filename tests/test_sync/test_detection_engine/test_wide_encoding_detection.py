import codecs
from collections.abc import Iterator
from typing import cast

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.detection_engine.preprocessor import ContentPreprocessor
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_WIDE_ENCODINGS = ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"]

_FAMILY_PAYLOADS = {
    "xss": "<script>alert(1)</script>",
    "sqli": "1' UNION SELECT username, password FROM users--",
    "cmd_injection": "; cat /etc/passwd; ls -la",
}

_NULL_REMOVAL_DEPENDENCY_MESSAGE = (
    "wide-encoding detection depends on null-removal in "
    "ContentPreprocessor.remove_null_bytes; if you scoped or narrowed null "
    "handling, all UTF-16/32 coverage is now silently gone"
)


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> Iterator[None]:
    sus_patterns_handler.configure(SyncSecurityConfig())
    yield


def _detect(body: bytes, content_type: str = "text/plain") -> DetectionResult:
    request = SyncMockGuardRequest(
        method="POST",
        headers={"content-length": str(len(body)), "content-type": content_type},
        body_content=body,
    )
    return detect_penetration_attempt(
        cast(SyncGuardRequest, request), SyncSecurityConfig()
    )


@pytest.mark.parametrize("family", sorted(_FAMILY_PAYLOADS))
@pytest.mark.parametrize("encoding", _WIDE_ENCODINGS)
def test_wide_encoding_family_payload_is_detected(family: str, encoding: str) -> None:
    payload = _FAMILY_PAYLOADS[family]
    body = payload.encode(encoding)

    result = _detect(body)

    assert result.is_threat is True
    assert family in result.threat_categories


def test_utf16_with_bom_xss_payload_is_detected() -> None:
    body = codecs.BOM_UTF16 + _FAMILY_PAYLOADS["xss"].encode("utf-16-le")

    result = _detect(body)

    assert result.is_threat is True
    assert "xss" in result.threat_categories


def test_utf16_le_with_embedded_cjk_character_xss_payload_is_detected() -> None:
    payload = "<script>你好alert(1)</script>"
    body = payload.encode("utf-16-le")

    result = _detect(body)

    assert result.is_threat is True
    assert "xss" in result.threat_categories


@pytest.mark.parametrize("encoding", _WIDE_ENCODINGS)
def test_wide_encoding_detection_depends_on_null_removal_in_preprocessor(
    encoding: str,
) -> None:
    payload = _FAMILY_PAYLOADS["xss"]
    wide_bytes = payload.encode(encoding)
    raw_decoded = wide_bytes.decode("utf-8", errors="replace")

    assert payload not in raw_decoded, (
        "test setup assumption broke: wide-encoded bytes decoded as UTF-8 no "
        "longer interleave NUL bytes between characters, so this mechanism "
        "pin no longer isolates null-removal as the cause of wide-encoding "
        "detection"
    )

    denulled = ContentPreprocessor().remove_null_bytes(raw_decoded)

    assert payload in denulled, _NULL_REMOVAL_DEPENDENCY_MESSAGE


def test_wide_encoding_pipeline_detection_traces_to_null_removal() -> None:
    payload = _FAMILY_PAYLOADS["sqli"]
    wide_bytes = payload.encode("utf-32-be")

    result = _detect(wide_bytes)

    assert result.is_threat is True, _NULL_REMOVAL_DEPENDENCY_MESSAGE
    assert "sqli" in result.threat_categories, _NULL_REMOVAL_DEPENDENCY_MESSAGE
