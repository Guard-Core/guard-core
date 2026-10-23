import json
import logging
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_SECRET = "SECRET-BLOB-BODY"


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


def _detection_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        line for line in caplog.text.splitlines() if "Potential attack detected" in line
    ]


def _single_threat_event_metadata(mock_agent: MagicMock) -> dict[str, Any]:
    pattern_detected_calls = [
        call
        for call in mock_agent.send_event.call_args_list
        if getattr(call.args[0], "event_type", None) == "pattern_detected"
    ]
    assert len(pattern_detected_calls) == 1, (
        f"expected exactly one pattern_detected event, "
        f"got {len(pattern_detected_calls)}"
    )
    return dict(pattern_detected_calls[0].args[0].metadata)


def _blob_request(body: bytes, content_type: str | None) -> SyncMockGuardRequest:
    headers = {"content-length": str(len(body))}
    if content_type is not None:
        headers["content-type"] = content_type
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers=headers,
    )


def test_text_plain_pair_body_redacts_sensitive_pair_keeps_benign_pair(
    caplog: pytest.LogCaptureFixture,
    mock_agent: MagicMock,
) -> None:
    config = SyncSecurityConfig()
    body = f"password={_SECRET}&note=<script>alert(1)</script>".encode()
    request = _blob_request(body, "text/plain")

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    expected = "password=[REDACTED]&note=<script>alert(1)</script>"
    assert expected in lines[0]
    assert _SECRET not in caplog.text

    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == expected
    assert _SECRET not in json.dumps(metadata, default=str)


def test_missing_content_type_pair_body_still_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = f"password={_SECRET}&note=<script>alert(1)</script>".encode()
    request = _blob_request(body, None)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "password=[REDACTED]&note=<script>alert(1)</script>" in lines[0]
    assert _SECRET not in caplog.text


def test_xml_sensitive_element_redacted_non_sensitive_element_kept(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = f"<user>bob</user><password>{_SECRET}</password><script>alert(1)</script>"
    request = _blob_request(body.encode(), "application/xml")

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "<user>bob</user>" in lines[0]
    assert "<password>[REDACTED]</password>" in lines[0]
    assert _SECRET not in caplog.text


def test_text_body_valid_json_redacted_like_json_content_type(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = json.dumps({"password": _SECRET, "note": "<script>alert(1)</script>"})
    request = _blob_request(body.encode(), "text/plain")

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert '"password":"[REDACTED]"' in lines[0]
    assert "<script>alert(1)</script>" in lines[0]
    assert _SECRET not in caplog.text


def test_custom_sensitive_body_field_only_pair_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_sensitive_body_fields={"custom_secret_field"})
    body = f"custom_secret_field={_SECRET}&note=<script>alert(1)</script>".encode()
    request = _blob_request(body, "text/plain")

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "custom_secret_field=[REDACTED]" in lines[0]
    assert _SECRET not in caplog.text


def test_blob_body_all_pair_separators_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = f"password={_SECRET}&a=1;b=2?c=3\nnote=<script>alert(1)</script>".encode()
    request = _blob_request(body, "text/plain")

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "password=[REDACTED]&a=1;b=2?c=3" in caplog.text
    assert "note=<script>alert(1)</script>" in caplog.text
    assert _SECRET not in caplog.text


def test_non_sensitive_blob_body_shown_verbatim(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = b"comment=<script>alert(1)</script>"
    request = _blob_request(body, "text/plain")

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    assert "comment=<script>alert(1)</script>" in caplog.text
