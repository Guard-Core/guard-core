import logging
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_SECRET = "SECRET-MALFORMED-MULTIPART"


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


def _wrong_boundary_body() -> bytes:
    return (
        f'--WRONG\r\nContent-Disposition: form-data; name="password"\r\n\r\n'
        f"{_SECRET} <script>alert(1)</script>\r\n--WRONG--\r\n"
    ).encode()


def test_malformed_multipart_boundary_log_line_shows_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = _wrong_boundary_body()
    request = SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": "multipart/form-data; boundary=B0",
            "content-length": str(len(body)),
        },
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _SECRET not in caplog.text
    assert "<script>" not in caplog.text


def test_malformed_multipart_boundary_event_content_preview_redacted(
    mock_agent: MagicMock,
) -> None:
    config = SyncSecurityConfig()
    body = _wrong_boundary_body()
    request = SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": "multipart/form-data; boundary=B0",
            "content-length": str(len(body)),
        },
    )

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert _SECRET not in str(metadata)


def test_well_formed_multipart_boundary_still_scans_normally(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = (
        f'--B0\r\nContent-Disposition: form-data; name="password"\r\n\r\n'
        f"{_SECRET} <script>alert(1)</script>\r\n--B0--\r\n"
    ).encode()
    request = SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": "multipart/form-data; boundary=B0",
            "content-length": str(len(body)),
        },
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert "Suspicious pattern in password" in lines[0]
    assert _SECRET not in caplog.text
