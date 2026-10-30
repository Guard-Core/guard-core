import logging

import pytest

from guard_core.sync._utils.detection_scan import _log_detected_component
from guard_core.sync._utils.logging_utils import _log_at_level

FORGED = "<script>alert(1)</script>\n2026-10-30 12:00:00 CRITICAL forged admin login ok"


def test_a_line_break_in_a_flagged_value_does_not_forge_a_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        _log_detected_component(FORGED, "query param 'q'", "1.2.3.4", "WARNING")

    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert "\n" not in message
    assert "\r" not in message
    assert "\\n2026-10-30 12:00:00 CRITICAL forged admin login ok" in message


def test_a_line_break_in_any_logged_reason_is_escaped(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="guard_core"):
        _log_at_level(logging.getLogger("guard_core"), "INFO", "a\r\nb")

    assert caplog.records[0].getMessage() == "a\\r\\nb"


def test_a_message_without_line_breaks_is_unchanged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="guard_core"):
        _log_at_level(logging.getLogger("guard_core"), "INFO", "plain message")

    assert caplog.records[0].getMessage() == "plain message"


def test_a_json_looking_value_that_is_not_json_is_left_as_it_is() -> None:
    from guard_core.sync._utils.request_logging import _json_redact_text

    assert _json_redact_text("{not json", frozenset(), frozenset(), 8) is None


def test_a_json_value_too_deep_to_parse_is_redacted_whole(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json

    from guard_core.sync._utils.request_logging import _json_redact_text

    def too_deep(_text: str) -> object:
        raise RecursionError

    monkeypatch.setattr(json, "loads", too_deep)

    assert _json_redact_text("[[[[", frozenset(), frozenset(), 8) == "[REDACTED]"
