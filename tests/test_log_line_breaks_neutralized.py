import logging

import pytest

from guard_core._utils.detection_scan import _log_detected_component
from guard_core._utils.logging_utils import _log_at_level

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
