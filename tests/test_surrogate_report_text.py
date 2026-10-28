import logging

import pytest

from guard_core._utils.logging_utils import _log_at_level, _sanitize_for_reporting
from guard_core.handlers import _suspatterns_regex
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("plain", "plain"),
        ("caf\u00e9", "caf\u00e9"),
        ("a\udce9b", "a\\xe9b"),
        ("a\ud800b", "a\\ud800b"),
        ("a\udc7fb", "a\\udc7fb"),
        ("a\udd00b", "a\\udd00b"),
        ("\udfffx\ud800\udce9", "\\udfffx\\ud800\\xe9"),
    ],
)
def test_report_text_renders_any_string(text: str, shown: str) -> None:
    assert _sanitize_for_reporting(text) == shown


def test_the_row_scan_and_the_log_line_share_one_sanitizer() -> None:
    assert _suspatterns_regex._sanitize_for_reporting is _sanitize_for_reporting


def test_a_log_line_with_a_lone_surrogate_is_emitted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("guard_core.test_surrogate")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        _log_at_level(logger, "WARNING", "found \ud800 in a value")
    assert "found \\ud800 in a value" in caplog.text


async def test_a_json_value_with_a_lone_surrogate_and_an_attack_is_flagged() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    body = b'{"a":"\\ud800<script>alert(1)</script>"}'
    request = MockGuardRequest(
        method="POST",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )

    result = await detect_penetration_attempt(request, config)

    assert result.is_threat is True
    assert "xss" in result.threat_categories
