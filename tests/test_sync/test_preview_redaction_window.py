import json
import time

import pytest

from guard_core.sync._utils.body_content_scan import _lazy_display
from guard_core.sync._utils.request_logging import redact_blob_for_display

_WORDS = "quarterly onboarding metrics for the regional sales team include revenue "
_SHOWN = 100


def _padding(size: int) -> str:
    return (_WORDS * (size // len(_WORDS) + 1))[:size]


def _preview(value: str) -> str | None:
    return _lazy_display(value, frozenset(), frozenset()).resolve()


def test_preview_of_a_20_mb_body_costs_work_proportional_to_what_it_shows() -> None:
    value = json.dumps({"password": "hunter2", "k": _padding(20_000_000)})

    started = time.thread_time()
    preview = _preview(value)
    spent = time.thread_time() - started

    assert spent < 0.5
    assert preview is not None
    assert "hunter2" not in preview[:_SHOWN]
    assert "[REDACTED]" in preview[:_SHOWN]


def test_secret_running_past_the_preview_window_is_still_redacted() -> None:
    secret = "S3CR3T" * 20_000
    value = (
        '{"user":"bob","password":"' + secret + '","k":"' + _padding(1_000_000) + '"}'
    )

    preview = _preview(value)

    assert preview is not None
    assert "S3CR3T" not in preview
    assert "[REDACTED]" in preview


def test_xml_element_running_past_the_preview_window_is_still_redacted() -> None:
    value = (
        "<r><password>"
        + "S3CR3T" * 20_000
        + "</password><pad>"
        + _padding(1_000_000)
        + "</pad></r>"
    )

    preview = _preview(value)

    assert preview is not None
    assert "S3CR3T" not in preview
    assert "<password>[REDACTED]" in preview


def test_secret_straddling_the_shown_edge_is_still_redacted() -> None:
    value = (
        '{"user":"bob","password":"' + "x" * 200 + '","k":"' + _padding(500_000) + '"}'
    )

    preview = _preview(value)

    assert preview is not None
    assert "xxxxxxxxxx" not in preview[: _SHOWN + 50]
    assert "[REDACTED]" in preview[:_SHOWN]


def test_secret_in_the_query_style_head_of_a_large_value_is_redacted() -> None:
    value = "user=bob&token=abc123abc123&note=" + _padding(2_000_000)

    preview = _preview(value)

    assert preview is not None
    assert "abc123abc123" not in preview


@pytest.mark.parametrize(
    "value",
    [
        '{"password": "hunter2", "user": "bob"}',
        '{\n  "token": "abc",\n  "nested": {"api_key": "k"}\n}',
        "a=1&password=hunter2&b=2",
        "<root><password>hunter2</password></root>",
        "plain text without any secret",
        "",
        json.dumps({"password": "p", "k": _padding(4000)})[:4096],
    ],
)
def test_preview_below_the_window_is_what_the_full_redaction_gives(
    value: str,
) -> None:
    redacted = redact_blob_for_display(value, frozenset(), frozenset())

    assert _preview(value) == (None if redacted == value else redacted)
