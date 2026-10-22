import pytest

from guard_core.sync._utils.request_logging import redact_blob_for_display


@pytest.mark.parametrize(
    "text",
    [
        "password=hunter2",
        "token=abc&password=hunter2",
        "password=hunter2&page=2",
        'password="hunter2"',
        "password: hunter2",
        "a=1;password=hunter2;b=2",
        "q=1&token=abc&password=hunter2&page=2",
        '{"password": "hunter2"}',
        '{"user": "u", "password": "hunter2", "token": "abc"}',
        "<password>hunter2</password>",
        "password=%5BREDACTED%5D",
    ],
)
def test_a_second_pass_equals_the_first(text: str) -> None:
    first = redact_blob_for_display(text, None, None)
    assert redact_blob_for_display(first, None, None) == first


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("password=hunter2", "password=[REDACTED]"),
        ("token=abc&password=hunter2", "token=[REDACTED]&password=[REDACTED]"),
        ('{"password": "hunter2"}', '{"password":"[REDACTED]"}'),
    ],
)
def test_the_first_pass_is_unchanged(text: str, expected: str) -> None:
    assert redact_blob_for_display(text, None, None) == expected
