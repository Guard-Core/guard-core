import pytest

from guard_core._utils.request_logging import redact_blob_for_display


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("password=/hunter2", "password=[REDACTED]"),
        ("password=(hunter2)", "password=[REDACTED]"),
        ("password=[x]hunter2", "password=[REDACTED]"),
        ("api_key=,secret", "api_key=[REDACTED]"),
        ("token=abc&password=/hunter2", "token=[REDACTED]&password=[REDACTED]"),
        ("password=hunt/er2", "password=[REDACTED]"),
        ("api_key=AbC+dEf/GhI=", "api_key=[REDACTED]"),
        ("password=hunt(er)2", "password=[REDACTED]"),
        ("password=pa,ss", "password=[REDACTED]"),
        (
            "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_secret_access_key=[REDACTED]",
        ),
        ("password=[REDACTED]/x", "password=[REDACTED]"),
        ("password=/x&user=bob", "password=[REDACTED]&user=bob"),
        ("a=1,password=hunter2,b=2", "a=1,password=[REDACTED],b=2"),
        ("secret=Zm9v=YmFy", "secret=[REDACTED]"),
        ("password=ab=cd", "password=[REDACTED]"),
        ("token=a%2Fb%2Fc", "token=[REDACTED]"),
        ("password=hunter2&user=bob", "password=[REDACTED]&user=bob"),
        ('password="/hunter2"', 'password="[REDACTED]"'),
    ],
)
def test_no_part_of_a_secret_survives_its_value_extent(
    text: str, expected: str
) -> None:
    first = redact_blob_for_display(text, None, None)
    assert first == expected
    assert redact_blob_for_display(first, None, None) == first
