import pytest

from guard_core.sync._utils.body_reader import (
    _parse_content_length,
    parse_declared_length,
    request_declares_body,
)


@pytest.mark.parametrize("digits", [4301, 5000, 100_000])
def test_a_content_length_past_the_integer_digit_limit_is_not_a_length(
    digits: int,
) -> None:
    assert parse_declared_length("1" * digits) is None
    assert _parse_content_length("1" * digits) is None
    assert request_declares_body({"content-length": "1" * digits}) is True


def test_a_content_length_inside_the_digit_limit_is_parsed() -> None:
    assert parse_declared_length("1" * 4300) == int("1" * 4300)
    assert parse_declared_length(" 42 ") == 42
    assert parse_declared_length("4x2") is None
