import pytest

from guard_core._security_headers_override import (
    has_control_character,
    is_clean_cors_value,
)


@pytest.mark.parametrize("value", ["a\x00b", "a\nb", "a\rb", "a\x1fb", "a\x7fb"])
def test_a_value_with_a_control_character_is_flagged_and_not_clean(
    value: str,
) -> None:
    assert has_control_character(value) is True
    assert is_clean_cors_value(value) is False


@pytest.mark.parametrize("value", ["", "https://a.example", "GET, POST", "é"])
def test_a_value_without_a_control_character_is_clean(value: str) -> None:
    assert has_control_character(value) is False
    assert is_clean_cors_value(value) is True
