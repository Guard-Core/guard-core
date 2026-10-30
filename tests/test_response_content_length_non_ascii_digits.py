import pytest

from guard_core.core.responses.modifier_view import (
    body_gate_refusal,
    declared_content_length,
)
from tests.conftest import MockGuardResponse


def _response(value: str) -> MockGuardResponse:
    return MockGuardResponse(
        "x", 200, {"content-length": value, "content-type": "application/json"}
    )


@pytest.mark.parametrize("value", ["²", "١٢", "1²"])
def test_a_non_ascii_digit_is_not_a_declared_length(value: str) -> None:
    assert declared_content_length(_response(value)) is None
    assert body_gate_refusal(_response(value), "GET", 1000) == (
        "the response declares no Content-Length"
    )


def test_an_ascii_length_is_read() -> None:
    assert declared_content_length(_response(" 12 ")) == 12
    assert body_gate_refusal(_response("12"), "GET", 1000) is None
