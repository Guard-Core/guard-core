import pytest
from pydantic import ValidationError

from guard_core._security_headers_defaults import default_security_headers_config
from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager

BAD_VALUES = ["a\r\nb", "a\nb", "a\rb", "a b", "a b", "a€b", "a\x7fb"]
BAD_NAMES = ["X A", "X:A", "", "X A", "X\nA", "X,A", "X\u0085A"]
GOOD_VALUES = [
    "SAMEORIGIN",
    "nosniff",
    "0",
    "strict-origin-when-cross-origin",
    "geolocation=(), microphone=(), camera=()",
    "café",
    "tab\tseparated",
    "x" * 8192,
]
VALUE_KEYS = ["frame_options", "referrer_policy", "permissions_policy"]


def _custom(name: str, value: str) -> dict[str, object]:
    return {"enabled": True, "custom": {name: value}}


@pytest.mark.parametrize("bad", BAD_VALUES)
@pytest.mark.parametrize("key", VALUE_KEYS)
def test_construction_refuses_a_value_the_response_cannot_carry(
    key: str, bad: str
) -> None:
    with pytest.raises(ValidationError):
        SyncSecurityConfig(security_headers={"enabled": True, key: bad})


@pytest.mark.parametrize("bad", BAD_VALUES)
def test_construction_refuses_a_custom_value_the_response_cannot_carry(
    bad: str,
) -> None:
    with pytest.raises(ValidationError):
        SyncSecurityConfig(security_headers=_custom("X-A", bad))


@pytest.mark.parametrize("bad", BAD_NAMES)
def test_construction_refuses_a_custom_header_name_that_is_not_a_token(
    bad: str,
) -> None:
    with pytest.raises(ValidationError):
        SyncSecurityConfig(security_headers=_custom(bad, "v"))


@pytest.mark.parametrize("bad", BAD_VALUES)
def test_assignment_refuses_a_value_the_response_cannot_carry(bad: str) -> None:
    config = SyncSecurityConfig()
    with pytest.raises(ValueError):
        config.security_headers = _custom("X-A", bad)
    with pytest.raises(ValueError):
        config.security_headers = {"enabled": True, "frame_options": bad}


@pytest.mark.parametrize("bad", BAD_NAMES)
def test_assignment_refuses_a_custom_header_name_that_is_not_a_token(
    bad: str,
) -> None:
    config = SyncSecurityConfig()
    with pytest.raises(ValueError):
        config.security_headers = _custom(bad, "v")


@pytest.mark.parametrize("good", GOOD_VALUES)
def test_construction_and_assignment_accept_what_the_response_accepts(
    good: str,
) -> None:
    headers = {"enabled": True, "frame_options": good, "custom": {"X-A": good}}
    config = SyncSecurityConfig(security_headers=headers)
    assert config.security_headers == headers
    config.security_headers = headers
    assert config.security_headers == headers


def test_a_disabled_block_is_not_checked_because_the_response_never_reads_it() -> None:
    config = SyncSecurityConfig(
        security_headers={"enabled": False, "frame_options": "a b"}
    )
    assert config.security_headers == {"enabled": False, "frame_options": "a b"}


def test_the_defaults_and_none_are_accepted() -> None:
    assert SyncSecurityConfig().security_headers == default_security_headers_config()
    assert SyncSecurityConfig(security_headers=None).security_headers is None


def test_the_response_path_keeps_both_messages() -> None:
    manager = SecurityHeadersManager()
    with pytest.raises(ValueError, match="Invalid header value contains newline"):
        manager._validate_header_value("a\nb")
    with pytest.raises(ValueError, match="a character a response cannot carry"):
        manager._validate_header_value("a b")
    with pytest.raises(ValueError, match="Invalid header name: X A"):
        manager._validate_header_name("X A")
    assert manager._validate_header_value("a\x00\x01\tb") == "a\tb"


@pytest.mark.parametrize(
    "custom", [{1: "x"}, {"X-A": 5}, {"X-A": None}, "X-A: 1", ["X-A"]]
)
def test_construction_refuses_a_custom_block_the_response_cannot_read(
    custom: object,
) -> None:
    with pytest.raises(ValidationError):
        SyncSecurityConfig(security_headers={"enabled": True, "custom": custom})


def test_an_empty_custom_block_is_accepted() -> None:
    headers = {"enabled": True, "custom": {}}
    assert SyncSecurityConfig(security_headers=headers).security_headers == headers
