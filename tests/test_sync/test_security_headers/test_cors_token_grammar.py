import re

import pytest

from guard_core._security_headers_override import (
    CorsParams,
    OverrideRecord,
    merge_cors,
)
from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager

BASE = CorsParams(
    True, ("https://a.example",), False, ("GET",), ("X-A",), 600, ("X-B",)
)
ORIGIN = "https://a.example"
CARRIABLE = re.compile(r"[\t\x20-\x7e\x80-\xff]*")
TOKEN_FIELDS = ["cors_allow_methods", "cors_allow_headers", "cors_expose_headers"]
NOT_TOKENS = ["GET ", "X\u0085A", "GET X", "X-A:", "GET,POST", "A B", ""]
LEGITIMATE = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
    "HEAD",
    "*",
    "Content-Type",
    "X-Custom-Header",
    "x-total-count",
    "X_A.b~c!d#e$f%g&h'i*j+k^l`m|n",
]


@pytest.mark.parametrize("key", TOKEN_FIELDS)
@pytest.mark.parametrize("bad", NOT_TOKENS)
def test_an_override_value_that_is_not_a_token_keeps_the_apps_own_value(
    key: str, bad: str
) -> None:
    merged, reason = merge_cors(BASE, {key: ["GET", bad]})

    assert reason is not None
    assert merged == BASE


@pytest.mark.parametrize("key", TOKEN_FIELDS)
@pytest.mark.parametrize("bad", NOT_TOKENS)
def test_a_config_value_that_is_not_a_token_is_refused(key: str, bad: str) -> None:
    with pytest.raises(ValueError, match="invalid origin"):
        SyncSecurityConfig(enable_redis=False, **{key: ["GET", bad]})


@pytest.mark.parametrize("key", TOKEN_FIELDS)
def test_every_legitimate_token_is_accepted(key: str) -> None:
    merged, reason = merge_cors(BASE, {key: LEGITIMATE})

    assert reason is None
    assert SyncSecurityConfig(enable_redis=False, **{key: LEGITIMATE})


def test_a_custom_security_header_with_a_line_separator_is_refused_at_config_time() -> (
    None
):
    manager = SecurityHeadersManager.isolated()

    with pytest.raises(ValueError, match="a character a response cannot carry"):
        manager.configure(custom_headers={"X-A": "a b"})


@pytest.mark.parametrize("bad", [" ", " ", "Ā", "€", "\x7f"])
def test_a_header_value_outside_the_carriable_set_is_refused(bad: str) -> None:
    manager = SecurityHeadersManager.isolated()

    with pytest.raises(ValueError):
        manager._validate_header_value(f"a{bad}b")


def test_every_character_a_value_check_lets_through_is_carriable() -> None:
    manager = SecurityHeadersManager.isolated()
    accepted = []
    for code in range(0x3000):
        try:
            accepted.append(manager._validate_header_value(f"a{chr(code)}b"))
        except ValueError:
            continue

    assert accepted
    assert all(CARRIABLE.fullmatch(value) for value in accepted)


def test_an_override_with_a_line_separator_keeps_the_apps_own_cors() -> None:
    manager = SecurityHeadersManager.isolated()
    config = SyncSecurityConfig(
        enable_redis=False, enable_cors=True, cors_allow_origins=[ORIGIN]
    )
    record = OverrideRecord(
        1.0, {"cors_allow_methods": ["GET "], "cors_allow_headers": ["X-A B"]}
    )

    headers = manager.get_cors_headers(ORIGIN, config, record)

    assert headers["Access-Control-Allow-Methods"] == ", ".join(
        config.cors_allow_methods
    )
    assert all(CARRIABLE.fullmatch(value) for value in headers.values())


@pytest.mark.parametrize("bad", ["GET ", "GET X-Evil: 1", "GET\u0085"])
def test_no_built_cors_header_holds_a_character_a_response_cannot_carry(
    bad: str,
) -> None:
    manager = SecurityHeadersManager.isolated()
    manager.configure(cors_origins=[ORIGIN], cors_allow_methods=[bad])

    headers = manager.get_cors_headers(ORIGIN)

    assert all(CARRIABLE.fullmatch(value) for value in headers.values())
