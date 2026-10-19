import pytest

from guard_core import utils as utils_module
from guard_core.utils import redact_blob_for_display, redact_url_for_display

_SECRET = "PLANTED-SECRET-VALUE"


def test_public_redaction_helpers_are_exported() -> None:
    assert "redact_blob_for_display" in utils_module.__all__
    assert "redact_url_for_display" in utils_module.__all__


def test_pair_secret_in_reason_text_is_redacted_with_defaults() -> None:
    redacted = redact_blob_for_display(f"blocked: token={_SECRET} at login", None, None)

    assert _SECRET not in redacted
    assert redacted == "blocked: token=[REDACTED]"


def test_json_context_secret_is_redacted_with_defaults() -> None:
    context = f'{{"password": "{_SECRET}", "user": "alice"}}'

    redacted = redact_blob_for_display(context, None, None)

    assert _SECRET not in redacted
    assert "alice" in redacted


def test_extra_header_name_extends_default_set() -> None:
    text = f"x-internal-ref={_SECRET}"

    assert _SECRET in redact_blob_for_display(text, None, None)
    assert _SECRET not in redact_blob_for_display(
        text, None, None, frozenset({"x-internal-ref"})
    )


def test_user_agent_without_secret_is_unchanged() -> None:
    user_agent = "Mozilla/5.0 (X11; Linux x86_64) Chrome/128.0"

    assert redact_blob_for_display(user_agent, None, None) == user_agent


def test_endpoint_query_secret_is_redacted_with_defaults() -> None:
    redacted = redact_url_for_display(f"/login?access_token={_SECRET}&next=/home", None)

    assert _SECRET not in redacted
    assert "next=/home" in redacted


def test_endpoint_userinfo_password_is_redacted() -> None:
    redacted = redact_url_for_display(f"https://svc:{_SECRET}@api.internal/v1", None)

    assert _SECRET not in redacted
    assert "svc:[REDACTED]@api.internal/v1" in redacted


def test_endpoint_without_secret_is_unchanged() -> None:
    assert redact_url_for_display("/health", None) == "/health"


_ANGLE_BRACKET_VALUE_CASES = (
    (f"token=<{_SECRET}>", "token=[REDACTED]"),
    (f"token=<{_SECRET}", "token=[REDACTED]"),
    ("token=<>", "token=[REDACTED]"),
    ("token=<abc<def>ghi>", "token=[REDACTED]"),
    ("token=<a b>", "token=[REDACTED]"),
    ('token=<a"b>', "token=[REDACTED]"),
    ("token=<sk_live_51ABC xyz>&user=bob", "token=[REDACTED]&user=bob"),
    ("password=<my secret value>&next=step", "password=[REDACTED]&next=step"),
    (
        "token=<oops&item_id=abc123>&next=ok",
        "token=[REDACTED]&item_id=abc123>&next=ok",
    ),
    ("token=<x/next=ok", "token=[REDACTED]/next=ok"),
    ("token=<x)password=y", "token=[REDACTED])password=[REDACTED]"),
    ("token=<b>bold</b>", "token=[REDACTED]/b>"),
    ("token=<x>\nnext=ok", "token=[REDACTED]\nnext=ok"),
    ("token=<abc> user=bob", "token=[REDACTED] user=bob"),
    ("user=<b>x</b>", "user=<b>x</b>"),
)


@pytest.mark.parametrize(("text", "expected"), _ANGLE_BRACKET_VALUE_CASES)
def test_angle_bracket_value_follows_the_unquoted_value_rules(
    text: str, expected: str
) -> None:
    assert redact_blob_for_display(text, None, None) == expected


def test_angle_bracket_value_mirrors_the_unbracketed_value_extent() -> None:
    bare = redact_blob_for_display("token=abc user=bob", None, None)
    bracketed = redact_blob_for_display("token=<abc> user=bob", None, None)

    assert bare == "token=[REDACTED] user=bob"
    assert bracketed == bare
