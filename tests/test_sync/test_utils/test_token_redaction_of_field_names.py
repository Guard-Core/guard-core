import logging
from typing import Any
from urllib.parse import quote

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync._utils.request_logging import (
    redact_blob_for_display,
    redact_url_for_display,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

SENSITIVE_NAMES = [
    "new_password",
    "id_token",
    "sessionid",
    "passwd",
    "otp",
    "sid",
    "access-token",
    "user.secret",
    "idToken",
    "accessToken",
    "X-Auth-Header",
    "api_key",
    "monkey_key",
]
ORDINARY_NAMES = ["keywords", "author", "monkey", "email", "note", "query", "authors"]


@pytest.mark.parametrize("name", SENSITIVE_NAMES)
def test_a_name_with_a_credential_token_is_redacted_in_a_url(name: str) -> None:
    redacted = redact_url_for_display(f"/s?{name}=VALUE-123&q=ok", None, None, None)

    assert "VALUE-123" not in redacted
    assert "q=ok" in redacted


@pytest.mark.parametrize("name", ORDINARY_NAMES)
def test_an_ordinary_name_stays_visible_in_a_url(name: str) -> None:
    redacted = redact_url_for_display(f"/s?{name}=VALUE-123&q=ok", None, None, None)

    assert f"{name}=VALUE-123" in redacted


@pytest.mark.parametrize("name", SENSITIVE_NAMES)
def test_a_name_with_a_credential_token_is_redacted_in_a_text_blob(name: str) -> None:
    assert "VALUE-123" not in redact_blob_for_display(
        f"{name}=VALUE-123&q=ok", None, None
    )


@pytest.mark.parametrize("name", ORDINARY_NAMES)
def test_an_ordinary_name_stays_visible_in_a_text_blob(name: str) -> None:
    assert f"{name}=VALUE-123" in redact_blob_for_display(
        f"{name}=VALUE-123&q=ok", None, None
    )


@pytest.mark.parametrize("name", SENSITIVE_NAMES)
def test_a_name_with_a_credential_token_is_redacted_in_json(name: str) -> None:
    redacted = redact_blob_for_display(
        f'{{"{name}": "VALUE-123", "q": "ok"}}', None, None
    )

    assert "VALUE-123" not in redacted
    assert '"q":"ok"' in redacted


@pytest.mark.parametrize("name", ORDINARY_NAMES)
def test_an_ordinary_name_stays_visible_in_json(name: str) -> None:
    assert "VALUE-123" in redact_blob_for_display(
        f'{{"{name}": "VALUE-123"}}', None, None
    )


@pytest.mark.parametrize("name", ["id_token", "idToken", "new_password"])
def test_a_name_with_a_credential_token_is_redacted_in_xml(name: str) -> None:
    redacted = redact_blob_for_display(f"<{name}>VALUE-123</{name}>", None, None)

    assert "VALUE-123" not in redacted


def _captured_log_text(caplog: pytest.LogCaptureFixture) -> str:
    return "\n".join(record.getMessage() for record in caplog.records)


def _post(content_type: str, body: str) -> SyncMockGuardRequest:
    raw = body.encode()
    return SyncMockGuardRequest(
        method="POST",
        path="/s",
        headers={"content-type": content_type, "content-length": str(len(raw))},
        body_content=raw,
    )


@pytest.mark.parametrize(
    "request_factory",
    [
        lambda name, value: SyncMockGuardRequest(path="/s", query_params={name: value}),
        lambda name, value: _post("application/json", f'{{"{name}": "{value}"}}'),
        lambda name, value: _post(
            "application/x-www-form-urlencoded", f"{name}={quote(value)}"
        ),
    ],
    ids=["query", "json", "form"],
)
def test_the_hit_log_hides_the_value_of_a_credential_named_field(
    caplog: pytest.LogCaptureFixture, request_factory: Any
) -> None:
    value = "<script>alert('SECRETVALUE')</script>"
    config = SecurityConfig(enable_penetration_detection=True)

    with caplog.at_level(logging.INFO, logger="guard_core"):
        sensitive = detect_penetration_attempt(
            request_factory("id_token", value), config
        )
        sensitive_log = _captured_log_text(caplog)
        caplog.clear()
        ordinary = detect_penetration_attempt(request_factory("note", value), config)
        ordinary_log = _captured_log_text(caplog)

    assert sensitive.is_threat is True
    assert ordinary.is_threat is True
    assert "SECRETVALUE" not in sensitive_log
    assert "SECRETVALUE" in ordinary_log
