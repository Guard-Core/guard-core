import json
import logging
from urllib.parse import urlencode

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.body_content_scan import _redact_sensitive_json
from guard_core.sync._utils.detection_scan import _json_depth_cap_value
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import (
    _DEFAULT_SENSITIVE_LOG_FIELDS,
    _resolve_sensitive_log_body_fields,
    _resolve_sensitive_log_params,
    detect_penetration_attempt,
)
from tests.test_sync.conftest import SyncMockGuardRequest

_CONTENT_TYPE_MULTIPART = "multipart/form-data; boundary=B0"
_SQLI_PAYLOAD = "' OR 1=1--"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _detection_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        line for line in caplog.text.splitlines() if "Potential attack detected" in line
    ]


def _json_request(body: bytes) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )


def _form_request(body: bytes) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": str(len(body)),
        },
    )


def _multipart_request(body: bytes) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": _CONTENT_TYPE_MULTIPART,
            "content-length": str(len(body)),
        },
    )


def _text_field_body(name: str, value: str) -> bytes:
    return (
        f'--B0\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
        f"{value}\r\n--B0--\r\n"
    ).encode()


def _nested_json_body(depth: int, key: str, leaf: str) -> bytes:
    leaf_json = json.dumps(leaf)
    prefix = f'{{"{key}":' * depth
    suffix = "}" * depth
    return (prefix + leaf_json + suffix).encode()


def _nested_wrapper_body(depth: int, wrapper_key: str, leaf: dict) -> bytes:
    leaf_json = json.dumps(leaf)
    prefix = f'{{"{wrapper_key}":' * depth
    suffix = "}" * depth
    return (prefix + leaf_json + suffix).encode()


def test_default_sensitive_query_param_value_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    request = SyncMockGuardRequest(
        query_params={"token": "SECRET-Q <script>alert(1)</script>"},
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert "query param 'token'" in lines[0]
    assert "SECRET-Q" not in caplog.text


def test_custom_sensitive_query_param_value_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_sensitive_params={"sig"})
    request = SyncMockGuardRequest(
        query_params={"sig": "SECRET-SIG <script>alert(1)</script>"},
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert "query param 'sig'" in lines[0]
    assert "SECRET-SIG" not in caplog.text


def test_non_sensitive_query_param_value_still_logged_verbatim(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_sensitive_params={"sig"})
    request = SyncMockGuardRequest(query_params={"q": "<script>alert(1)</script>"})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    assert "<script>alert(1)</script>" in caplog.text


def test_query_param_name_scan_unaffected_by_sensitive_params(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_sensitive_params={"token"})
    request = SyncMockGuardRequest(
        query_params={"<script>alert(1)</script>": "benign"},
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    assert "<script>alert(1)</script>" in caplog.text


def test_sensitive_query_param_with_log_suspicious_level_none_emits_no_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(
        log_sensitive_params={"token"}, log_suspicious_level=None
    )
    request = SyncMockGuardRequest(
        query_params={"token": "SECRET-Q3 <script>alert(1)</script>"},
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    assert "Potential attack detected" not in caplog.text
    assert "SECRET-Q3" not in caplog.text


def test_config_none_uses_default_sensitive_query_param_set(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = SyncMockGuardRequest(
        query_params={"token": "SECRET-Q4 <script>alert(1)</script>"},
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, None)

    assert result.is_threat is True
    assert "[REDACTED]" in caplog.text
    assert "query param 'token'" in caplog.text
    assert "SECRET-Q4" not in caplog.text


def test_non_sensitive_query_param_embedded_json_sensitive_field_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = json.dumps({"password": _SQLI_PAYLOAD, "note": "benign"})
    request = SyncMockGuardRequest(query_params={"data": body})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _SQLI_PAYLOAD not in caplog.text


def test_non_sensitive_query_param_embedded_json_sibling_secret_stays_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    secret = "PASSWORD-SIBLING-SECRET-Q"
    body = json.dumps({"password": secret, "note": _SQLI_PAYLOAD})
    request = SyncMockGuardRequest(query_params={"data": body})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _SQLI_PAYLOAD in lines[0]
    assert secret not in caplog.text


def test_non_sensitive_query_param_embedded_json_custom_sensitive_field_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_sensitive_body_fields={"custom_secret"})
    body = json.dumps({"custom_secret": _SQLI_PAYLOAD, "note": "benign"})
    request = SyncMockGuardRequest(query_params={"data": body})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _SQLI_PAYLOAD not in caplog.text


def test_json_top_level_key_password_value_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = json.dumps({"password": "SECRET-JSON <script>alert(1)</script>"}).encode()

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert "Suspicious pattern in password" in lines[0]
    assert "SECRET-JSON" not in caplog.text


def test_json_nested_key_at_depth_two_value_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = json.dumps(
        {"user": {"password": "SECRET-NESTED <script>alert(1)</script>"}}
    ).encode()

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert "Suspicious pattern in password" in lines[0]
    assert "SECRET-NESTED" not in caplog.text


def test_json_sensitive_key_wraps_object_nested_nonsensitive_leaf_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = json.dumps(
        {"password": {"inner": "SECRET-BODY-OBJVAL <script>alert(1)</script>"}}
    ).encode()

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert "Suspicious pattern in inner" in lines[0]
    assert "SECRET-BODY-OBJVAL" not in caplog.text


def test_json_sensitive_key_wraps_array_of_objects_nested_leaf_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = json.dumps(
        {"password": [{"inner": "SECRET-BODY-ARRVAL <script>alert(1)</script>"}]}
    ).encode()

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert "SECRET-BODY-ARRVAL" not in caplog.text


def test_capped_json_subtree_label_redacted_when_sensitive(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_sensitive_body_fields={"a"})
    body = _nested_json_body(40, "a", _SQLI_PAYLOAD)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _SQLI_PAYLOAD not in caplog.text


@pytest.mark.parametrize("depth_offset", [-1, 0, 1])
def test_capped_json_subtree_password_leaf_under_nonsensitive_wrapper_redacted(
    caplog: pytest.LogCaptureFixture, depth_offset: int
) -> None:
    config = SyncSecurityConfig()
    depth = _json_depth_cap_value() + depth_offset
    body = _nested_wrapper_body(depth, "wrapper", {"password": _SQLI_PAYLOAD})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _SQLI_PAYLOAD not in caplog.text


def test_capped_json_subtree_without_sensitive_key_logs_raw_serialization(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    depth = _json_depth_cap_value()
    body = _nested_wrapper_body(depth, "wrapper", {"comment": _SQLI_PAYLOAD})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" not in lines[0]
    assert _SQLI_PAYLOAD in lines[0]


def test_capped_json_subtree_sensitive_key_inside_list_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    depth = _json_depth_cap_value()
    body = _nested_wrapper_body(
        depth, "wrapper", {"items": [{"password": _SQLI_PAYLOAD}]}
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _SQLI_PAYLOAD not in caplog.text


def test_capped_json_subtree_custom_sensitive_field_name_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_sensitive_body_fields={"ssn"})
    depth = _json_depth_cap_value()
    body = _nested_wrapper_body(depth, "wrapper", {"ssn": _SQLI_PAYLOAD})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _SQLI_PAYLOAD not in caplog.text


def test_capped_json_subtree_trigger_info_unchanged_by_redaction(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    depth = _json_depth_cap_value()
    body = _nested_wrapper_body(depth, "wrapper", {"password": _SQLI_PAYLOAD})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    assert result.trigger_info.startswith("Request body field 'wrapper': ")
    assert "[REDACTED]" not in result.trigger_info
    assert _SQLI_PAYLOAD not in result.trigger_info


def test_form_field_password_value_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = urlencode({"password": "SECRET-FORM <script>alert(1)</script>"}).encode()

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_form_request(body), config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert "Suspicious pattern in password" in lines[0]
    assert "SECRET-FORM" not in caplog.text


def test_multipart_text_part_secret_value_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = _text_field_body("secret", "SECRET-MP <script>alert(1)</script>")

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_multipart_request(body), config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert "Suspicious pattern in secret" in lines[0]
    assert "SECRET-MP" not in caplog.text


def test_non_sensitive_body_field_still_logged_verbatim(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    body = json.dumps({"comment": "<script>alert(1)</script>"}).encode()

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    assert "<script>alert(1)</script>" in caplog.text


def test_blob_body_value_unaffected_by_sensitive_body_fields(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_sensitive_body_fields={"password"})
    body = b"<script>alert(1)</script>"
    request = SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": "text/plain",
            "content-length": str(len(body)),
        },
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    assert "<script>alert(1)</script>" in caplog.text


def test_sensitive_body_field_with_log_suspicious_level_none_emits_no_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(log_suspicious_level=None)
    body = json.dumps({"password": "SECRET-NONE <script>alert(1)</script>"}).encode()

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    assert "Potential attack detected" not in caplog.text
    assert "SECRET-NONE" not in caplog.text


def test_config_none_uses_default_sensitive_body_field_set(
    caplog: pytest.LogCaptureFixture,
) -> None:
    body = json.dumps({"password": "SECRET-DEFAULT <script>alert(1)</script>"}).encode()

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), None)

    assert result.is_threat is True
    assert "[REDACTED]" in caplog.text
    assert "Suspicious pattern in password" in caplog.text
    assert "SECRET-DEFAULT" not in caplog.text


def test_resolve_sensitive_log_params_config_none_returns_default() -> None:
    assert _resolve_sensitive_log_params(None) == _DEFAULT_SENSITIVE_LOG_FIELDS


def test_resolve_sensitive_log_params_with_config_extras() -> None:
    config = SyncSecurityConfig(log_sensitive_params={"sig"})
    result = _resolve_sensitive_log_params(config)
    assert result == _DEFAULT_SENSITIVE_LOG_FIELDS | {"sig"}


def test_resolve_sensitive_log_body_fields_config_none_returns_default() -> None:
    assert _resolve_sensitive_log_body_fields(None) == _DEFAULT_SENSITIVE_LOG_FIELDS


def test_resolve_sensitive_log_body_fields_with_config_extras() -> None:
    config = SyncSecurityConfig(log_sensitive_body_fields={"ssn"})
    result = _resolve_sensitive_log_body_fields(config)
    assert result == _DEFAULT_SENSITIVE_LOG_FIELDS | {"ssn"}


def test_redact_sensitive_json_int_key_kept_and_string_key_redacted() -> None:
    result = _redact_sensitive_json(
        {1: "keep-me", "password": _SQLI_PAYLOAD},
        frozenset(),
        frozenset({"password"}),
        _json_depth_cap_value(),
    )
    assert result == {1: "keep-me", "password": "[REDACTED]"}
