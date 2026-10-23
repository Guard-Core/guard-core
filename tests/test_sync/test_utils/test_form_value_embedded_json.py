import json
import logging
from collections.abc import Callable
from urllib.parse import urlencode

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_CONFIG = SyncSecurityConfig()
_XSS = "<script>alert(1)</script>"
_MULTIPART_BOUNDARY = "B0"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _nested_array_nosql_payload() -> str:
    return json.dumps({"a": {"b": {"c": [{"$gt": 100}]}}})


def _json_body_request(payload: str) -> SyncMockGuardRequest:
    body = payload.encode()
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={"content-type": "application/json", "content-length": str(len(body))},
    )


def _header_request(payload: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(headers={"x-note": payload})


def _form_body_request(payload: str) -> SyncMockGuardRequest:
    body = urlencode({"note": payload}).encode()
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": str(len(body)),
        },
    )


def _multipart_body_request(payload: str) -> SyncMockGuardRequest:
    body = (
        f"--{_MULTIPART_BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="note"\r\n\r\n'
        f"{payload}\r\n--{_MULTIPART_BOUNDARY}--\r\n"
    ).encode()
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": f"multipart/form-data; boundary={_MULTIPART_BOUNDARY}",
            "content-length": str(len(body)),
        },
    )


_SURFACE_BUILDERS: dict[str, Callable[[str], SyncMockGuardRequest]] = {
    "json_body": _json_body_request,
    "header": _header_request,
    "form_field": _form_body_request,
    "multipart_field": _multipart_body_request,
}


@pytest.mark.parametrize("surface", list(_SURFACE_BUILDERS))
def test_nested_array_nosql_operator_detected_on_every_surface(
    surface: str,
) -> None:
    request = _SURFACE_BUILDERS[surface](_nested_array_nosql_payload())
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["nosql"]


@pytest.mark.parametrize("surface", ["form_field", "multipart_field"])
def test_form_value_json_password_redacted_in_detection_log(
    surface: str, caplog: pytest.LogCaptureFixture
) -> None:
    secret = f"SIBLING-SECRET-{surface}"
    payload = json.dumps({"note": _XSS, "password": secret})
    request = _SURFACE_BUILDERS[surface](payload)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, _CONFIG)

    assert result.is_threat is True
    lines = [
        line for line in caplog.text.splitlines() if "Potential attack detected" in line
    ]
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _XSS in lines[0]
    assert secret not in caplog.text
