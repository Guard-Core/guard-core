import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
    DETECTION_RAW_VIEW_PATTERN_SOURCES,
    DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES,
    sus_patterns_handler,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_CONFIG = SyncSecurityConfig()


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _text_body_request(body: str) -> SyncMockGuardRequest:
    encoded = body.encode()
    headers = {
        "content-length": str(len(encoded)),
        "content-type": "text/plain",
    }
    return SyncMockGuardRequest(body_content=encoded, headers=headers)


def _query_param_request(value: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(query_params={"q": value})


def _assert_body_fires_cmd_injection(body: str) -> None:
    request = _text_body_request(body)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert "cmd_injection" in result.threat_categories


def _assert_query_param_fires_cmd_injection(value: str) -> None:
    request = _query_param_request(value)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert "cmd_injection" in result.threat_categories


def test_pattern_is_url_decoded_view_only_not_raw_view() -> None:
    assert (
        _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE not in DETECTION_RAW_VIEW_PATTERN_SOURCES
    )
    assert (
        _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE
        in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    )


URL_ENCODED_NEWLINE_SHELL_DASH_C_GAP_BODIES = [
    pytest.param("x%0A/bin/sh%20-c%20id", id="urlencoded_newline_bin_sh"),
    pytest.param("x%0Aenv%20bash%20-c%20id", id="urlencoded_newline_env_bash"),
]


@pytest.mark.parametrize("body", URL_ENCODED_NEWLINE_SHELL_DASH_C_GAP_BODIES)
def test_url_encoded_newline_shell_dash_c_fires_in_request_body(
    body: str,
) -> None:
    _assert_body_fires_cmd_injection(body)


@pytest.mark.parametrize("value", URL_ENCODED_NEWLINE_SHELL_DASH_C_GAP_BODIES)
def test_url_encoded_newline_shell_dash_c_fires_in_query_param(
    value: str,
) -> None:
    _assert_query_param_fires_cmd_injection(value)


LITERAL_NEWLINE_SHELL_DASH_C_STILL_FIRES_BODIES = [
    pytest.param("x" + chr(10) + "/bin/sh -c id", id="literal_newline_bin_sh"),
    pytest.param("x" + chr(10) + "env bash -c id", id="literal_newline_env_bash"),
]


@pytest.mark.parametrize("body", LITERAL_NEWLINE_SHELL_DASH_C_STILL_FIRES_BODIES)
def test_literal_newline_shell_dash_c_still_fires_in_request_body(
    body: str,
) -> None:
    _assert_body_fires_cmd_injection(body)


BARE_URL_ENCODED_SHELL_DASH_C_ALREADY_DETECTED_VIA_OTHER_PATTERNS = [
    pytest.param("%0A/bin/sh%20-c%20id", id="bare_urlencoded_newline_bin_sh"),
    pytest.param(
        "%0AFOO=bar%20/bin/sh%20-c%20id", id="bare_urlencoded_newline_var_assign"
    ),
]


@pytest.mark.parametrize(
    "body", BARE_URL_ENCODED_SHELL_DASH_C_ALREADY_DETECTED_VIA_OTHER_PATTERNS
)
def test_bare_url_encoded_shell_dash_c_already_fires_via_other_patterns(
    body: str,
) -> None:
    _assert_body_fires_cmd_injection(body)


URL_ENCODED_BACKTICK_AND_DOLLAR_PAREN_CORPUS_PIN = [
    pytest.param("%60id%60", id="urlencoded_backtick_id"),
    pytest.param("%24%28id%29", id="urlencoded_dollar_paren_id"),
]


@pytest.mark.parametrize("value", URL_ENCODED_BACKTICK_AND_DOLLAR_PAREN_CORPUS_PIN)
def test_url_encoded_backtick_and_dollar_paren_detected_in_query_param(
    value: str,
) -> None:
    _assert_query_param_fires_cmd_injection(value)
