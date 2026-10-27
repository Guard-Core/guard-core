import re
from collections.abc import Generator
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.agent_protocol import JsonValue
from guard_core.sync.handlers.suspatterns_handler import (
    _LDAP_NULL_BYTE_ATTR_COMPILED_RE,
    _LDAP_NULL_BYTE_ATTR_LEAD_CHAR_RE,
    _LDAP_NULL_BYTE_ATTR_RE,
    _LDAP_NULL_BYTE_BARE_RE,
    _LDAP_NULL_BYTE_DECODED_ATTR_RE,
    _LDAP_NULL_BYTE_DECODED_BARE_RE,
    _LDAP_NULL_BYTE_TAIL_RE,
    DETECTION_RAW_VIEW_PATTERN_SOURCES,
    DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES,
    DetectionResult,
    SusPatternsManager,
    _ldap_null_byte_attr_finditer,
    _ldap_null_byte_attr_name_start,
    sus_patterns_handler,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_NUL_RAW = chr(0)
_NUL_UNICODE_TEXT = chr(92) + "u0000"
_NUL_HEX_TEXT = chr(92) + "x00"
_NUL_OCTAL_TEXT = chr(92) + "0"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


@pytest.fixture
def manager() -> Generator[SusPatternsManager, None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    new_instance = SusPatternsManager(SyncSecurityConfig())
    yield new_instance
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


def _body_request(body: str) -> SyncMockGuardRequest:
    encoded = body.encode()
    return SyncMockGuardRequest(
        path="/login",
        method="POST",
        headers={"content-length": str(len(encoded))},
        body_content=encoded,
    )


def _body_categories(body: str) -> list[str]:
    result = detect_penetration_attempt(_body_request(body), SyncSecurityConfig())
    return list(result.threat_categories)


def _body_is_threat(body: str) -> bool:
    result = detect_penetration_attempt(_body_request(body), SyncSecurityConfig())
    return bool(result.is_threat)


def _manager_detect(body: str, manager: SusPatternsManager) -> DetectionResult:
    return manager.detect(body, "203.0.113.9", context="request_body")


_LDAP_NULL_BYTE_PATTERNS = frozenset(
    {
        _LDAP_NULL_BYTE_ATTR_RE,
        _LDAP_NULL_BYTE_BARE_RE,
        _LDAP_NULL_BYTE_DECODED_ATTR_RE,
        _LDAP_NULL_BYTE_DECODED_BARE_RE,
    }
)


def _null_byte_threats(result: DetectionResult) -> list[dict[str, JsonValue]]:
    return [
        threat
        for threat in result["threats"]
        if threat.get("type") == "regex"
        and threat.get("pattern") in _LDAP_NULL_BYTE_PATTERNS
    ]


LDAP_NUL_FAMILY_BODIES = [
    pytest.param("uid=alice*)" + _NUL_RAW, id="attr_raw_nul_byte"),
    pytest.param("*)" + ")" + _NUL_RAW, id="bare_raw_nul_byte"),
    pytest.param("uid=alice*)" + _NUL_UNICODE_TEXT, id="attr_literal_unicode_nul_text"),
    pytest.param("*)" + ")" + _NUL_UNICODE_TEXT, id="bare_literal_unicode_nul_text"),
    pytest.param("uid=alice*)" + _NUL_HEX_TEXT, id="attr_literal_hex_nul_text"),
    pytest.param("*)" + ")" + _NUL_HEX_TEXT, id="bare_literal_hex_nul_text"),
    pytest.param("uid=alice*)" + _NUL_OCTAL_TEXT, id="attr_literal_octal_nul_text"),
    pytest.param("*)" + ")" + _NUL_OCTAL_TEXT, id="bare_literal_octal_nul_text"),
    pytest.param("uid=alice*)%2500", id="attr_double_encoded_nul"),
    pytest.param("*)" + ")%2500", id="bare_double_encoded_nul"),
    pytest.param("uid=alice*)%00", id="attr_percent_nul_regression"),
    pytest.param("*)" + ")%00", id="bare_percent_nul_regression"),
]


@pytest.mark.parametrize("body", LDAP_NUL_FAMILY_BODIES)
def test_nul_family_in_body_fires_ldap(body: str) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        assert _body_is_threat(body) is True
        categories = _body_categories(body)
        assert "ldap" in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


def test_decoded_null_byte_patterns_registered_in_url_decoded_view_only(
    manager: SusPatternsManager,
) -> None:
    assert _LDAP_NULL_BYTE_DECODED_ATTR_RE in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    assert _LDAP_NULL_BYTE_DECODED_BARE_RE in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    assert _LDAP_NULL_BYTE_DECODED_ATTR_RE not in DETECTION_RAW_VIEW_PATTERN_SOURCES
    assert _LDAP_NULL_BYTE_DECODED_BARE_RE not in DETECTION_RAW_VIEW_PATTERN_SOURCES
    assert _LDAP_NULL_BYTE_ATTR_RE in DETECTION_RAW_VIEW_PATTERN_SOURCES
    assert _LDAP_NULL_BYTE_BARE_RE in DETECTION_RAW_VIEW_PATTERN_SOURCES
    assert _LDAP_NULL_BYTE_ATTR_RE not in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    assert _LDAP_NULL_BYTE_BARE_RE not in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES


def test_double_encoded_attr_nul_caught_by_decoded_view_pattern(
    manager: SusPatternsManager,
) -> None:
    result = _manager_detect("uid=alice*)%2500", manager)
    threats = [
        threat
        for threat in result["threats"]
        if threat.get("type") == "regex"
        and threat.get("category") == "ldap"
        and threat.get("pattern") == _LDAP_NULL_BYTE_DECODED_ATTR_RE
    ]
    assert threats
    assert threats[0]["pattern"] == _LDAP_NULL_BYTE_DECODED_ATTR_RE


def test_double_encoded_bare_nul_caught_by_decoded_view_pattern(
    manager: SusPatternsManager,
) -> None:
    result = _manager_detect("*)" + ")%2500", manager)
    threats = [
        threat
        for threat in result["threats"]
        if threat.get("type") == "regex"
        and threat.get("category") == "ldap"
        and threat.get("pattern") == _LDAP_NULL_BYTE_DECODED_BARE_RE
    ]
    assert threats
    assert threats[0]["pattern"] == _LDAP_NULL_BYTE_DECODED_BARE_RE


LDAP_NULL_BYTE_FP_BODIES = [
    pytest.param("uid=alice)(objectClass=user)", id="benign_ldap_filter"),
    pytest.param("(uid=*)(cn=*))", id="benign_wildcard_conjunction"),
    pytest.param("report;final.pdf", id="benign_semicolon_pdf"),
    pytest.param("function foo(a)(b))", id="benign_double_close_paren"),
    pytest.param("hello" + _NUL_RAW + "world", id="raw_nul_without_filter_shape"),
]


@pytest.mark.parametrize("body", LDAP_NULL_BYTE_FP_BODIES)
def test_benign_bodies_do_not_fire_ldap_null_byte_patterns(
    body: str, manager: SusPatternsManager
) -> None:
    result = _manager_detect(body, manager)
    assert not _null_byte_threats(result)


def test_raw_nul_attr_survives_signal_preserving_view(
    manager: SusPatternsManager,
) -> None:
    result = _manager_detect("uid=alice*)" + _NUL_RAW, manager)
    threats = [
        threat
        for threat in result["threats"]
        if threat.get("type") == "regex"
        and threat.get("category") == "ldap"
        and threat.get("pattern") == _LDAP_NULL_BYTE_ATTR_RE
    ]
    assert threats
    assert threats[0]["pattern"] == _LDAP_NULL_BYTE_ATTR_RE


def test_literal_text_nul_caught_by_raw_view_pattern(
    manager: SusPatternsManager,
) -> None:
    result = _manager_detect("uid=alice*)" + _NUL_UNICODE_TEXT, manager)
    threats = [
        threat
        for threat in result["threats"]
        if threat.get("type") == "regex"
        and threat.get("category") == "ldap"
        and threat.get("pattern") == _LDAP_NULL_BYTE_ATTR_RE
    ]
    assert threats
    assert threats[0]["pattern"] == _LDAP_NULL_BYTE_ATTR_RE


def test_ldap_null_byte_attr_name_start_returns_none_when_no_continuation_chars() -> (
    None
):
    assert _ldap_null_byte_attr_name_start("=x", 0) is None


def test_ldap_null_byte_attr_name_start_returns_none_when_lead_char_is_digit() -> None:
    assert _ldap_null_byte_attr_name_start("1=x", 1) is None
    assert _LDAP_NULL_BYTE_ATTR_LEAD_CHAR_RE.match("1") is None


def test_ldap_null_byte_attr_name_start_benign_input_not_detected(
    manager: SusPatternsManager,
) -> None:
    result = _manager_detect("1=x", manager)
    assert not _null_byte_threats(result)
    assert result["is_threat"] is False


def test_ldap_null_byte_finditer_skips_when_attr_name_lead_fails() -> None:
    text = "! =a*)" + _NUL_RAW
    matches = list(
        _ldap_null_byte_attr_finditer(
            text, _LDAP_NULL_BYTE_ATTR_COMPILED_RE, _LDAP_NULL_BYTE_TAIL_RE
        )
    )
    assert matches == []


def test_ldap_null_byte_finditer_lead_fail_input_not_detected(
    manager: SusPatternsManager,
) -> None:
    result = _manager_detect("! =a*)" + _NUL_RAW, manager)
    assert not _null_byte_threats(result)
    assert result["is_threat"] is False


def test_ldap_null_byte_finditer_skips_overlapping_tail_after_prior_yield() -> None:
    text = "uid=a*)" + _NUL_RAW + "uid=b*)" + _NUL_RAW
    fake_match = MagicMock()
    fake_match.end.return_value = 9999
    fake_compiled = MagicMock()
    fake_compiled.match.return_value = fake_match
    matches = list(
        _ldap_null_byte_attr_finditer(text, fake_compiled, _LDAP_NULL_BYTE_TAIL_RE)
    )
    assert len(matches) == 1
    assert matches[0] is fake_match
    fake_compiled.match.assert_called_once()


def test_ldap_null_byte_finditer_overlap_text_is_detected(
    manager: SusPatternsManager,
) -> None:
    result = _manager_detect("uid=a*)" + _NUL_RAW + "uid=b*)" + _NUL_RAW, manager)
    assert _null_byte_threats(result)


def test_ldap_null_byte_finditer_yields_nothing_when_compiled_pattern_misses() -> None:
    text = "uid=a*)" + _NUL_RAW
    matches = list(
        _ldap_null_byte_attr_finditer(text, re.compile(r"ZZZ"), _LDAP_NULL_BYTE_TAIL_RE)
    )
    assert matches == []


def test_ldap_null_byte_finditer_miss_text_detected_with_real_compiled(
    manager: SusPatternsManager,
) -> None:
    result = _manager_detect("uid=a*)" + _NUL_RAW, manager)
    assert _null_byte_threats(result)
