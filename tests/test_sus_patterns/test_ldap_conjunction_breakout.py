from collections.abc import Generator

import pytest

from guard_core.handlers.suspatterns_handler import (
    _LDAP_WILDCARD_CHAIN_RE,
    DETECTION_RAW_VIEW_PATTERN_SOURCES,
    DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES,
    DetectionResult,
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


@pytest.fixture
def manager() -> Generator[SusPatternsManager, None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    new_instance = SusPatternsManager(SecurityConfig())
    yield new_instance
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


def _body_request(body: str) -> MockGuardRequest:
    encoded = body.encode()
    return MockGuardRequest(
        path="/login",
        method="POST",
        headers={"content-length": str(len(encoded))},
        body_content=encoded,
    )


async def _body_is_threat(body: str) -> bool:
    result = await detect_penetration_attempt(_body_request(body), SecurityConfig())
    return bool(result.is_threat)


async def _body_categories(body: str) -> list[str]:
    result = await detect_penetration_attempt(_body_request(body), SecurityConfig())
    return list(result.threat_categories)


async def _manager_detect(body: str, manager: SusPatternsManager) -> DetectionResult:
    return await manager.detect(body, "203.0.113.9", context="request_body")


LDAP_CONJUNCTION_BREAKOUT_PAYLOADS = [
    pytest.param("*)|(objectClass=*", id="or_conjunction_objectclass_wildcard"),
    pytest.param("*)&(objectClass=*", id="and_conjunction_objectclass_wildcard"),
    pytest.param("*)|(uid=*", id="or_conjunction_uid_wildcard"),
    pytest.param("*)&(cn=*", id="and_conjunction_cn_wildcard"),
    pytest.param("*)|(objectClass=*)", id="or_conjunction_objectclass_closed"),
    pytest.param("*)&(objectClass=*)", id="and_conjunction_objectclass_closed"),
]


LDAP_PLAIN_BREAKOUT_REGRESSION_PAYLOADS = [
    pytest.param("*)((objectClass=*", id="plain_breakout_double_open"),
    pytest.param("*)(objectClass=*", id="plain_breakout_single_open"),
    pytest.param("*)(uid=*", id="plain_breakout_uid_wildcard"),
    pytest.param("*))%00", id="bare_null_byte_breakout"),
    pytest.param("uid=alice*)%00", id="attr_null_byte_breakout"),
]


LDAP_BENIGN_PAYLOADS = [
    pytest.param("(uid=alice)(objectClass=user)", id="benign_multi_clause_filter"),
    pytest.param("(cn=*)", id="benign_single_wildcard_filter"),
    pytest.param("objectClass=person", id="benign_no_parens"),
    pytest.param("(uid=alice)(cn=bob)", id="benign_two_clause_no_wildcards"),
    pytest.param("report;final.pdf", id="benign_no_ldap_shape"),
    pytest.param("function foo(a)(b))", id="benign_parens_no_wildcard_op"),
]


LDAP_RFC4515_HEX_ESCAPE_WIRE_PAYLOADS = [
    pytest.param(r"admin\29\28cn=\2a", id="paren_breakout_wildcard_escaped"),
    pytest.param(r"*\29\28cn=admin", id="wildcard_chain_breakout_escaped"),
    pytest.param(r"admin\5c29\5c28cn=\5c2a", id="double_escaped_paren_breakout"),
    pytest.param(r"admin\29\28cn=\2A", id="mixed_case_hex_digits"),
]


LDAP_WILDCARD_BREAKOUT_PRE_JUNK_PAYLOADS = [
    pytest.param("x" * 39 + "*)(uid=*", id="pre_junk_below_window_bound"),
    pytest.param("x" * 40 + "*)(uid=*", id="pre_junk_at_window_bound"),
    pytest.param("x" * 41 + "*)(uid=*", id="pre_junk_past_window_bound"),
    pytest.param("x" * 200 + "*)(uid=*", id="pre_junk_far_past_window_bound"),
]


LDAP_PAREN_BREAKOUT_POST_JUNK_PAYLOADS = [
    pytest.param("admin)(cn=" + "A" * 34 + "*)", id="post_junk_below_window_bound"),
    pytest.param("admin)(cn=" + "A" * 35 + "*)", id="post_junk_at_window_bound"),
    pytest.param("admin)(cn=" + "A" * 36 + "*)", id="post_junk_past_window_bound"),
    pytest.param("admin)(cn=" + "A" * 195 + "*)", id="post_junk_far_past_window_bound"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LDAP_CONJUNCTION_BREAKOUT_PAYLOADS)
async def test_conjunction_breakout_fires_ldap(payload: str) -> None:
    assert await _body_is_threat(payload) is True
    categories = await _body_categories(payload)
    assert "ldap" in categories


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LDAP_PLAIN_BREAKOUT_REGRESSION_PAYLOADS)
async def test_plain_breakout_still_fires_ldap(payload: str) -> None:
    assert await _body_is_threat(payload) is True
    categories = await _body_categories(payload)
    assert "ldap" in categories


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LDAP_RFC4515_HEX_ESCAPE_WIRE_PAYLOADS)
async def test_rfc4515_hex_escape_fires_through_wire_entry(payload: str) -> None:
    assert await _body_is_threat(payload) is True
    categories = await _body_categories(payload)
    assert "ldap" in categories


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LDAP_WILDCARD_BREAKOUT_PRE_JUNK_PAYLOADS)
async def test_wildcard_breakout_fires_regardless_of_leading_junk_length(
    payload: str,
) -> None:
    assert await _body_is_threat(payload) is True
    categories = await _body_categories(payload)
    assert "ldap" in categories


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LDAP_PAREN_BREAKOUT_POST_JUNK_PAYLOADS)
async def test_paren_breakout_fires_regardless_of_trailing_junk_length(
    payload: str,
) -> None:
    assert await _body_is_threat(payload) is True
    categories = await _body_categories(payload)
    assert "ldap" in categories


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LDAP_BENIGN_PAYLOADS)
async def test_benign_payloads_do_not_fire_ldap(payload: str) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert not any(threat.get("category") == "ldap" for threat in result["threats"])


async def test_wildcard_chain_re_not_in_view_sets() -> None:
    assert _LDAP_WILDCARD_CHAIN_RE not in DETECTION_RAW_VIEW_PATTERN_SOURCES
    assert _LDAP_WILDCARD_CHAIN_RE not in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES


async def test_manager_detects_or_conjunction_with_widened_pattern(
    manager: SusPatternsManager,
) -> None:
    result = await _manager_detect("*)|(objectClass=*", manager)
    threats = [
        threat
        for threat in result["threats"]
        if threat.get("type") == "regex"
        and threat.get("category") == "ldap"
        and threat.get("pattern") == _LDAP_WILDCARD_CHAIN_RE
    ]
    assert threats


async def test_manager_detects_and_conjunction_with_widened_pattern(
    manager: SusPatternsManager,
) -> None:
    result = await _manager_detect("*)&(objectClass=*", manager)
    threats = [
        threat
        for threat in result["threats"]
        if threat.get("type") == "regex"
        and threat.get("category") == "ldap"
        and threat.get("pattern") == _LDAP_WILDCARD_CHAIN_RE
    ]
    assert threats
