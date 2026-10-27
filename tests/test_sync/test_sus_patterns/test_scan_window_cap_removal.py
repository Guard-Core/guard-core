import re
from collections.abc import Generator

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    _GLOB_WILDCARD_ATOM_RE,
    _LDAP_NULL_BYTE_ATTR_COMPILED_RE,
    _LDAP_NULL_BYTE_ATTR_RE,
    _LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE,
    _LDAP_NULL_BYTE_DECODED_ATTR_RE,
    _LDAP_NULL_BYTE_DECODED_TAIL_RE,
    _LDAP_NULL_BYTE_TAIL_RE,
    _QUOTE_SPLICE_CANDIDATE_COMPILED_RE,
    _QUOTE_SPLICE_CANDIDATE_RE,
    DetectionResult,
    SusPatternsManager,
    _ldap_null_byte_attr_finditer,
    _quote_splice_finditer,
)

_OLD_LDAP_NULL_BYTE_ATTR_RE = re.compile(
    r"[a-zA-Z][\w-]{0,63}\s*=[\d\w\s]{0,255}\*\)+(?:%00|\\u0000|\\x00|\\0|\x00)",
    re.IGNORECASE,
)
_OLD_LDAP_NULL_BYTE_DECODED_ATTR_RE = re.compile(
    r"[a-zA-Z][\w-]{0,63}\s*=[\d\w\s]{0,255}\*\)+\x00",
    re.IGNORECASE,
)
_OLD_QUOTE_SPLICE_CANDIDATE_RE = re.compile(
    r"\w{1,12}(?:['\"]+\w{1,12}){1,10}", re.IGNORECASE
)


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


def _manager_detect(body: str, manager: SusPatternsManager) -> DetectionResult:
    return manager.detect(body, "203.0.113.9", context="request_body")


_ALLOWED_REPETITION_COUNT_BOUNDS = frozenset({"{1,10}"})


def test_no_capped_quantifier_remains_in_the_four_converted_patterns() -> None:
    for pattern in (
        _LDAP_NULL_BYTE_ATTR_RE,
        _LDAP_NULL_BYTE_DECODED_ATTR_RE,
        _QUOTE_SPLICE_CANDIDATE_RE,
        _GLOB_WILDCARD_ATOM_RE,
    ):
        bounds_found = re.findall(r"\{\d*,\d+\}", pattern)
        disallowed = [
            b for b in bounds_found if b not in _ALLOWED_REPETITION_COUNT_BOUNDS
        ]
        assert disallowed == [], pattern


def _ldap_attr_padded_name(length: int) -> str:
    return "a" + "b" * (length - 1)


@pytest.mark.parametrize("payload", ["uid=alice*)\x00", "mail=bob*)%00"])
def test_ldap_null_byte_attr_old_payload_still_matches(payload: str) -> None:
    old_match = _OLD_LDAP_NULL_BYTE_ATTR_RE.search(payload)
    new_matches = list(
        _ldap_null_byte_attr_finditer(
            payload, _LDAP_NULL_BYTE_ATTR_COMPILED_RE, _LDAP_NULL_BYTE_TAIL_RE
        )
    )
    assert bool(old_match) == bool(new_matches)
    assert new_matches
    assert old_match is not None
    assert new_matches[0].group() == old_match.group()


def test_ldap_null_byte_attr_2x_and_10x_name_bound_still_detected() -> None:
    for multiplier in (2, 10):
        attr_name = _ldap_attr_padded_name(63 * multiplier)
        payload = f"{attr_name}=x*)\x00"
        assert _OLD_LDAP_NULL_BYTE_ATTR_RE.search(payload) is not None, (
            "a uniform-letter attr name lets .search() restart within the "
            "last 63 chars, so this cap was already dead on this shape"
        )
        matches = list(
            _ldap_null_byte_attr_finditer(
                payload, _LDAP_NULL_BYTE_ATTR_COMPILED_RE, _LDAP_NULL_BYTE_TAIL_RE
            )
        )
        assert matches, f"multiplier={multiplier}"


def test_ldap_null_byte_attr_2x_and_10x_value_bound_now_detect() -> None:
    for multiplier in (2, 10):
        value = "x" * (255 * multiplier)
        payload = f"uid={value}*)\x00"
        assert _OLD_LDAP_NULL_BYTE_ATTR_RE.search(payload) is None
        matches = list(
            _ldap_null_byte_attr_finditer(
                payload, _LDAP_NULL_BYTE_ATTR_COMPILED_RE, _LDAP_NULL_BYTE_TAIL_RE
            )
        )
        assert matches, f"multiplier={multiplier}"


def test_ldap_null_byte_attr_value_containing_letters_still_detected() -> None:
    payload = "uid=alice*)\x00"
    matches = list(
        _ldap_null_byte_attr_finditer(
            payload, _LDAP_NULL_BYTE_ATTR_COMPILED_RE, _LDAP_NULL_BYTE_TAIL_RE
        )
    )
    assert matches
    assert matches[0].group() == payload


def test_ldap_null_byte_attr_benign_not_flagged() -> None:
    payload = "uid=alice)(objectClass=user)"
    assert not list(
        _ldap_null_byte_attr_finditer(
            payload, _LDAP_NULL_BYTE_ATTR_COMPILED_RE, _LDAP_NULL_BYTE_TAIL_RE
        )
    )


def test_ldap_null_byte_attr_detected_through_full_pipeline(
    manager: SusPatternsManager,
) -> None:
    result = _manager_detect("uid=alice*)" + chr(0), manager)
    assert result["is_threat"] is True
    patterns = [t["pattern"] for t in result["threats"] if t["type"] == "regex"]
    assert _LDAP_NULL_BYTE_ATTR_RE in patterns


@pytest.mark.parametrize("payload", ["uid=alice*)\x00", "mail=bob*)\x00"])
def test_ldap_null_byte_decoded_attr_old_payload_still_matches(payload: str) -> None:
    old_match = _OLD_LDAP_NULL_BYTE_DECODED_ATTR_RE.search(payload)
    new_matches = list(
        _ldap_null_byte_attr_finditer(
            payload,
            _LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE,
            _LDAP_NULL_BYTE_DECODED_TAIL_RE,
        )
    )
    assert bool(old_match) == bool(new_matches)
    assert new_matches
    assert old_match is not None
    assert new_matches[0].group() == old_match.group()


def test_ldap_null_byte_decoded_attr_2x_and_10x_bound_now_detect() -> None:
    for multiplier in (2, 10):
        value = "x" * (255 * multiplier)
        payload = f"uid={value}*)\x00"
        assert _OLD_LDAP_NULL_BYTE_DECODED_ATTR_RE.search(payload) is None
        matches = list(
            _ldap_null_byte_attr_finditer(
                payload,
                _LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE,
                _LDAP_NULL_BYTE_DECODED_TAIL_RE,
            )
        )
        assert matches, f"multiplier={multiplier}"


@pytest.mark.parametrize("payload", ["c'a't", "w'g'e't", "cur'l"])
def test_quote_splice_old_payload_still_matches(payload: str) -> None:
    old_match = _OLD_QUOTE_SPLICE_CANDIDATE_RE.search(payload)
    new_matches = list(
        _quote_splice_finditer(payload, _QUOTE_SPLICE_CANDIDATE_COMPILED_RE)
    )
    assert bool(old_match) == bool(new_matches)
    assert new_matches
    assert old_match is not None
    assert new_matches[0].group() == old_match.group()


def test_quote_splice_2x_and_10x_token_bound_still_detected() -> None:
    for multiplier in (2, 10):
        padding = "a" * (12 * multiplier)
        payload = f"{padding}'b"
        assert _OLD_QUOTE_SPLICE_CANDIDATE_RE.search(payload) is not None, (
            "a uniform-word first token lets .search() restart within the "
            "last 12 chars, so this cap was already dead on this shape"
        )
        matches = list(
            _quote_splice_finditer(payload, _QUOTE_SPLICE_CANDIDATE_COMPILED_RE)
        )
        assert matches, f"multiplier={multiplier}"


def test_quote_splice_detected_through_full_pipeline(
    manager: SusPatternsManager,
) -> None:
    result = _manager_detect("c'a't config.ini", manager)
    assert result["is_threat"] is True
    patterns = [t["pattern"] for t in result["threats"] if t["type"] == "regex"]
    assert _QUOTE_SPLICE_CANDIDATE_RE in patterns


def test_glob_wildcard_detected_through_full_pipeline(
    manager: SusPatternsManager,
) -> None:
    result = _manager_detect("c?t config.ini", manager)
    assert result["is_threat"] is True
    patterns = [t["pattern"] for t in result["threats"] if t["type"] == "regex"]
    assert _GLOB_WILDCARD_ATOM_RE in patterns
