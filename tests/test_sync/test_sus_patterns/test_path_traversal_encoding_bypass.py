from collections.abc import Generator

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    _CTX_PATH_TRAVERSAL,
    _PATH_TRAVERSAL_DECODED_SHAPE_RE,
    _PATH_TRAVERSAL_ENCODED_DOT_RE,
    _PATH_TRAVERSAL_SEMICOLON_SEP_RE,
    SusPatternsManager,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_NEW_PATTERN_SOURCES = {
    _PATH_TRAVERSAL_DECODED_SHAPE_RE.pattern,
    _PATH_TRAVERSAL_ENCODED_DOT_RE,
    _PATH_TRAVERSAL_SEMICOLON_SEP_RE,
}


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


@pytest.fixture
def legacy_manager() -> Generator[SusPatternsManager, None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    new_instance = SusPatternsManager()

    yield new_instance

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


def _new_pattern_threats(
    manager: SusPatternsManager, payload: str, context: str
) -> list[dict]:
    result = manager.detect(payload, "203.0.113.9", context=context)
    return [
        threat
        for threat in result["threats"]
        if threat["type"] == "regex" and threat["pattern"] in _NEW_PATTERN_SOURCES
    ]


EVADING_SHAPES = [
    pytest.param("..%2f", id="literal_dot_encoded_slash"),
    pytest.param("..%5c", id="literal_dot_encoded_backslash"),
    pytest.param("..%c0%af", id="literal_dot_overlong_utf8_slash"),
    pytest.param("..%c1%9c", id="literal_dot_overlong_utf8_backslash"),
    pytest.param("..%252f", id="literal_dot_double_encoded_slash"),
    pytest.param("..%u2215", id="literal_dot_iis_unicode_division_slash"),
    pytest.param("..%uff0f", id="literal_dot_iis_unicode_fullwidth_solidus"),
    pytest.param("%2e%2e%2f", id="encoded_dot_pair_encoded_slash"),
    pytest.param("%2e%2e%5c", id="encoded_dot_pair_encoded_backslash"),
    pytest.param("%252e%252e%252f", id="double_encoded_dot_pair_double_encoded_slash"),
    pytest.param("%c0%ae%c0%ae%c0%af", id="overlong_utf8_dot_pair_overlong_utf8_slash"),
    pytest.param(".%2e/", id="partial_encoded_dot_leading_literal"),
    pytest.param("%2e./", id="partial_encoded_dot_trailing_literal"),
    pytest.param("..;/", id="semicolon_path_parameter_bypass"),
    pytest.param("..;foo/..;foo/config.yaml", id="named_matrix_semicolon_bypass"),
    pytest.param("..;a=b/..;a=b/secret", id="named_matrix_assignment_semicolon_bypass"),
    pytest.param("..;x/..;y/private/key", id="named_matrix_chained_semicolon_bypass"),
    pytest.param("..%c0%2f", id="overlong_utf8_lead_byte_plus_literal_encoded_slash"),
    pytest.param("..%25%32%66", id="fully_double_encoded_slash_per_hex_digit"),
    pytest.param("..%00/", id="null_byte_before_literal_slash"),
    pytest.param("..%f0%80%80%af", id="four_byte_overlong_utf8_slash"),
    pytest.param("%u002e%u002e%2f", id="iis_unicode_dot_pair_encoded_slash"),
    pytest.param(
        "%u002e%u002e%u2215", id="iis_unicode_dot_pair_iis_unicode_division_slash"
    ),
    pytest.param(
        "%25252e%25252e%25252fetc%25252fpasswd",
        id="triple_encoded_dot_pair_and_slash_sensitive_target",
    ),
    pytest.param(
        "%2525252e%2525252e%2525252fetc%2525252fpasswd",
        id="quadruple_encoded_dot_pair_and_slash_sensitive_target",
    ),
    pytest.param(
        "%252525252e%252525252e%252525252fetc%252525252fpasswd",
        id="quintuple_encoded_dot_pair_and_slash_sensitive_target",
    ),
]


@pytest.mark.parametrize("context", ["url_path", "query_param"])
@pytest.mark.parametrize("payload", EVADING_SHAPES)
def test_evading_shape_is_detected_by_a_new_pattern(
    manager: SusPatternsManager, payload: str, context: str
) -> None:
    threats = _new_pattern_threats(manager, payload, context=context)
    assert threats


@pytest.mark.parametrize("context", ["url_path", "query_param"])
@pytest.mark.parametrize("payload", EVADING_SHAPES)
def test_evading_shape_is_flagged_as_threat_in_enhanced_mode(
    manager: SusPatternsManager, payload: str, context: str
) -> None:
    result = manager.detect(payload, "203.0.113.9", context=context)
    assert result["detection_method"] == "enhanced"
    assert result["is_threat"] is True


ADVERSARIAL_BYPASS_ATTEMPTS = [
    pytest.param("..%25252f", id="triple_encoded_slash"),
    pytest.param("..%2F", id="uppercase_encoded_slash"),
    pytest.param("..%C0%AF", id="uppercase_overlong_utf8_slash"),
    pytest.param("..%U2215", id="uppercase_iis_unicode_slash"),
    pytest.param("%2E%2e%2F", id="mixed_case_encoded_dot_pair_and_slash"),
    pytest.param("..%2f..%2f", id="chained_encoded_slash_segments"),
]


@pytest.mark.parametrize("payload", ADVERSARIAL_BYPASS_ATTEMPTS)
def test_case_and_encoding_depth_variants_still_detected(
    manager: SusPatternsManager, payload: str
) -> None:
    threats = _new_pattern_threats(manager, payload, context="url_path")
    assert threats


BENIGN_RELATIVE_PATHS = [
    pytest.param("../assets/logo.png", id="single_segment_relative_image"),
    pytest.param("../../src/index.js", id="double_segment_relative_import"),
    pytest.param("../images/pic.jpg", id="single_segment_relative_photo"),
    pytest.param("assets%2Flogo.png", id="encoded_slash_without_preceding_dotdot"),
    pytest.param("path/to/file", id="plain_nested_path"),
    pytest.param("2024/05/report.pdf", id="dated_report_path"),
    pytest.param("note%2Fstore", id="encoded_slash_word_boundary"),
    pytest.param("..%20file", id="encoded_space_does_not_decode_to_separator"),
    pytest.param("redirect=%2fdashboard", id="encoded_slash_after_redirect_param"),
    pytest.param("a..%2Cb", id="encoded_comma_does_not_decode_to_separator"),
]


@pytest.mark.parametrize("payload", BENIGN_RELATIVE_PATHS)
def test_benign_relative_path_does_not_trigger_new_patterns(
    manager: SusPatternsManager, payload: str
) -> None:
    threats = _new_pattern_threats(manager, payload, context="url_path")
    assert threats == []


def test_lone_literal_dotdot_to_nonsensitive_target_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    result = manager.detect("../secret", "203.0.113.9", context="url_path")
    assert result["is_threat"] is False


def test_colon_after_dotdot_is_not_a_semicolon_bypass(
    manager: SusPatternsManager,
) -> None:
    threats = _new_pattern_threats(manager, "..:/", context="url_path")
    assert threats == []


def _nest_encode(token: str, layers: int) -> str:
    for _ in range(layers):
        token = token.replace("%", "%25")
    return token


def test_encoding_nested_past_the_decode_pass_bound_is_not_flagged(
    manager: SusPatternsManager,
) -> None:
    payload = ".." + _nest_encode("%2f", 20)
    threats = _new_pattern_threats(manager, payload, context="url_path")
    assert threats == []


PROSE_WITH_DOTS_AND_SLASHES_FALSE_POSITIVES = [
    pytest.param("….//path", id="nfkc_ellipsis_dot_truncation_shape"),
    pytest.param("Loading........//please wait", id="loading_dots_progress_indicator"),
    pytest.param("Section 4....//5", id="document_section_reference"),
    pytest.param("v1.2.3....//legacy", id="version_string_with_slashes"),
    pytest.param("glob=**/....//node_modules", id="glob_pattern_query_value"),
]


@pytest.mark.parametrize("payload", PROSE_WITH_DOTS_AND_SLASHES_FALSE_POSITIVES)
def test_prose_with_dots_and_slashes_is_not_flagged(
    manager: SusPatternsManager, payload: str
) -> None:
    result = manager.detect(payload, "203.0.113.9", context="request_body")
    assert result["is_threat"] is False


def test_decoded_view_check_detects_path_traversal_in_legacy_mode(
    legacy_manager: SusPatternsManager,
) -> None:
    threats = _new_pattern_threats(legacy_manager, "%2e%2e%2f", context="url_path")
    result = legacy_manager.detect("%2e%2e%2f", "203.0.113.9", context="url_path")
    assert result["detection_method"] == "legacy"
    assert result["is_threat"] is True
    assert threats


LEGACY_SINGLE_SEGMENT_PATH_TRAVERSAL_SHAPES = [
    pytest.param("..%2fconfig.yaml", id="literal_dot_encoded_slash"),
    pytest.param("..%c0%afconfig.yaml", id="overlong_utf8_slash"),
    pytest.param("..%u2215config.yaml", id="iis_unicode_slash"),
    pytest.param("%2e%2e%2fconfig.yaml", id="encoded_dot_pair_encoded_slash"),
    pytest.param(".%2e/config.yaml", id="partial_encoded_dot"),
    pytest.param("..%c0%2fconfig.yaml", id="overlong_lead_byte_literal_slash"),
    pytest.param("..%25%32%66config.yaml", id="per_digit_double_encoded_slash"),
    pytest.param("..%00/config.yaml", id="null_byte_before_literal_slash"),
]


@pytest.mark.parametrize("payload", LEGACY_SINGLE_SEGMENT_PATH_TRAVERSAL_SHAPES)
def test_legacy_mode_detects_single_segment_encoded_path_traversal(
    legacy_manager: SusPatternsManager, payload: str
) -> None:
    result = legacy_manager.detect(payload, "203.0.113.9", context="url_path")
    assert result["detection_method"] == "legacy"
    assert result["is_threat"] is True
    assert any(
        threat["pattern"] == _PATH_TRAVERSAL_DECODED_SHAPE_RE.pattern
        for threat in result["threats"]
    )


def test_legacy_decoded_view_check_not_flagged_past_the_decode_bound(
    legacy_manager: SusPatternsManager,
) -> None:
    payload = ".." + _nest_encode("%2f", 12)
    result = legacy_manager.detect(payload, "203.0.113.9", context="url_path")
    assert result["detection_method"] == "legacy"
    assert result["is_threat"] is False


def test_decoded_view_check_runs_only_inside_path_traversal_contexts(
    manager: SusPatternsManager,
) -> None:
    for context in sorted(_CTX_PATH_TRAVERSAL):
        threats = _new_pattern_threats(manager, "%2e%2e%2f", context=context)
        assert threats, f"expected a decoded-view hit for context={context!r}"

    outside_contexts = SusPatternsManager._KNOWN_CONTEXTS - _CTX_PATH_TRAVERSAL
    for context in sorted(outside_contexts):
        threats = _new_pattern_threats(manager, "%2e%2e%2f", context=context)
        assert threats == [], f"expected no decoded-view hit for context={context!r}"


def test_decoded_view_check_skipped_when_category_disabled(
    manager: SusPatternsManager,
) -> None:
    result = manager.detect(
        "%2e%2e%2f",
        "203.0.113.9",
        context="url_path",
        enabled_categories={"xss"},
    )
    threats = [
        threat
        for threat in result["threats"]
        if threat["type"] == "regex" and threat["pattern"] in _NEW_PATTERN_SOURCES
    ]
    assert threats == []


def test_decoded_view_check_runs_when_category_explicitly_enabled(
    manager: SusPatternsManager,
) -> None:
    result = manager.detect(
        "%2e%2e%2f",
        "203.0.113.9",
        context="url_path",
        enabled_categories={"path_traversal"},
    )
    threats = [
        threat
        for threat in result["threats"]
        if threat["type"] == "regex" and threat["pattern"] in _NEW_PATTERN_SOURCES
    ]
    assert threats


NAMED_MATRIX_SEMICOLON_PATHS = [
    pytest.param("..;foo/..;foo/config.yaml", id="named_matrix_foo"),
    pytest.param("..;a=b/..;a=b/secret", id="named_matrix_assignment"),
    pytest.param("..;x/..;y/private/key", id="named_matrix_chained"),
]


@pytest.mark.parametrize("path", NAMED_MATRIX_SEMICOLON_PATHS)
def test_named_matrix_semicolon_evasion_fires_dir_traversal_through_entry_point(
    path: str,
) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        request = SyncMockGuardRequest(path=path, method="GET")
        result = detect_penetration_attempt(request, SyncSecurityConfig())
        assert result.is_threat is True
        assert "dir_traversal" in result.threat_categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


def test_empty_matrix_semicolon_evasion_still_fires_through_entry_point() -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        request = SyncMockGuardRequest(path="..;/..;/etc/passwd", method="GET")
        result = detect_penetration_attempt(request, SyncSecurityConfig())
        assert result.is_threat is True
        assert "dir_traversal" in result.threat_categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config
